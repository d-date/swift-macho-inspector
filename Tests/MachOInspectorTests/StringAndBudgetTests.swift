import Foundation
import MachOFixtures
import Testing

@testable import MachOInspector

@Suite struct StringAndBudgetTests {
  private let stride = MemoryLayout<Symbol>.stride

  @Test func fatSlicesShareOneSymbolBudget() throws {
    var img = TestImage()
    img.zeroNameSymbols = 200
    let one = img.data()
    let file = fat([
      (cpu: 0x0100_000c, sub: 0, data: one), (0x0100_000c, 0, one), (0x0100_000c, 0, one),
    ])
    var limits = SymbolLimits()
    limits.maxSymbolMemory = 250 * stride
    let parsed = try MachOFile(data: file, limits: limits)
    let total = parsed.slices.reduce(0) { $0 + $1.symbols.count }
    #expect(total <= 250 && total < 600)
    #expect(parsed.slices[0].symbols.count == 200)
    #expect(parsed.slices[2].symbols.isEmpty)
    #expect(parsed.slices[2].parseWarnings.contains { $0.contains("shared by all slices") })
  }

  @Test func unterminatedNameScansAreBudgeted() throws {
    var img = TestImage()
    img.zeroNameSymbols = 20_000
    var d = img.data()
    let symtab = try #require(try MachOFile(data: d).slices[0].loadCommands.first { $0.cmd == 2 })
    let stroff = Int(u32LE(d, Int(symtab.offset) + 16))
    let strsize = Int(u32LE(d, Int(symtab.offset) + 20))
    // No NUL anywhere: every lookup would rescan up to 4 KiB without the scan budget.
    d.replaceSubrange(stroff..<stroff + strsize, with: Data(repeating: 0x41, count: strsize))
    let slice = try MachOFile(data: d).slices[0]
    #expect(slice.symbols.count == 20_000)
    #expect(slice.symbols.allSatisfy { $0.name.isEmpty })
    #expect(slice.parseWarnings.contains { $0.contains("unterminated") })
  }

  @Test func manyShortValidNamesStayWithinScanBudget() throws {
    var img = TestImage()
    // Distinct 7-byte names: a flat per-lookup charge would exhaust the budget long before
    // the last import, which must still be visible.
    img.symbols = (0..<20_000).map { (String(format: "_s%05d", $0), 0x0f) } + [("_strcpy", 0x01)]
    let slice = try MachOFile(data: img.data()).slices[0]
    #expect(slice.importedSymbols.contains("_strcpy"))
    #expect(!slice.parseWarnings.contains { $0.contains("scan budget") })
  }

  @Test func overlappingValidNamesDoNotHideLaterImports() throws {
    // Codex counterexample: three NUL-terminated 4,095-byte names, a symbol for every suffix of
    // them (~25 MB of rescanning under a flat scan budget), and a final `_strcpy` import.
    var img = TestImage()
    img.symbols = [("_x", 0x0f)]  // string table starts "\0_x\0"
    let suffixes = 3 * 4096
    img.zeroNameSymbols = suffixes + 12
    var d = img.data()
    let symtab = try #require(try MachOFile(data: d).slices[0].loadCommands.first { $0.cmd == 2 })
    let symoff = Int(u32LE(d, Int(symtab.offset) + 8))
    let stroff = Int(u32LE(d, Int(symtab.offset) + 16))
    let base = 4
    var table = Data()
    for c in [UInt8(0x61), 0x62, 0x63] { table += Data(repeating: c, count: 4095) + Data([0]) }
    // A fresh (uncached) location for the import name, inside the trailing zero padding.
    let importStrx = UInt32(base + table.count)
    table += Data("_strcpy".utf8) + Data([0])
    d.replaceSubrange(stroff + base..<stroff + base + table.count, with: table)
    for i in 0..<img.zeroNameSymbols {
      let entry = symoff + 16 * (1 + i)
      let strx: UInt32 =
        i == img.zeroNameSymbols - 1 ? importStrx : UInt32(base + min(i, suffixes - 1))
      patch(&d, at: entry, u32: strx)
    }
    let slice = try MachOFile(data: d).slices[0]
    #expect(slice.symbols.last?.name == "_strcpy")
    #expect(slice.importedSymbols.contains("_strcpy"))
    #expect(slice.symbols[1].name.utf8.count == 4095)
  }

  @Test func namesAreChargedBeforeDecoding() throws {
    var img = TestImage()
    img.symbols = (0..<20).map { ("_" + String(repeating: "A", count: 1000) + "\($0)", 0x01) }
    var limits = SymbolLimits()
    limits.maxSymbolMemory = 5_000 + 20 * stride
    let s = try MachOFile(data: img.data(), limits: limits).slices[0]
    #expect(s.symbols.count < 20)
    #expect(s.symbols.reduce(0) { $0 + $1.name.utf8.count } <= 5_000)
  }

  @Test func unterminatedSymbolNameIsEmptyWithWarning() throws {
    var img = TestImage()
    img.symbols = [("_foo", 0x01)]
    var d = img.data()
    let symtab = try #require(try MachOFile(data: d).slices[0].loadCommands.first { $0.cmd == 2 })
    patch(&d, at: Int(symtab.offset) + 20, u32: 5)  // strsize ends before the NUL
    let s = try MachOFile(data: d).slices[0]
    #expect(s.symbols.count == 1 && s.symbols[0].name.isEmpty)
    #expect(s.parseWarnings.filter { $0.contains("LC_SYMTAB: 1 symbol names") }.count == 1)
  }

  @Test func overlongStringsAreRejectedNotTruncated() throws {
    let long = String(repeating: "A", count: 5000)
    var img = TestImage()
    img.payloadStart = 0x4000
    img.symbols = [(long, 0x01), ("_ok", 0x01)]
    img.extraLibraries = ["/usr/lib/" + long]
    img.rpaths = [long]
    img.signature = sampleSignature(identifier: long)
    let s = try MachOFile(data: img.data()).slices[0]
    #expect(s.symbols.map(\.name) == ["", "_ok"])
    #expect(s.linkedLibraries.count == 2 && s.rpaths.isEmpty)
    #expect(s.parseWarnings.contains { $0.hasPrefix("LC_LOAD_DYLIB") })
    #expect(s.parseWarnings.contains { $0.hasPrefix("LC_RPATH") })
    #expect(s.parseWarnings.contains { $0.contains("CodeDirectory: identifier") })
    #expect(s.codeSignature?.codeDirectories.first?.identifier == "")
  }
}
