import Foundation
import MachOFixtures
import Testing

@testable import MachOInspector

private var signed: TestImage {
  var img = TestImage()
  img.symbols = TestImage.sampleSymbols
  img.signature = sampleSignature()
  return img
}

@Suite struct ThinTests {
  @Test func parsesArm64Executable() throws {
    let file = try MachOFile(data: signed.data())
    #expect(!file.isFat)
    let s = try #require(file.slices.first)
    #expect(s.architecture == "arm64")
    #expect(s.is64Bit && s.isPIE && !s.allowsStackExecution && !s.hasNoHeapExecution)
    #expect(s.fileType == 2 && s.fileOffset == 0)
    #expect(s.segments.first?.name == "__TEXT")
    #expect(s.segments.first?.sections.first?.name == "__text")
    #expect(s.segments.first?.sections.first?.size == 0x20)
    #expect(
      s.linkedLibraries.map(\.path) == [
        "/usr/lib/libSystem.B.dylib", "/System/Library/Frameworks/UIKit.framework/UIKit",
      ])
    #expect(s.linkedLibraries.map(\.kind) == [.normal, .weak])
    #expect(s.linkedLibraries[0].currentVersion == "76.5.1")
    #expect(s.linkedLibraries[0].compatibilityVersion == "1.0.0")
    #expect(s.rpaths == ["@executable_path/Frameworks"])
    #expect(
      s.minimumOS == BuildVersion(platform: 2, platformName: "ios", minOS: "15.0.0", sdk: "17.0.1"))
    #expect(s.uuid == "A0A1A2A3-A4A5-A6A7-A8A9-AAABACADAEAF")
    #expect(s.loadCommands.map(\.name).contains("LC_BUILD_VERSION"))
    #expect(s.parseWarnings.isEmpty)
  }

  @Test func archNames() throws {
    func arch(_ t: UInt32, _ s: UInt32) throws -> String {
      var img = TestImage()
      img.cpuType = t
      img.cpuSubtype = s
      return try MachOFile(data: img.data()).slices[0].architecture
    }
    #expect(try arch(0x0100_000c, 0x8000_0002) == "arm64e")
    #expect(try arch(12, 9) == "armv7")
    #expect(try arch(12, 11) == "armv7s")
    #expect(try arch(0x0100_0007, 3) == "x86_64")
    #expect(try arch(7, 3) == "i386")
    #expect(try arch(99, 1) == "cpu(99,1)")
  }

  @Test func flagsAndBigEndian() throws {
    var img = TestImage()
    img.flags = 0x1_0000 | 0x2_0000 | 0x100_0000
    let s = try MachOFile(data: img.data()).slices[0]
    #expect(!s.isPIE && s.allowsStackExecution && s.hasNoHeapExecution)

    let beData = be { b in
      b.u32(0xfeed_face)
      b.u32(12)
      b.u32(9)
      b.u32(6)
      b.u32(0)
      b.u32(0)
      b.u32(0x20_0000)
    }
    let b = try MachOFile(data: beData).slices[0]
    #expect(!b.is64Bit && b.architecture == "armv7" && b.fileType == 6 && b.isPIE)
  }

  @Test func sniff() {
    #expect(MachOFile.isMachO(signed.data()))
    #expect(MachOFile.isMachO(fat([(12, 9, signed.data())])))
    #expect(MachOFile.isMachO(Data([0xfe, 0xed, 0xfa, 0xce])))
    #expect(!MachOFile.isMachO(Data([0x7f, 0x45, 0x4c, 0x46])))
    #expect(!MachOFile.isMachO(Data([0xfe])))
    #expect(!MachOFile.isMachO(Data()))
    // A Data slice has a non-zero startIndex.
    #expect(MachOFile.isMachO((Data([9, 9]) + signed.data()).dropFirst(2)))
  }
}

@Suite struct FatTests {
  @Test func fat32AndFat64() throws {
    var arm64 = TestImage()
    arm64.symbols = TestImage.sampleSymbols
    var armv7 = TestImage()
    armv7.cpuType = 12
    armv7.cpuSubtype = 9
    for is64 in [false, true] {
      let data = fat([(0x0100_000c, 0, arm64.data()), (12, 9, armv7.data())], fat64: is64)
      let file = try MachOFile(data: data)
      #expect(file.isFat)
      #expect(file.slices.map(\.architecture) == ["arm64", "armv7"])
      #expect(file.slices[0].fileOffset == 0x4000)
      #expect(file.slices[1].fileOffset == 0x8000)
      #expect(file.slices[0].symbols.count == 4)
    }
  }

  @Test func fatSliceOutsideFileThrows() {
    var data = fat([(0x0100_000c, 0, TestImage().data())])
    patch(&data, at: 8 + 12, u32: 0x7fff_ffff, bigEndian: true)
    #expect(throws: MachOError.self) { try MachOFile(data: data) }
  }

  @Test func overlappingFatSlicesThrow() {
    var data = fat([(0x0100_000c, 0, TestImage().data()), (12, 9, TestImage().data())])
    patch(&data, at: 8 + 20 + 8, u32: 0x4000, bigEndian: true)  // second slice offset = first
    #expect(throws: MachOError.self) { try MachOFile(data: data) }
  }

  @Test func fatArchCountCapped() {
    var data = fat([(0x0100_000c, 0, TestImage().data())])
    patch(&data, at: 4, u32: 65, bigEndian: true)
    #expect(throws: MachOError.self) { try MachOFile(data: data) }
  }

  @Test func offsetMathAndStartIndex() throws {
    var enc = TestImage()
    enc.cryptID = 1
    let data = fat([(12, 9, TestImage().data()), (0x0100_000c, 0, enc.data())])
    // A Data slice has a non-zero startIndex; the parser must cope.
    let padded = (Data([9, 9, 9]) + data).dropFirst(3)
    let s = try MachOFile(data: padded).slices[1]
    #expect(s.isEncrypted)
    #expect(s.encryptedFileRanges == [(0x8000 + 0x1000)..<(0x8000 + 0x3000)])
  }
}

@Suite struct EncryptionTests {
  @Test func encryptedVsNot() throws {
    var img = TestImage()
    img.cryptID = 1
    let enc = try MachOFile(data: img.data()).slices[0]
    #expect(enc.isEncrypted)
    #expect(
      enc.encryptionInfo == [
        EncryptionInfo(
          cryptOffset: 0x1000, cryptSize: 0x2000, cryptID: 1, isWithinSlice: true)
      ])
    #expect(!enc.hasInvalidEncryptionRange && enc.parseWarnings.isEmpty)
    #expect(enc.encryptedFileRanges == [0x1000..<0x3000])

    img.cryptID = 0
    let plain = try MachOFile(data: img.data()).slices[0]
    #expect(!plain.isEncrypted && plain.encryptedFileRanges.isEmpty)
    #expect(plain.encryptionInfo.count == 1)

    #expect(try MachOFile(data: TestImage().data()).slices[0].encryptionInfo.isEmpty)
  }
}

@Suite struct EncryptionRangeTests {
  @Test func rangeCannotReachIntoNextFatSlice() throws {
    var a = TestImage()
    a.cryptID = 1
    a.cryptOffset = 0x1000
    a.cryptSize = 0x1000
    a.padToCryptRange = false  // slice is far smaller than the declared range
    let file = try MachOFile(data: fat([(0x0100_000c, 0, a.data()), (12, 9, TestImage().data())]))
    let (sa, sb) = (file.slices[0], file.slices[1])
    #expect(sa.isEncrypted && sa.hasInvalidEncryptionRange)
    #expect(sa.encryptedFileRanges.isEmpty)
    #expect(sa.encryptionInfo.first?.isWithinSlice == false)
    #expect(sa.encryptionInfo.first?.cryptSize == 0x1000)
    #expect(sa.parseWarnings.contains { $0.contains("encrypted range outside slice") })
    #expect(!sb.isEncrypted && sb.encryptedFileRanges.isEmpty)
  }

  @Test func boundaryAndOverflowRanges() throws {
    var img = TestImage()
    img.cryptID = 1
    img.padToCryptRange = false
    let size = try MachOFile(data: img.data()).slices[0].size
    // Exactly reaching the end of the slice is valid.
    img.cryptOffset = UInt32(size) - 0x100
    img.cryptSize = 0x100
    var s = try MachOFile(data: img.data()).slices[0]
    #expect(!s.hasInvalidEncryptionRange && s.encryptedFileRanges.count == 1)
    // One byte past the end, and a wrapping 32-bit sum, are both rejected.
    img.cryptSize = 0x101
    s = try MachOFile(data: img.data()).slices[0]
    #expect(s.hasInvalidEncryptionRange && s.encryptedFileRanges.isEmpty)
    img.cryptOffset = 0xffff_ff00
    img.cryptSize = 0x200
    s = try MachOFile(data: img.data()).slices[0]
    #expect(s.isEncrypted && s.encryptedFileRanges.isEmpty)
  }

  @Test func outOfRangeRecordWithoutCryptIDIsNotAWarning() throws {
    var img = TestImage()
    img.cryptID = 0
    img.cryptSize = 0x7000_0000
    img.padToCryptRange = false
    let s = try MachOFile(data: img.data()).slices[0]
    #expect(!s.isEncrypted && !s.hasInvalidEncryptionRange && s.parseWarnings.isEmpty)
  }
}

@Suite struct SymbolTests {
  @Test func commonSymbolsAreNotImports() throws {
    var img = TestImage()
    img.symbols = [("_import", 0x01), ("_common", 0x01)]
    img.symbolValues = [1: 8]
    let s = try MachOFile(data: img.data()).slices[0]
    #expect(s.symbols[1].isUndefined && s.symbols[1].isCommon && !s.symbols[0].isCommon)
    #expect(s.importedSymbols == ["_import"])
  }

  private func parseThin(_ data: Data, _ limits: SymbolLimits) throws -> MachOSlice {
    let file = Reader(data: data, bigEndian: true)
    return try MachOSliceParser.parse(file: file, fileOffset: 0, size: file.size, limits: limits)
  }

  @Test func manyDistinctEmptyNamesAreCapped() throws {
    var img = TestImage()
    img.zeroNameSymbols = 1000
    var limits = SymbolLimits()
    limits.maxSymbols = 100
    var s = try parseThin(img.data(), limits)
    #expect(s.symbols.count == 100 && s.symbols.allSatisfy { $0.name.isEmpty })
    #expect(s.parseWarnings.contains { $0.contains("capped at 100") })

    // The memory estimate (count * stride + name bytes) also stops decoding.
    limits = SymbolLimits()
    limits.maxSymbolMemory = 50 * MemoryLayout<Symbol>.stride
    s = try parseThin(img.data(), limits)
    #expect(s.symbols.count == 50)
    #expect(s.parseWarnings.contains { $0.contains("memory bound") })

    // Real limits: the documented bound is realistic and a normal image is unaffected.
    #expect(MachOSlice.maxSymbols == 4_000_000)
    #expect(try parseThin(img.data(), SymbolLimits()).symbols.count == 1000)
  }

  @Test func importsAndStabs() throws {
    let s = try MachOFile(data: signed.data()).slices[0]
    #expect(s.symbols.map(\.name) == ["___stack_chk_fail", "_objc_release", "_main", "_stab_fun"])
    #expect(s.importedSymbols == ["___stack_chk_fail", "_objc_release"])
    #expect(s.hasDebugSymbols)
    #expect(s.symbols[3].isStab && !s.symbols[3].isUndefined)
    #expect(s.symbols[2].isExternal && !s.symbols[2].isUndefined)

    var img = TestImage()
    img.symbols = [("_x", 0x01)]
    #expect(!(try MachOFile(data: img.data()).slices[0].hasDebugSymbols))
    // ld's N_OPT marker is present in release binaries and is not debug info.
    img.symbols = [("radr://5614542", 0x3c)]
    let opt = try MachOFile(data: img.data()).slices[0]
    #expect(opt.symbols[0].isStab && !opt.hasDebugSymbols && opt.debugStabs.isEmpty)
  }
}

@Suite struct CodeSignatureTests {
  @Test func parsesSuperBlob() throws {
    let sig = try #require(try MachOFile(data: signed.data()).slices[0].codeSignature)
    #expect(sig.blobs.map(\.type) == [0, 2, 5, 0x10000])
    let cd = try #require(sig.codeDirectories.first)
    #expect(sig.codeDirectories.count == 1)
    #expect(cd.version == 0x20400 && cd.flags == 0x0002_0000)
    #expect(cd.identifier == "com.example.app" && cd.teamIdentifier == "ABCDE12345")
    #expect(cd.hashTypeName == "sha256" && cd.hashSize == 32 && cd.pageSizeLog2 == 12)
    #expect(cd.codeLimit == 0x2000 && cd.nCodeSlots == 2 && cd.nSpecialSlots == 0)
    #expect(cd.execSegFlags == 1)
    #expect(String(decoding: try #require(sig.entitlementsXML), as: UTF8.self) == entitlementsXML)
    #expect(sig.entitlementsDER == nil)
    #expect(sig.hasRequirements)
    #expect(sig.hasCMSSignature && sig.cmsSignatureSize == 4)
  }

  private func parse(_ blob: Data) throws -> MachOSlice {
    var img = TestImage()
    img.signature = blob
    return try MachOFile(data: img.data()).slices[0]
  }

  @Test func duplicateSlotsAreRejected() throws {
    let cd = codeDirectory(identifier: "a", team: "T")
    // Six slot-0 entries would exhaust the CodeDirectory cap and hide later ones.
    var s = try parse(superBlob(Array(repeating: (slot: 0, data: cd), count: 6)))
    #expect(s.codeSignature == nil && !s.parseWarnings.isEmpty)
    // Two entitlement slots would expose only the first.
    let e1 = simpleBlob(magic: 0xfade_7171, payload: Data("<a/>".utf8))
    let e2 = simpleBlob(magic: 0xfade_7171, payload: Data("<b/>".utf8))
    s = try parse(superBlob([(5, e1), (5, e2)]))
    #expect(s.codeSignature == nil && !s.parseWarnings.isEmpty)
  }

  @Test func blobsMustNotOverlapOrPrecedeTheTable() throws {
    let req = simpleBlob(magic: 0xfade_0c01, payload: Data())
    let shared =
      be { b in
        b.u32(0xfade_0cc0)
        b.u32(UInt32(12 + 16 + req.count))
        b.u32(2)
        b.u32(2)
        b.u32(28)
        b.u32(0x1234)
        b.u32(28)
      } + req
    var s = try parse(shared)
    #expect(s.codeSignature == nil && !s.parseWarnings.isEmpty)

    var intoTable = superBlob([(2, req)])
    patch(&intoTable, at: 16, u32: 4, bigEndian: true)  // blob offset inside the index table
    s = try parse(intoTable)
    #expect(s.codeSignature == nil && !s.parseWarnings.isEmpty)
  }

  @Test func codeLimitPrefers64BitWhenSet() throws {
    func limit(_ v: UInt32, _ l32: UInt32, _ l64: UInt64) throws -> UInt64? {
      let cd = codeDirectory(
        identifier: "a", team: "T", version: v, codeLimit: l32, codeLimit64: l64)
      return try parse(superBlob([(0, cd)])).codeSignature?.codeDirectories.first?.codeLimit
    }
    #expect(try limit(0x20400, 0x2000, 0x1_0000_0000) == 0x1_0000_0000)
    #expect(try limit(0x20400, 0xffff_ffff, 0x1_0000_0000) == 0x1_0000_0000)
    #expect(try limit(0x20400, 0x2000, 0) == 0x2000)
    #expect(try limit(0x20200, 0x2000, 0x1_0000_0000) == 0x2000)  // field absent before 0x20300
  }

  @Test func emptyCMSBlobMeansUnsigned() throws {
    var img = TestImage()
    img.signature = sampleSignature(cms: Data())
    let sig = try #require(try MachOFile(data: img.data()).slices[0].codeSignature)
    #expect(!sig.hasCMSSignature && sig.cmsSignatureSize == 0)
  }

  @Test func hashTypeNames() throws {
    #expect(
      try MachOFile(data: signed.data()).slices[0].codeSignature?.codeDirectories[0].hashTypeName
        == "sha256")
  }
}

@Suite struct MalformedTests {
  private let valid = signed.data()

  @Test func emptyAndTiny() {
    #expect(throws: MachOError.self) { try MachOFile(data: Data()) }
    #expect(throws: MachOError.self) { try MachOFile(data: Data([0xcf, 0xfa])) }
    #expect(throws: MachOError.self) { try MachOFile(data: Data([0xcf, 0xfa, 0xed, 0xfe])) }
  }

  @Test func truncatedHeader() {
    #expect(throws: MachOError.self) { try MachOFile(data: valid.prefix(20)) }
    #expect(throws: MachOError.self) { try MachOFile(data: valid.prefix(40)) }
  }

  @Test func invalidMagic() {
    #expect(throws: MachOError.invalidMagic(0x0403_0201)) {
      try MachOFile(data: Data([1, 2, 3, 4, 5, 6, 7, 8]))
    }
  }

  @Test func hugeNcmds() {
    var d = valid
    patch(&d, at: 16, u32: 0xffff_ffff)
    #expect(throws: MachOError.tooManyLoadCommands(0xffff_ffff)) { try MachOFile(data: d) }
    patch(&d, at: 16, u32: 9_000)  // under the cap but far more than the data holds
    #expect(throws: MachOError.self) { try MachOFile(data: d) }
  }

  @Test func sizeofcmdsPastEnd() {
    var d = valid
    patch(&d, at: 20, u32: 0xffff_fff0)
    #expect(throws: MachOError.self) { try MachOFile(data: d) }
  }

  @Test func zeroCmdsize() {
    var d = valid
    patch(&d, at: 32 + 4, u32: 0)
    #expect(throws: MachOError.self) { try MachOFile(data: d) }
  }

  @Test func cmdsizePastEnd() {
    var d = valid
    patch(&d, at: 32 + 4, u32: 0x00ff_ffff)
    #expect(throws: MachOError.self) { try MachOFile(data: d) }
  }

  @Test func symtabStringOffsetOutOfRange() throws {
    var d = valid
    let symtab = try #require(try MachOFile(data: d).slices[0].loadCommands.first { $0.cmd == 2 })
    patch(&d, at: Int(symtab.offset) + 16, u32: 0xffff_ff00)  // stroff
    let s = try MachOFile(data: d).slices[0]
    #expect(!s.parseWarnings.isEmpty)
    #expect(s.symbols.isEmpty)
  }

  @Test func symbolNameIndexOutOfRangeAndHugeNsyms() throws {
    var d = valid
    let symtab = try #require(try MachOFile(data: d).slices[0].loadCommands.first { $0.cmd == 2 })
    patch(&d, at: Int(symtab.offset) + 12, u32: 0xffff_ffff)  // nsyms
    patch(&d, at: Int(symtab.offset) + 20, u32: 4)  // strsize shorter than names
    let s = try MachOFile(data: d).slices[0]
    #expect(!s.parseWarnings.isEmpty)
    #expect(s.symbols.count < 0xffff_ffff)
  }

  @Test func superBlobCountHuge() throws {
    var d = valid
    let lc = try #require(try MachOFile(data: d).slices[0].loadCommands.first { $0.cmd == 0x1d })
    let sigOff = Int(u32LE(d, Int(lc.offset) + 8))
    patch(&d, at: sigOff + 8, u32: 0xffff_ffff, bigEndian: true)
    let s = try MachOFile(data: d).slices[0]
    #expect(s.codeSignature == nil)
    #expect(!s.parseWarnings.isEmpty)
  }

  @Test func duplicateSymtabIsIgnored() throws {
    var d = valid
    let cmds = try MachOFile(data: d).slices[0].loadCommands
    let symtab = try #require(cmds.first { $0.cmd == 2 })
    // LC_UUID has the same 24-byte size as LC_SYMTAB, so it can be overwritten with a copy.
    let uuid = try #require(cmds.first { $0.cmd == 0x1b })
    let copy = d.subdata(in: Int(symtab.offset)..<Int(symtab.offset) + 24)
    d.replaceSubrange(Int(uuid.offset)..<Int(uuid.offset) + 24, with: copy)
    let s = try MachOFile(data: d).slices[0]
    #expect(s.parseWarnings.contains { $0.contains("duplicate") })
    #expect(s.symbols.count == (try MachOFile(data: valid).slices[0].symbols.count))
  }

  @Test func blobOffsetOutOfRange() throws {
    var d = valid
    let lc = try #require(try MachOFile(data: d).slices[0].loadCommands.first { $0.cmd == 0x1d })
    let sigOff = Int(u32LE(d, Int(lc.offset) + 8))
    patch(&d, at: sigOff + 12 + 4, u32: 0xffff_fff0, bigEndian: true)
    let s = try MachOFile(data: d).slices[0]
    #expect(s.codeSignature == nil && !s.parseWarnings.isEmpty)
  }

  @Test func garbage() {
    var x: UInt64 = 0x1234_5678
    var junk = Data()
    for _ in 0..<4096 {
      x = x &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
      junk.append(UInt8(x >> 56))
    }
    #expect(throws: MachOError.self) { try MachOFile(data: junk) }
    #expect(throws: MachOError.self) { try MachOFile(data: Data([0xca, 0xfe, 0xba, 0xbe]) + junk) }
  }

  @Test func mutationFuzzNeverCrashes() {
    let seeds = [valid, fat([(0x0100_000c, 0, valid), (12, 9, TestImage().data())])]
    var x: UInt64 = 42
    func next() -> Int {
      x = x &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
      return Int(x >> 33)
    }
    for seed in seeds {
      for _ in 0..<1500 {
        var d = seed
        for _ in 0..<(1 + next() % 8) {
          // Bias toward headers and load commands, where the interesting structure lives.
          let i = next() % 2 == 0 ? next() % min(d.count, 0x200) : next() % d.count
          d[i] = UInt8(truncatingIfNeeded: next())
        }
        if next() % 4 == 0 { d = d.prefix(next() % d.count) }
        _ = try? MachOFile(data: d)
      }
    }
  }
}

private let canReadUsrBinTrue: Bool = {
  #if os(macOS)
    FileManager.default.fileExists(atPath: "/usr/bin/true")
  #else
    false
  #endif
}()

@Test(.enabled(if: canReadUsrBinTrue))
func parsesSystemBinary() throws {
  let data = try Data(contentsOf: URL(fileURLWithPath: "/usr/bin/true"))
  let file = try MachOFile(data: data)
  #expect(!file.slices.isEmpty)
  #expect(file.slices.allSatisfy { !$0.loadCommands.isEmpty && !$0.linkedLibraries.isEmpty })
}
