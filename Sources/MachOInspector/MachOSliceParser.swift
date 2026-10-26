import Foundation

/// Magic numbers shared by the FAT and thin parsers.
enum MachOMagic {
  static let thin32: UInt32 = 0xfeed_face
  static let thin64: UInt32 = 0xfeed_facf
  static let thin32Swapped: UInt32 = 0xcefa_edfe
  static let thin64Swapped: UInt32 = 0xcffa_edfe
  static let fat32: UInt32 = 0xcafe_babe
  static let fat64: UInt32 = 0xcafe_babf
}

/// Load-command identifiers (`LC_*`). Commands with the `LC_REQ_DYLD` bit carry 0x8000_0000.
private enum LC {
  static let segment: UInt32 = 0x1
  static let symtab: UInt32 = 0x2
  static let thread: UInt32 = 0x4
  static let unixThread: UInt32 = 0x5
  static let dysymtab: UInt32 = 0xb
  static let loadDylib: UInt32 = 0xc
  static let idDylib: UInt32 = 0xd
  static let loadDylinker: UInt32 = 0xe
  static let idDylinker: UInt32 = 0xf
  static let segment64: UInt32 = 0x19
  static let routines64: UInt32 = 0x1a
  static let uuid: UInt32 = 0x1b
  static let codeSignature: UInt32 = 0x1d
  static let segmentSplitInfo: UInt32 = 0x1e
  static let lazyLoadDylib: UInt32 = 0x20
  static let encryptionInfo: UInt32 = 0x21
  static let dyldInfo: UInt32 = 0x22
  static let versionMinMacOSX: UInt32 = 0x24
  static let versionMinIPhoneOS: UInt32 = 0x25
  static let functionStarts: UInt32 = 0x26
  static let dyldEnvironment: UInt32 = 0x27
  static let dataInCode: UInt32 = 0x29
  static let sourceVersion: UInt32 = 0x2a
  static let dylibCodeSignDRs: UInt32 = 0x2b
  static let encryptionInfo64: UInt32 = 0x2c
  static let linkerOption: UInt32 = 0x2d
  static let linkerOptimizationHint: UInt32 = 0x2e
  static let versionMinTvOS: UInt32 = 0x2f
  static let versionMinWatchOS: UInt32 = 0x30
  static let buildVersion: UInt32 = 0x32

  static let reqDyld: UInt32 = 0x8000_0000
  static let loadWeakDylib: UInt32 = 0x18 | reqDyld
  static let rpath: UInt32 = 0x1c | reqDyld
  static let reexportDylib: UInt32 = 0x1f | reqDyld
  static let dyldInfoOnly: UInt32 = 0x22 | reqDyld
  static let loadUpwardDylib: UInt32 = 0x23 | reqDyld
  static let main: UInt32 = 0x28 | reqDyld
  static let dyldExportsTrie: UInt32 = 0x33 | reqDyld
  static let dyldChainedFixups: UInt32 = 0x34 | reqDyld

  static let names: [UInt32: String] = [
    segment: "LC_SEGMENT", symtab: "LC_SYMTAB", thread: "LC_THREAD", unixThread: "LC_UNIXTHREAD",
    dysymtab: "LC_DYSYMTAB", loadDylib: "LC_LOAD_DYLIB", idDylib: "LC_ID_DYLIB",
    loadDylinker: "LC_LOAD_DYLINKER", idDylinker: "LC_ID_DYLINKER", segment64: "LC_SEGMENT_64",
    routines64: "LC_ROUTINES_64", uuid: "LC_UUID", codeSignature: "LC_CODE_SIGNATURE",
    segmentSplitInfo: "LC_SEGMENT_SPLIT_INFO", lazyLoadDylib: "LC_LAZY_LOAD_DYLIB",
    encryptionInfo: "LC_ENCRYPTION_INFO", dyldInfo: "LC_DYLD_INFO",
    versionMinMacOSX: "LC_VERSION_MIN_MACOSX", versionMinIPhoneOS: "LC_VERSION_MIN_IPHONEOS",
    functionStarts: "LC_FUNCTION_STARTS", dyldEnvironment: "LC_DYLD_ENVIRONMENT",
    dataInCode: "LC_DATA_IN_CODE", sourceVersion: "LC_SOURCE_VERSION",
    dylibCodeSignDRs: "LC_DYLIB_CODE_SIGN_DRS", encryptionInfo64: "LC_ENCRYPTION_INFO_64",
    linkerOption: "LC_LINKER_OPTION", linkerOptimizationHint: "LC_LINKER_OPTIMIZATION_HINT",
    versionMinTvOS: "LC_VERSION_MIN_TVOS", versionMinWatchOS: "LC_VERSION_MIN_WATCHOS",
    buildVersion: "LC_BUILD_VERSION", loadWeakDylib: "LC_LOAD_WEAK_DYLIB", rpath: "LC_RPATH",
    reexportDylib: "LC_REEXPORT_DYLIB", dyldInfoOnly: "LC_DYLD_INFO_ONLY",
    loadUpwardDylib: "LC_LOAD_UPWARD_DYLIB", main: "LC_MAIN",
    dyldExportsTrie: "LC_DYLD_EXPORTS_TRIE", dyldChainedFixups: "LC_DYLD_CHAINED_FIXUPS",
  ]

  static func name(_ cmd: UInt32) -> String { names[cmd] ?? "0x" + String(cmd, radix: 16) }
}

/// `PLATFORM_*` values used to label legacy `LC_VERSION_MIN_*` commands.
private enum Platform {
  static let macOS: UInt32 = 1
  static let iOS: UInt32 = 2
  static let tvOS: UInt32 = 3
  static let watchOS: UInt32 = 4

  static let names: [UInt32: String] = [
    1: "macos", 2: "ios", 3: "tvos", 4: "watchos", 5: "bridgeos", 6: "maccatalyst",
    7: "iossimulator", 8: "tvossimulator", 9: "watchossimulator", 10: "driverkit", 11: "visionos",
    12: "visionossimulator",
  ]

  static func name(_ p: UInt32) -> String { names[p] ?? "platform(\(p))" }
}

/// Symbol-table resource bounds; tests shrink them to exercise the truncation paths cheaply.
struct SymbolLimits {
  var maxSymbols = MachOSlice.maxSymbols
  var maxSymbolMemory = MachOFile.maxSymbolMemory
  var maxCachedNames = MachOSlice.maxCachedNames
}

/// Aggregate symbol-memory budget shared by every slice of one ``MachOFile``.
/// A charge that would exceed the limit is refused and changes nothing.
final class SymbolBudget {
  let limit: Int
  private(set) var used = 0
  init(limit: Int) { self.limit = limit }

  func charge(_ bytes: Int) -> Bool {
    guard bytes >= 0, bytes <= limit - used else { return false }
    used += bytes
    return true
  }
  var remaining: Int { limit - used }
}

/// Parses one thin Mach-O image. Every read is bounds-checked through ``Reader``.
struct MachOSliceParser {
  /// Accumulated results; also the place the "first LC_SYMTAB / LC_CODE_SIGNATURE only" state lives.
  private struct Output {
    var segments: [Segment] = []
    var libraries: [LinkedLibrary] = []
    var rpaths: [String] = []
    var encryption: [EncryptionInfo] = []
    var symbols: [Symbol] = []
    var buildVersion: BuildVersion?
    var minVersion: BuildVersion?
    var uuid: String?
    var signature: CodeSignature?
    var warnings: [String] = []
    var sawSymtab = false
    var sawSignature = false
  }

  private let r: Reader
  private let is64: Bool
  private var limits = SymbolLimits()
  private var budget = SymbolBudget(limit: MachOFile.maxSymbolMemory)

  /// `file` is the whole-file reader; `fileOffset`/`size` were already validated against it.
  static func parse(
    file: Reader, fileOffset: UInt64, size: UInt64, limits: SymbolLimits = SymbolLimits(),
    budget: SymbolBudget? = nil
  ) throws -> MachOSlice {
    let magic = try file.sub(fileOffset, size, bigEndian: false).u32(0)
    let is64: Bool
    let big: Bool
    switch magic {
    case MachOMagic.thin32: (is64, big) = (false, false)
    case MachOMagic.thin64: (is64, big) = (true, false)
    case MachOMagic.thin32Swapped: (is64, big) = (false, true)
    case MachOMagic.thin64Swapped: (is64, big) = (true, true)
    default: throw MachOError.invalidMagic(magic)
    }
    let r = try file.sub(fileOffset, size, bigEndian: big)
    let cpuType = Int32(bitPattern: try r.u32(4))
    let cpuSubtype = Int32(bitPattern: try r.u32(8))
    let fileType = try r.u32(12)
    let ncmds = try r.u32(16)
    let sizeofcmds = try r.u32(20)
    let flags = try r.u32(24)
    let headerSize: UInt64 = is64 ? 32 : 28
    _ = try r.sub(0, headerSize)  // the whole header must fit
    guard ncmds <= MachOSlice.maxLoadCommands else { throw MachOError.tooManyLoadCommands(ncmds) }
    let cmds = try r.sub(headerSize, UInt64(sizeofcmds))

    var parser = MachOSliceParser(r: r, is64: is64)
    parser.limits = limits
    parser.budget = budget ?? SymbolBudget(limit: limits.maxSymbolMemory)
    var out = Output()
    var loadCommands: [LoadCommand] = []
    var off: UInt64 = 0
    for _ in 0..<ncmds {
      guard cmds.size - off >= 8 else { throw MachOError.truncated("load command header") }
      let cmd = try cmds.u32(off)
      let cmdsize = try cmds.u32(off + 4)
      guard cmdsize >= 8, UInt64(cmdsize) <= cmds.size - off else {
        throw MachOError.malformed(
          "invalid cmdsize \(cmdsize) for command 0x\(String(cmd, radix: 16))")
      }
      let name = LC.name(cmd)
      loadCommands.append(
        LoadCommand(cmd: cmd, name: name, offset: headerSize + off, size: cmdsize))
      let c = try cmds.sub(off, UInt64(cmdsize))
      off += UInt64(cmdsize)
      do {
        try parser.handle(cmd, name: name, c, &out)
      } catch {
        out.warnings.append("\(name): \(error)")
      }
    }
    return MachOSlice(
      fileOffset: fileOffset, size: size, cpuType: cpuType, cpuSubtype: cpuSubtype,
      is64Bit: is64, fileType: fileType, flags: flags, loadCommands: loadCommands,
      segments: out.segments, linkedLibraries: out.libraries, rpaths: out.rpaths,
      encryptionInfo: out.encryption, minimumOS: out.buildVersion ?? out.minVersion,
      uuid: out.uuid, symbols: out.symbols, codeSignature: out.signature,
      parseWarnings: out.warnings)
  }

  private func handle(_ cmd: UInt32, name: String, _ c: Reader, _ out: inout Output) throws {
    switch cmd {
    case LC.segment, LC.segment64:
      out.segments.append(try segment(c))
    case LC.loadDylib: out.libraries.append(try dylib(c, .normal))
    case LC.loadWeakDylib: out.libraries.append(try dylib(c, .weak))
    case LC.reexportDylib: out.libraries.append(try dylib(c, .reexport))
    case LC.lazyLoadDylib: out.libraries.append(try dylib(c, .lazy))
    case LC.loadUpwardDylib: out.libraries.append(try dylib(c, .upward))
    case LC.rpath:
      guard let s = c.cString(UInt64(try c.u32(8))) else {
        throw MachOError.malformed("rpath offset invalid, unterminated or longer than 4096 bytes")
      }
      out.rpaths.append(s)
    case LC.uuid:
      out.uuid = Self.uuidString(try c.bytes(8, 16))
    case LC.encryptionInfo, LC.encryptionInfo64:
      let cryptOffset = try c.u32(8)
      let cryptSize = try c.u32(12)
      let cryptID = try c.u32(16)
      let within =
        UInt64(cryptOffset) <= r.size && UInt64(cryptSize) <= r.size - UInt64(cryptOffset)
      if cryptID != 0 && !within {
        out.warnings.append("\(name): encrypted range outside slice, ignored")
      }
      out.encryption.append(
        EncryptionInfo(
          cryptOffset: cryptOffset, cryptSize: cryptSize, cryptID: cryptID, isWithinSlice: within))
    case LC.buildVersion:
      let p = try c.u32(8)
      out.buildVersion = BuildVersion(
        platform: p, platformName: Platform.name(p),
        minOS: Self.version(try c.u32(12)), sdk: Self.version(try c.u32(16)))
    case LC.versionMinMacOSX, LC.versionMinIPhoneOS, LC.versionMinTvOS, LC.versionMinWatchOS:
      let p: UInt32
      switch cmd {
      case LC.versionMinMacOSX: p = Platform.macOS
      case LC.versionMinIPhoneOS: p = Platform.iOS
      case LC.versionMinTvOS: p = Platform.tvOS
      default: p = Platform.watchOS
      }
      out.minVersion = BuildVersion(
        platform: p, platformName: Platform.name(p),
        minOS: Self.version(try c.u32(8)), sdk: Self.version(try c.u32(12)))
    // Only the first LC_SYMTAB / LC_CODE_SIGNATURE is honoured (as dyld does); repeats would
    // let a crafted binary multiply the parsing work.
    case LC.symtab where !out.sawSymtab:
      out.sawSymtab = true
      out.symbols = try symbols(
        symoff: try c.u32(8), nsyms: try c.u32(12), stroff: try c.u32(16),
        strsize: try c.u32(20), warnings: &out.warnings)
    case LC.codeSignature where !out.sawSignature:
      out.sawSignature = true
      let sb = try r.sub(UInt64(try c.u32(8)), UInt64(try c.u32(12)), bigEndian: true)
      out.signature = try CodeSignature(superBlob: sb, warnings: &out.warnings)
    case LC.symtab, LC.codeSignature:
      out.warnings.append("\(name): duplicate command ignored")
    default: break
    }
  }

  private func segment(_ c: Reader) throws -> Segment {
    let hdr: UInt64 = is64 ? 72 : 56
    let secSize: UInt64 = is64 ? 80 : 68
    let nsects = UInt64(try c.u32(is64 ? 64 : 48))
    guard c.size >= hdr, nsects <= (c.size - hdr) / secSize else {
      throw MachOError.malformed("section count \(nsects) exceeds command size")
    }
    var sections: [Section] = []
    for i in 0..<nsects {
      let s = hdr + i * secSize
      sections.append(
        Section(
          name: try c.fixedString(s, 16), segmentName: try c.fixedString(s + 16, 16),
          offset: try c.u32(s + (is64 ? 48 : 40)),
          size: is64 ? try c.u64(s + 40) : UInt64(try c.u32(s + 36))))
    }
    func word(_ o: UInt64) throws -> UInt64 { is64 ? try c.u64(o) : UInt64(try c.u32(o)) }
    let w: UInt64 = is64 ? 8 : 4
    return Segment(
      name: try c.fixedString(8, 16), vmAddress: try word(24), vmSize: try word(24 + w),
      fileOffset: try word(24 + 2 * w), fileSize: try word(24 + 3 * w),
      maxProtection: Int32(bitPattern: try c.u32(24 + 4 * w)),
      initialProtection: Int32(bitPattern: try c.u32(28 + 4 * w)), sections: sections)
  }

  private func dylib(_ c: Reader, _ kind: LinkedLibrary.Kind) throws -> LinkedLibrary {
    guard let path = c.cString(UInt64(try c.u32(8))) else {
      throw MachOError.malformed(
        "dylib name offset invalid, unterminated or longer than 4096 bytes")
    }
    return LinkedLibrary(
      path: path, kind: kind, currentVersion: Self.version(try c.u32(16)),
      compatibilityVersion: Self.version(try c.u32(20)))
  }

  private func symbols(
    symoff: UInt32, nsyms: UInt32, stroff: UInt32, strsize: UInt32, warnings: inout [String]
  ) throws -> [Symbol] {
    let entSize: UInt64 = is64 ? 16 : 12
    let symbolStride = MemoryLayout<Symbol>.stride
    let symoff = UInt64(symoff)
    let stroff = UInt64(stroff)
    guard symoff <= r.size, stroff <= r.size else {
      warnings.append("LC_SYMTAB: table offsets outside slice")
      return []
    }
    var count = UInt64(nsyms)
    if count > limits.maxSymbols {
      warnings.append("LC_SYMTAB: nsyms \(count) capped at \(limits.maxSymbols)")
      count = limits.maxSymbols
    }
    let memoryCap = UInt64(limits.maxSymbolMemory / symbolStride)
    if count > memoryCap {
      warnings.append("LC_SYMTAB: nsyms \(count) capped at \(memoryCap) by the memory bound")
      count = memoryCap
    }
    let available = (r.size - symoff) / entSize
    if count > available {
      warnings.append("LC_SYMTAB: symbol table truncated (\(count) declared, \(available) fit)")
      count = available
    }
    let strLen = min(UInt64(strsize), r.size - stroff)
    if strLen < UInt64(strsize) { warnings.append("LC_SYMTAB: string table truncated") }
    let strings = try r.sub(stroff, strLen)
    var badNames = 0
    var budgetExceeded = false
    // Resolve names through a NUL index (one linear pass, binary search per lookup) so that
    // overlapping or unterminated references cost O(log n) instead of a rescan each. The index
    // is charged to the shared budget; if it is unaffordable, fall back to bounded rescans.
    // strsize is a UInt32, so window offsets fit in UInt32.
    let nulCount = strLen > 0 ? UInt64(strings.nulCount()) : 0
    let nuls: [UInt32]? =
      nulCount * 4 <= UInt64(budget.remaining) && budget.charge(Int(nulCount * 4))
      ? strings.nulOffsets() : nil
    var scanBudget = strLen &* 4 &+ (16 << 20)
    var scanExhausted = false
    func scanName(_ strx: UInt64) -> Int? {
      guard strx < strLen else { return nil }
      if let nuls {
        // First NUL at or after strx.
        var lo = 0
        var hi = nuls.count
        while lo < hi {
          let mid = (lo + hi) / 2
          if UInt64(nuls[mid]) < strx { lo = mid + 1 } else { hi = mid }
        }
        guard lo < nuls.count else { return nil }
        let length = UInt64(nuls[lo]) - strx
        return length <= 4096 ? Int(length) : nil
      }
      guard !scanExhausted else { return nil }
      let length = strings.cStringLength(strx)
      // Charge the bytes actually examined (name + NUL, or the whole window on failure).
      let used = length.map { UInt64($0) + 1 } ?? min(strLen - strx, 4097)
      if used >= scanBudget {
        scanBudget = 0
        scanExhausted = true
      } else {
        scanBudget -= used
      }
      return length
    }
    var names: [UInt64: String] = [:]
    var out: [Symbol] = []
    // Let the array grow instead of trusting `nsyms`; pre-pay only a bounded, affordable chunk.
    let prepaid = min(Int(min(count, 65_536)), budget.remaining / symbolStride)
    if prepaid > 0 && budget.charge(prepaid * symbolStride) { out.reserveCapacity(prepaid) }
    for i in 0..<count {
      // Array growth can double the capacity, so entries past the pre-paid chunk cost 2x.
      let entryCost = Int(i) < prepaid ? 0 : 2 * symbolStride
      let e = symoff + i * entSize
      let strx = UInt64(try r.u32(e))
      var name = ""
      var nameCost = 0
      var cacheIt = false
      if let cached = names[strx] {
        name = cached
      } else if let n = scanName(strx) {
        // Decoded names are heap strings: count the bytes plus a header estimate.
        nameCost = n == 0 ? 0 : n + 32
        cacheIt = n > 0 && names.count < limits.maxCachedNames
      } else {
        badNames += 1
      }
      // Check the next allocation before committing to it.
      guard budget.charge(entryCost + nameCost) else {
        budgetExceeded = true
        break
      }
      if nameCost > 0, let s = strings.cString(strx) {
        name = s
        // Empty names are free to re-decode; caching them would let distinct `strx` values
        // grow the cache without spending any name budget.
        if cacheIt && budget.charge(Self.cacheEntryCost) { names[strx] = s }
      }
      out.append(
        Symbol(
          name: name, type: try r.u8(e + 4), section: try r.u8(e + 5), desc: try r.u16(e + 6),
          value: is64 ? try r.u64(e + 8) : UInt64(try r.u32(e + 8))))
    }
    if badNames > 0 {
      warnings.append(
        "LC_SYMTAB: \(badNames) symbol names outside the string table, unterminated or "
          + "longer than 4096 bytes left empty"
      )
    }
    if scanExhausted {
      warnings.append("LC_SYMTAB: string scan budget exhausted; remaining names left empty")
    }
    if budgetExceeded {
      warnings.append(
        "LC_SYMTAB: symbols truncated at \(out.count) (\(limits.maxSymbolMemory) byte memory bound shared by all slices)"
      )
    }
    return out
  }

  /// Estimated storage of one name-cache entry (key, string value, hash-table overhead).
  private static let cacheEntryCost = 64

  private static func version(_ v: UInt32) -> String { "\(v >> 16).\((v >> 8) & 0xff).\(v & 0xff)" }

  private static func uuidString(_ b: Data) -> String {
    let hex = b.map { ($0 < 16 ? "0" : "") + String($0, radix: 16, uppercase: true) }
    return [hex[0..<4], hex[4..<6], hex[6..<8], hex[8..<10], hex[10..<16]].map { $0.joined() }
      .joined(separator: "-")
  }
}
