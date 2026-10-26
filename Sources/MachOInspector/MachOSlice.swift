import Foundation

/// One architecture's Mach-O image: a whole thin file, or one slice of a FAT file.
///
/// Instances are produced only by ``MachOFile``. Everything is parsed eagerly from untrusted
/// input; problems that leave the rest of the slice usable are reported in ``parseWarnings``
/// instead of failing the parse.
public struct MachOSlice: Sendable, Hashable {
  /// Maximum number of load commands accepted (`ncmds`); more throws ``MachOError/tooManyLoadCommands(_:)``.
  public static let maxLoadCommands: UInt32 = 10_000
  /// Maximum number of `nlist` entries decoded; the rest are dropped with a warning.
  public static let maxSymbols: UInt64 = 4_000_000
  // The symbol-memory bound is shared by all slices: see ``MachOFile/maxSymbolMemory``.
  /// Maximum number of distinct non-empty names kept in the per-slice name cache.
  static let maxCachedNames = 1 << 20

  /// Offset of the slice within the containing file (0 for thin files).
  public let fileOffset: UInt64
  public let size: UInt64
  public let cpuType: Int32
  public let cpuSubtype: Int32
  public let is64Bit: Bool
  public let fileType: UInt32
  public let flags: UInt32
  public let loadCommands: [LoadCommand]
  public let segments: [Segment]
  public let linkedLibraries: [LinkedLibrary]
  public let rpaths: [String]
  public let encryptionInfo: [EncryptionInfo]
  /// `LC_BUILD_VERSION` if present, otherwise the legacy `LC_VERSION_MIN_*` command.
  public let minimumOS: BuildVersion?
  /// Upper-case, hyphenated `LC_UUID`.
  public let uuid: String?
  public let symbols: [Symbol]
  /// Only the first `LC_CODE_SIGNATURE` is parsed.
  public let codeSignature: CodeSignature?
  /// Non-fatal problems, e.g. a malformed command that was skipped or a truncated symbol table.
  public let parseWarnings: [String]

  // Parser output only; the library never constructs partial slices for callers.
  init(
    fileOffset: UInt64, size: UInt64, cpuType: Int32, cpuSubtype: Int32, is64Bit: Bool,
    fileType: UInt32, flags: UInt32, loadCommands: [LoadCommand], segments: [Segment],
    linkedLibraries: [LinkedLibrary], rpaths: [String], encryptionInfo: [EncryptionInfo],
    minimumOS: BuildVersion?, uuid: String?, symbols: [Symbol], codeSignature: CodeSignature?,
    parseWarnings: [String]
  ) {
    self.fileOffset = fileOffset
    self.size = size
    self.cpuType = cpuType
    self.cpuSubtype = cpuSubtype
    self.is64Bit = is64Bit
    self.fileType = fileType
    self.flags = flags
    self.loadCommands = loadCommands
    self.segments = segments
    self.linkedLibraries = linkedLibraries
    self.rpaths = rpaths
    self.encryptionInfo = encryptionInfo
    self.minimumOS = minimumOS
    self.uuid = uuid
    self.symbols = symbols
    self.codeSignature = codeSignature
    self.parseWarnings = parseWarnings
  }

  /// Human-readable architecture (`arm64`, `arm64e`, `armv7`, `armv7s`, `x86_64`, `i386`),
  /// or `cpu(<type>,<subtype>)` for anything else.
  public var architecture: String {
    let sub = cpuSubtype & CPU.subtypeMask  // strip capability bits
    switch cpuType {
    case CPU.arm64: return sub == CPU.arm64e ? "arm64e" : "arm64"
    case CPU.arm:
      if sub == CPU.armv7 { return "armv7" }
      if sub == CPU.armv7s { return "armv7s" }
    case CPU.intel64: return "x86_64"
    case CPU.x86: return "i386"
    default: break
    }
    return "cpu(\(cpuType),\(cpuSubtype))"
  }

  /// `MH_PIE`: position-independent executable.
  public var isPIE: Bool { flags & Flags.pie != 0 }
  /// `MH_ALLOW_STACK_EXECUTION`.
  public var allowsStackExecution: Bool { flags & Flags.allowStackExecution != 0 }
  /// `MH_NO_HEAP_EXECUTION`.
  public var hasNoHeapExecution: Bool { flags & Flags.noHeapExecution != 0 }
  /// True if any encryption command has a non-zero `cryptid`, even when its range is outside
  /// the slice (fail safe: the binary claims to be encrypted, so callers must not assume
  /// plaintext). See ``hasInvalidEncryptionRange``.
  public var isEncrypted: Bool { encryptionInfo.contains { $0.cryptID != 0 } }
  /// True if a command with a non-zero `cryptid` has a range outside the slice. Such ranges are
  /// absent from ``encryptedFileRanges`` and a parse warning is added, so ``isEncrypted`` can be
  /// true while the ranges are incomplete: treat the encrypted extent as unknown.
  public var hasInvalidEncryptionRange: Bool {
    encryptionInfo.contains { $0.cryptID != 0 && !$0.isWithinSlice }
  }

  /// Encrypted ranges as absolute offsets into the containing file. Only ranges that lie inside
  /// this slice are listed; out-of-slice records are omitted (see ``hasInvalidEncryptionRange``).
  public var encryptedFileRanges: [Range<UInt64>] {
    encryptionInfo.compactMap { e in
      guard e.cryptID != 0, e.cryptSize > 0, e.isWithinSlice else { return nil }
      let (lo, o1) = fileOffset.addingReportingOverflow(UInt64(e.cryptOffset))
      let (hi, o2) = lo.addingReportingOverflow(UInt64(e.cryptSize))
      return o1 || o2 ? nil : lo..<hi
    }
  }

  /// Names of undefined external symbols with `n_value == 0`; common symbols are excluded.
  public var importedSymbols: Set<String> {
    Set(symbols.lazy.filter { $0.isUndefined && $0.isExternal && $0.value == 0 }.map(\.name))
  }

  /// Stab entries that carry debug information (`N_OPT` excluded, see ``Symbol/isStab``).
  public var debugStabs: [Symbol] { symbols.filter(\.isDebugStab) }
  /// True if ``debugStabs`` is non-empty.
  public var hasDebugSymbols: Bool { symbols.contains(where: \.isDebugStab) }

  /// Mach-O header `flags` bits.
  private enum Flags {
    static let allowStackExecution: UInt32 = 0x2_0000
    static let pie: UInt32 = 0x20_0000
    static let noHeapExecution: UInt32 = 0x100_0000
  }

  /// `cputype` / `cpusubtype` values.
  private enum CPU {
    static let subtypeMask: Int32 = 0x00ff_ffff
    static let x86: Int32 = 7
    static let arm: Int32 = 12
    static let intel64: Int32 = 0x0100_0007
    static let arm64: Int32 = 0x0100_000c
    static let armv7: Int32 = 9
    static let armv7s: Int32 = 11
    static let arm64e: Int32 = 2
  }
}
