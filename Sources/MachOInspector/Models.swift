import Foundation

/// One entry of the load-command table, as found in the file (not interpreted).
public struct LoadCommand: Sendable, Hashable {
  /// Raw `cmd` value, including the `LC_REQ_DYLD` bit (0x8000_0000) where set.
  public let cmd: UInt32
  /// Symbolic name such as `LC_SEGMENT_64`, or `0x<hex>` for commands this library does not know.
  public let name: String
  /// Absolute offset of the command, relative to the start of the slice.
  public let offset: UInt64
  /// Declared `cmdsize`; always at least 8 and within the load-command area.
  public let size: UInt32
}

/// A section inside a ``Segment``.
public struct Section: Sendable, Hashable {
  public let name: String
  public let segmentName: String
  /// Section file offset, relative to the start of the slice. Not validated against the slice size.
  public let offset: UInt32
  public let size: UInt64
}

/// A `LC_SEGMENT` / `LC_SEGMENT_64` command. All values are as declared and are not cross-checked.
public struct Segment: Sendable, Hashable {
  public let name: String
  public let vmAddress: UInt64
  public let vmSize: UInt64
  public let fileOffset: UInt64
  public let fileSize: UInt64
  public let maxProtection: Int32
  public let initialProtection: Int32
  public let sections: [Section]
}

/// A dylib referenced by a `LC_*_DYLIB` command.
public struct LinkedLibrary: Sendable, Hashable {
  public enum Kind: Sendable, Hashable { case normal, weak, reexport, lazy, upward }
  public let path: String
  public let kind: Kind
  /// Dotted `major.minor.patch` version.
  public let currentVersion: String
  /// Dotted `major.minor.patch` version.
  public let compatibilityVersion: String
}

/// A `LC_ENCRYPTION_INFO(_64)` command (FairPlay).
public struct EncryptionInfo: Sendable, Hashable {
  /// Offset of the encrypted range, relative to the start of the slice.
  public let cryptOffset: UInt32
  public let cryptSize: UInt32
  /// Zero means the range is not encrypted.
  public let cryptID: UInt32
  /// True if `cryptOffset + cryptSize` lies inside the slice. A record that fails this is
  /// attacker-controlled or corrupt: it is kept as declared, but never exposed as a file range
  /// (see ``MachOSlice/encryptedFileRanges``), so it cannot mark a neighbouring FAT slice encrypted.
  public let isWithinSlice: Bool
}

/// Platform and OS versions from `LC_BUILD_VERSION` or a legacy `LC_VERSION_MIN_*` command.
public struct BuildVersion: Sendable, Hashable {
  /// Raw `PLATFORM_*` value.
  public let platform: UInt32
  /// Lower-case platform name such as `ios`, or `platform(<n>)` when unknown.
  public let platformName: String
  /// Dotted minimum OS version.
  public let minOS: String
  /// Dotted SDK version.
  public let sdk: String
}

/// One `nlist` symbol-table entry.
public struct Symbol: Sendable, Hashable {
  /// Empty when the name index was invalid or the slice's name-byte budget was exhausted
  /// (see ``MachOSlice/parseWarnings``).
  public let name: String
  /// Raw `n_type`.
  public let type: UInt8
  /// Raw `n_sect`.
  public let section: UInt8
  /// Raw `n_desc`.
  public let desc: UInt16
  /// Raw `n_value`.
  public let value: UInt64

  /// True for debugger (stab) entries.
  public var isStab: Bool { type & NList.stabMask != 0 }
  /// True for external symbols (`N_EXT`).
  public var isExternal: Bool { type & NList.external != 0 }
  /// True for non-stab symbols whose raw type is `N_UNDF`. This includes common symbols
  /// (``isCommon``); use ``MachOSlice/importedSymbols`` for real imports.
  public var isUndefined: Bool { type & NList.typeMask == 0 && !isStab }
  /// True for common symbols: `N_UNDF | N_EXT` with a non-zero `n_value` (the size). They are
  /// definitions to be allocated by the linker, not imports.
  public var isCommon: Bool { isUndefined && isExternal && value != 0 }
  /// True for stab entries that carry debug information; `N_OPT` is excluded because `ld`
  /// emits one (`radr://5614542`) into virtually every binary, stripped or not.
  var isDebugStab: Bool { isStab && type != NList.optStab }
}

/// `nlist` `n_type` bit masks and values.
enum NList {
  static let stabMask: UInt8 = 0xe0
  static let external: UInt8 = 0x01
  static let typeMask: UInt8 = 0x0e
  static let optStab: UInt8 = 0x3c
}
