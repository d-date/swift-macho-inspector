import Foundation

/// One entry of the SuperBlob index.
public struct BlobIndex: Sendable, Hashable {
  /// Slot type (for example 0 for the primary CodeDirectory).
  public let type: UInt32
  /// Magic of the blob the entry points to.
  public let magic: UInt32
  /// Blob offset from the start of the SuperBlob; validated to lie inside it.
  public let offset: UInt32
}

/// A parsed CodeDirectory. Fields are as declared; hashes are never computed or verified.
public struct CodeDirectory: Sendable, Hashable {
  public let version: UInt32
  public let flags: UInt32
  /// Raw hash type; see ``hashTypeName``.
  public let hashType: UInt8
  public let hashSize: UInt8
  public let pageSizeLog2: UInt8
  /// Empty (plus a parse warning) if the identifier is outside the blob, unterminated or longer
  /// than 4096 bytes.
  public let identifier: String
  /// Present only for version 0x20200 and later, and when the offset is valid.
  public let teamIdentifier: String?
  public let codeLimit: UInt64
  public let nSpecialSlots: UInt32
  public let nCodeSlots: UInt32
  /// Present only for version 0x20400 and later.
  public let execSegFlags: UInt64?

  /// `sha1`, `sha256`, `sha256-truncated`, `sha384`, or `unknown(<n>)`.
  public var hashTypeName: String {
    switch hashType {
    case 1: "sha1"
    case 2: "sha256"
    case 3: "sha256-truncated"
    case 4: "sha384"
    default: "unknown(\(hashType))"
    }
  }

  /// `blob` is a big-endian window covering exactly this CodeDirectory blob.
  init(blob: Reader, warnings: inout [String]) throws {
    version = try blob.u32(8)
    flags = try blob.u32(12)
    let identOffset = try blob.u32(20)
    nSpecialSlots = try blob.u32(24)
    nCodeSlots = try blob.u32(28)
    let limit32 = try blob.u32(32)
    hashSize = try blob.u8(36)
    hashType = try blob.u8(37)
    pageSizeLog2 = try blob.u8(39)
    if let id = blob.cString(UInt64(identOffset)) {
      identifier = id
    } else {
      identifier = ""
      warnings.append(
        "CodeDirectory: identifier invalid, unterminated or longer than 4096 bytes, left empty")
    }
    if version >= 0x20200 {
      let teamOffset = try blob.u32(48)
      let team = teamOffset == 0 ? nil : blob.cString(UInt64(teamOffset))
      if teamOffset != 0 && team == nil {
        warnings.append("CodeDirectory: team identifier invalid or unterminated, ignored")
      }
      teamIdentifier = team
    } else {
      teamIdentifier = nil
    }
    // As Apple's signingLimit(): codeLimit64 wins when set, else the 32-bit codeLimit.
    let limit64 = version >= 0x20300 ? try blob.u64(56) : 0
    codeLimit = limit64 != 0 ? limit64 : UInt64(limit32)
    execSegFlags = version >= 0x20400 ? try blob.u64(80) : nil
  }
}

/// The structure of an embedded code signature (`LC_CODE_SIGNATURE` SuperBlob).
///
/// Structure only: no hash or CMS verification is performed, so ``hasCMSSignature`` means a
/// non-empty signature blob exists, not that it is valid.
public struct CodeSignature: Sendable, Hashable {
  /// Maximum number of blobs accepted in a SuperBlob; more is rejected as malformed.
  public static let maxBlobs: UInt64 = 64
  /// At most this many CodeDirectories (primary plus alternates) are parsed.
  public static let maxCodeDirectories = 6

  public let blobs: [BlobIndex]
  public let codeDirectories: [CodeDirectory]
  /// Payload of the first XML entitlements blob.
  public let entitlementsXML: Data?
  /// Payload of the first DER entitlements blob.
  public let entitlementsDER: Data?
  public let hasCMSSignature: Bool
  /// Size in bytes of the largest CMS blob payload, 0 if none.
  public let cmsSignatureSize: Int
  public let hasRequirements: Bool

  /// Everything in the SuperBlob is big-endian regardless of the Mach-O byte order.
  init(superBlob sb: Reader, warnings: inout [String]) throws {
    guard try sb.u32(0) == Magic.superBlob else {
      throw MachOError.malformed("bad SuperBlob magic")
    }
    let length = UInt64(try sb.u32(4))
    let count = UInt64(try sb.u32(8))
    guard length >= 12, length <= sb.size else {
      throw MachOError.malformed("bad SuperBlob length")
    }
    // Real signatures carry ~10 blobs; the cap bounds work on crafted SuperBlobs.
    guard count <= Self.maxBlobs else {
      throw MachOError.malformed("SuperBlob count \(count) exceeds \(Self.maxBlobs)")
    }
    guard count <= (length - 12) / 8 else {
      throw MachOError.malformed("SuperBlob count \(count) exceeds length")
    }
    let body = try sb.sub(0, length)

    var blobs: [BlobIndex] = []
    var dirs: [CodeDirectory] = []
    var xml: Data?
    var der: Data?
    var cms = 0
    var reqs = false
    let tableEnd = 12 + count * 8
    var seenTypes = Set<UInt32>()
    var extents: [(start: UInt64, end: UInt64)] = []
    for i in 0..<count {
      let type = try body.u32(12 + i * 8)
      let off = UInt64(try body.u32(12 + i * 8 + 4))
      // A repeated slot would let one copy hide another (CodeDirectory cap, first-wins XML).
      guard seenTypes.insert(type).inserted else {
        throw MachOError.malformed("duplicate SuperBlob slot 0x\(String(type, radix: 16))")
      }
      guard off >= tableEnd else {
        throw MachOError.malformed("blob \(i) overlaps the index table")
      }
      let magic = try body.u32(off)
      let len = UInt64(try body.u32(off + 4))
      guard len >= 8, off + len <= body.size else {
        throw MachOError.malformed("blob \(i) out of range")
      }
      extents.append((off, off + len))
      blobs.append(BlobIndex(type: type, magic: magic, offset: UInt32(off)))
      switch (type, magic) {
      case (_, Magic.codeDirectory)
      where Slot.isCodeDirectory(type) && dirs.count < Self.maxCodeDirectories:
        dirs.append(try CodeDirectory(blob: try body.sub(off, len), warnings: &warnings))
      case (Slot.entitlements, Magic.entitlements):
        if xml == nil { xml = try body.bytes(off + 8, len - 8) }
      case (Slot.derEntitlements, Magic.derEntitlements):
        if der == nil { der = try body.bytes(off + 8, len - 8) }
      case (Slot.signature, Magic.cmsWrapper):
        cms = max(cms, Int(len - 8))
      case (Slot.requirements, Magic.requirements):
        reqs = true
      default:
        break
      }
    }
    let sorted = extents.sorted { $0.start < $1.start }
    for (a, b) in zip(sorted, sorted.dropFirst()) where a.end > b.start {
      throw MachOError.malformed("overlapping SuperBlob blobs")
    }
    self.blobs = blobs
    codeDirectories = dirs
    entitlementsXML = xml
    entitlementsDER = der
    hasCMSSignature = cms > 0
    cmsSignatureSize = cms
    hasRequirements = reqs
  }
}

/// Code-signing blob magic numbers.
private enum Magic {
  static let superBlob: UInt32 = 0xfade_0cc0
  static let codeDirectory: UInt32 = 0xfade_0c02
  static let requirements: UInt32 = 0xfade_0c01
  static let entitlements: UInt32 = 0xfade_7171
  static let derEntitlements: UInt32 = 0xfade_7172
  static let cmsWrapper: UInt32 = 0xfade_0b01
}

/// Code-signing slot types.
private enum Slot {
  static let codeDirectory: UInt32 = 0
  static let requirements: UInt32 = 2
  static let entitlements: UInt32 = 5
  static let derEntitlements: UInt32 = 7
  static let alternateCodeDirectories: ClosedRange<UInt32> = 0x1000...0x1004

  static func isCodeDirectory(_ type: UInt32) -> Bool {
    type == codeDirectory || alternateCodeDirectories.contains(type)
  }
  static let signature: UInt32 = 0x10000
}
