// MachOFixtures: synthetic Mach-O / FAT / code-signature builders for tests.
//
// TEST SUPPORT ONLY. This product is not covered by semantic-versioning guarantees: its API may
// change in any release and it must not be linked into shipping binaries. Its builders can
// produce deliberately malformed images.
import Foundation

/// Byte writer; little-endian by default.
public struct Bytes {
  public var d = Data()
  public var be = false
  public init() {}
  public mutating func u8(_ v: UInt8) { d.append(v) }
  public mutating func int(_ v: UInt64, _ n: Int) {
    for i in 0..<n {
      let shift = be ? 8 * (n - 1 - i) : 8 * i
      d.append(UInt8((v >> UInt64(shift)) & 0xff))
    }
  }
  public mutating func u16(_ v: UInt16) { int(UInt64(v), 2) }
  public mutating func u32(_ v: UInt32) { int(UInt64(v), 4) }
  public mutating func u64(_ v: UInt64) { int(v, 8) }
  public mutating func fixed(_ s: String, _ n: Int) {
    var b = Array(s.utf8.prefix(n))
    b += [UInt8](repeating: 0, count: n - b.count)
    d.append(contentsOf: b)
  }
  public mutating func cstr(_ s: String) {
    d.append(contentsOf: Array(s.utf8))
    d.append(0)
  }
  public mutating func pad(to n: Int) { if d.count < n { d.append(Data(count: n - d.count)) } }
}

public func le(_ f: (inout Bytes) -> Void) -> Data {
  var b = Bytes()
  f(&b)
  return b.d
}
public func be(_ f: (inout Bytes) -> Void) -> Data {
  var b = Bytes()
  b.be = true
  f(&b)
  return b.d
}

public func patch(_ data: inout Data, at off: Int, u32 v: UInt32, bigEndian: Bool = false) {
  for i in 0..<4 {
    let shift = bigEndian ? 8 * (3 - i) : 8 * i
    data[data.startIndex + off + i] = UInt8((v >> UInt32(shift)) & 0xff)
  }
}

public func u32LE(_ d: Data, _ off: Int) -> UInt32 {
  (0..<4).reduce(0) { $0 | UInt32(d[d.startIndex + off + $1]) << UInt32(8 * $1) }
}

public let entitlementsXML = "<plist><dict><key>get-task-allow</key><true/></dict></plist>"

/// Synthesizes a 64-bit little-endian Mach-O. Commands live below `payloadOffset`, payload above.
public struct TestImage {
  public static let payloadOffset = 0x800

  /// Where tables start; raise it for images whose load commands exceed `payloadOffset`.
  public var payloadStart = TestImage.payloadOffset
  public var cpuType: UInt32 = 0x0100_000c
  public var cpuSubtype: UInt32 = 0
  public var fileType: UInt32 = 2
  public var flags: UInt32 = 0x20_0085
  public var cryptID: UInt32?
  public var cryptOffset: UInt32 = 0x1000
  public var cryptSize: UInt32 = 0x2000
  /// When true (default) and `cryptID` is set, the image is zero-padded so the crypt range lies
  /// inside it; set false to build records that point outside the slice.
  public var padToCryptRange = true
  public var symbols: [(name: String, type: UInt8)] = []
  /// `n_value` overrides by symbol index (default: 0 for undefined symbols, 0x1000 otherwise).
  public var symbolValues: [Int: UInt64] = [:]
  /// Extra external symbols whose `strx` points at a distinct empty string each.
  public var zeroNameSymbols = 0
  public var signature: Data?
  /// LC_RPATH entries; the default matches the historical fixture.
  public var rpaths: [String] = ["@executable_path/Frameworks"]
  /// Extra LC_LOAD_DYLIB paths appended after the two default libraries.
  public var extraLibraries: [String] = []
  /// Extra segments without sections, as (name, initprot, maxprot).
  public var extraSegments: [(name: String, initprot: Int32, maxprot: Int32)] = []
  /// LC_BUILD_VERSION minos in the packed x.y.z form (default 15.0.0).
  public var minOS: UInt32 = 0x0f_0000
  /// Raw bytes written at absolute file offsets (must be past the symbol/signature area).
  public var blobs: [(offset: Int, data: Data)] = []

  public init() {}

  public static let sampleSymbols: [(name: String, type: UInt8)] = [
    ("___stack_chk_fail", 0x01), ("_objc_release", 0x01), ("_main", 0x0f), ("_stab_fun", 0x24),
  ]

  /// Symbols for a typical hardened ObjC binary without debug stabs.
  public static let hardenedSymbols: [(name: String, type: UInt8)] = [
    ("___stack_chk_fail", 0x01), ("___stack_chk_guard", 0x01), ("_objc_release", 0x01),
    ("_objc_retain", 0x01), ("_main", 0x0f),
  ]

  public func data() -> Data {
    var strtab = Bytes()
    strtab.u8(0)
    var nlist = Bytes()
    for (i, s) in symbols.enumerated() {
      nlist.u32(UInt32(strtab.d.count))
      nlist.u8(s.type)
      nlist.u8(s.type & 0x0e == 0 ? 0 : 1)
      nlist.u16(0)
      let undefined = s.type & 0xe0 == 0 && s.type & 0x0e == 0
      nlist.u64(symbolValues[i] ?? (undefined ? 0 : 0x1000))
      strtab.cstr(s.name)
    }
    if zeroNameSymbols > 0 {
      let base = strtab.d.count
      var raw = [UInt8]()
      raw.reserveCapacity(zeroNameSymbols * 16)
      for i in 0..<zeroNameSymbols {
        let strx = UInt32(base + i)
        raw += [UInt8(strx & 0xff), UInt8((strx >> 8) & 0xff), UInt8((strx >> 16) & 0xff)]
        raw += [UInt8(strx >> 24), 0x01, 1, 0, 0]
        raw += [UInt8](repeating: 0, count: 8)
      }
      nlist.d.append(contentsOf: raw)
      strtab.d.append(Data(count: zeroNameSymbols))
    }
    let symbolCount = symbols.count + zeroNameSymbols
    let symoff = payloadStart
    let stroff = symoff + nlist.d.count
    let sigoff = stroff + strtab.d.count

    var cmds: [Data] = []
    cmds.append(
      le { b in
        b.u32(0x19)
        b.u32(72 + 80)
        b.fixed("__TEXT", 16)
        b.u64(0x1_0000_0000)
        b.u64(0x4000)
        b.u64(0)
        b.u64(0x4000)
        b.u32(5)
        b.u32(5)
        b.u32(1)
        b.u32(0)
        b.fixed("__text", 16)
        b.fixed("__TEXT", 16)
        b.u64(0x1_0000_1000)
        b.u64(0x20)
        b.u32(0x1000)
        b.u32(0)
        b.u32(0)
        b.u32(0)
        b.u32(0)
        b.u32(0)
        b.u32(0)
        b.u32(0)
      })
    for seg in extraSegments {
      cmds.append(
        le { b in
          b.u32(0x19)
          b.u32(72)
          b.fixed(seg.name, 16)
          b.u64(0x2_0000_0000)
          b.u64(0x4000)
          b.u64(0)
          b.u64(0)
          b.u32(UInt32(bitPattern: seg.maxprot))
          b.u32(UInt32(bitPattern: seg.initprot))
          b.u32(0)
          b.u32(0)
        })
    }
    let libs: [(UInt32, String, UInt32)] =
      [
        (0xc, "/usr/lib/libSystem.B.dylib", 0x4c_0000 | 0x0501),
        (0x8000_0018, "/System/Library/Frameworks/UIKit.framework/UIKit", 0x10_0000),
      ]
      + extraLibraries.map { (0xc, $0, 0x10_0000) }
    for (cmd, path, cur) in libs {
      cmds.append(
        le { b in
          let size = (24 + path.utf8.count + 1 + 7) & ~7
          b.u32(cmd)
          b.u32(UInt32(size))
          b.u32(24)
          b.u32(2)
          b.u32(cur)
          b.u32(0x01_0000)
          b.cstr(path)
          b.pad(to: size)
        })
    }
    for rpath in rpaths {
      cmds.append(
        le { b in
          let size = (12 + rpath.utf8.count + 1 + 7) & ~7
          b.u32(0x8000_001c)
          b.u32(UInt32(size))
          b.u32(12)
          b.cstr(rpath)
          b.pad(to: size)
        })
    }
    cmds.append(
      le { b in
        b.u32(0x1b)
        b.u32(24)
        b.d.append(contentsOf: (0..<16).map { UInt8(0xa0 + $0) })
      })
    cmds.append(
      le { b in
        b.u32(0x32)
        b.u32(24)
        b.u32(2)
        b.u32(minOS)
        b.u32(0x11_0001)
        b.u32(0)
      })
    if let cryptID {
      cmds.append(
        le { b in
          b.u32(0x2c)
          b.u32(24)
          b.u32(cryptOffset)
          b.u32(cryptSize)
          b.u32(cryptID)
          b.u32(0)
        })
    }
    if symbolCount > 0 {
      cmds.append(
        le { b in
          b.u32(0x2)
          b.u32(24)
          b.u32(UInt32(symoff))
          b.u32(UInt32(symbolCount))
          b.u32(UInt32(stroff))
          b.u32(UInt32(strtab.d.count))
        })
    }
    if let signature {
      cmds.append(
        le { b in
          b.u32(0x1d)
          b.u32(16)
          b.u32(UInt32(sigoff))
          b.u32(UInt32(signature.count))
        })
    }
    let body = cmds.reduce(Data(), +)
    var out = le { b in
      b.u32(0xfeed_facf)
      b.u32(cpuType)
      b.u32(cpuSubtype)
      b.u32(fileType)
      b.u32(UInt32(cmds.count))
      b.u32(UInt32(body.count))
      b.u32(flags)
      b.u32(0)
    }
    out += body
    precondition(out.count <= payloadStart)
    out.append(Data(count: payloadStart - out.count))
    out += nlist.d + strtab.d
    if let signature { out += signature }
    for blob in blobs {
      precondition(blob.offset >= out.count || blob.data.isEmpty, "blob overlaps image tables")
      out.append(Data(count: max(0, blob.offset - out.count)))
      out += blob.data
    }
    if cryptID != nil, padToCryptRange {
      out.append(Data(count: max(0, Int(cryptOffset) + Int(cryptSize) - out.count)))
    }
    return out
  }
}

public func codeDirectory(
  identifier: String, team: String, version: UInt32 = 0x20400, hashType: UInt8 = 2,
  codeLimit: UInt32 = 0x2000, codeLimit64: UInt64 = 0
) -> Data {
  let hashSize: UInt8 = hashType == 1 ? 20 : 32
  var tail = Bytes()
  tail.cstr(identifier)
  let teamOffset = 88 + tail.d.count
  tail.cstr(team)
  let hashOffset = 88 + tail.d.count
  tail.d.append(Data(count: 2 * Int(hashSize)))
  var b = Bytes()
  b.be = true
  b.u32(0xfade_0c02)
  b.u32(UInt32(88 + tail.d.count))
  b.u32(version)
  b.u32(0x0002_0000)
  b.u32(UInt32(hashOffset))
  b.u32(88)
  b.u32(0)
  b.u32(2)
  b.u32(codeLimit)
  b.u8(hashSize)
  b.u8(hashType)
  b.u8(0)
  b.u8(12)
  b.u32(0)
  b.u32(0)
  b.u32(UInt32(teamOffset))
  b.u32(0)
  b.u64(codeLimit64)
  b.u64(0)
  b.u64(0x4000)
  b.u64(1)
  return b.d + tail.d
}

public func simpleBlob(magic: UInt32, payload: Data) -> Data {
  be { b in
    b.u32(magic)
    b.u32(UInt32(8 + payload.count))
  } + payload
}

public func superBlob(_ blobs: [(slot: UInt32, data: Data)]) -> Data {
  var b = Bytes()
  b.be = true
  var offset = 12 + blobs.count * 8
  b.u32(0xfade_0cc0)
  b.u32(UInt32(offset + blobs.reduce(0) { $0 + $1.data.count }))
  b.u32(UInt32(blobs.count))
  for blob in blobs {
    b.u32(blob.slot)
    b.u32(UInt32(offset))
    offset += blob.data.count
  }
  for blob in blobs { b.d += blob.data }
  return b.d
}

public func sampleSignature(
  cms: Data = Data([1, 2, 3, 4]), entitlements: String? = entitlementsXML,
  entitlementsDER: Data? = nil,
  identifier: String = "com.example.app", team: String = "ABCDE12345", cdVersion: UInt32 = 0x20400,
  hashType: UInt8 = 2
) -> Data {
  var blobs: [(slot: UInt32, data: Data)] = [
    (0, codeDirectory(identifier: identifier, team: team, version: cdVersion, hashType: hashType)),
    (2, simpleBlob(magic: 0xfade_0c01, payload: Data())),
  ]
  if let entitlements {
    blobs.append((5, simpleBlob(magic: 0xfade_7171, payload: Data(entitlements.utf8))))
  }
  if let entitlementsDER {
    blobs.append((7, simpleBlob(magic: 0xfade_7172, payload: entitlementsDER)))
  }
  blobs.append((0x10000, simpleBlob(magic: 0xfade_0b01, payload: cms)))
  return superBlob(blobs)
}

public func fat(_ slices: [(cpu: UInt32, sub: UInt32, data: Data)], fat64: Bool = false) -> Data {
  var b = Bytes()
  b.be = true
  b.u32(fat64 ? 0xcafe_babf : 0xcafe_babe)
  b.u32(UInt32(slices.count))
  var offset = 0x4000
  var placed: [(Int, Data)] = []
  for s in slices {
    b.u32(s.cpu)
    b.u32(s.sub)
    if fat64 {
      b.u64(UInt64(offset))
      b.u64(UInt64(s.data.count))
      b.u32(14)
      b.u32(0)
    } else {
      b.u32(UInt32(offset))
      b.u32(UInt32(s.data.count))
      b.u32(14)
    }
    placed.append((offset, s.data))
    offset = (offset + s.data.count + 0x3fff) & ~0x3fff
  }
  for (off, d) in placed {
    b.pad(to: off)
    b.d += d
  }
  return b.d
}
