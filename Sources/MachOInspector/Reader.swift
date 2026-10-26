import Foundation

/// Errors that abort parsing. Recoverable problems are reported as ``MachOSlice/parseWarnings`` instead.
public enum MachOError: Error, Sendable, Hashable {
  /// A read or range extends past the end of its containing slice, command or file.
  case truncated(String)
  /// The slice does not start with a Mach-O magic number.
  case invalidMagic(UInt32)
  /// `ncmds` exceeds ``MachOSlice/maxLoadCommands``.
  case tooManyLoadCommands(UInt32)
  /// A structural field is invalid (bad `cmdsize`, FAT count, overlapping FAT slices, ...).
  case malformed(String)
}

/// Bounds-checked window over `Data`. Offsets are relative to the window.
struct Reader: Sendable {
  let data: Data
  let base: UInt64
  let size: UInt64
  let bigEndian: Bool

  init(data: Data, bigEndian: Bool = false) {
    self.data = data
    self.base = 0
    self.size = UInt64(data.count)
    self.bigEndian = bigEndian
  }

  private init(data: Data, base: UInt64, size: UInt64, bigEndian: Bool) {
    self.data = data
    self.base = base
    self.size = size
    self.bigEndian = bigEndian
  }

  func sub(_ off: UInt64, _ len: UInt64, bigEndian: Bool? = nil) throws -> Reader {
    guard off <= size, len <= size - off else {
      throw MachOError.truncated("range \(off)+\(len) exceeds \(size)")
    }
    return Reader(data: data, base: base + off, size: len, bigEndian: bigEndian ?? self.bigEndian)
  }

  func uint(_ off: UInt64, _ n: Int) throws -> UInt64 {
    guard off <= size, UInt64(n) <= size - off else {
      throw MachOError.truncated("read of \(n) bytes at \(off) exceeds \(size)")
    }
    let start = data.startIndex + Int(base + off)
    var v: UInt64 = 0
    for i in 0..<n {
      let b = UInt64(data[start + i])
      if bigEndian { v = (v << 8) | b } else { v |= b << UInt64(8 * i) }
    }
    return v
  }

  func u8(_ off: UInt64) throws -> UInt8 { UInt8(truncatingIfNeeded: try uint(off, 1)) }
  func u16(_ off: UInt64) throws -> UInt16 { UInt16(truncatingIfNeeded: try uint(off, 2)) }
  func u32(_ off: UInt64) throws -> UInt32 { UInt32(truncatingIfNeeded: try uint(off, 4)) }
  func u64(_ off: UInt64) throws -> UInt64 { try uint(off, 8) }

  func bytes(_ off: UInt64, _ len: UInt64) throws -> Data {
    let r = try sub(off, len)
    let start = data.startIndex + Int(r.base)
    return Data(data[start..<start + Int(len)])
  }

  /// Window offsets of every NUL byte, ascending. One linear pass; lets callers resolve many
  /// (possibly overlapping) string references by binary search instead of rescanning.
  func nulOffsets() -> [UInt32] {
    var out: [UInt32] = []
    out.reserveCapacity(nulCount())
    forEachNul { out.append(UInt32($0)) }
    return out
  }

  /// Number of NUL bytes in the window (used to charge the index before building it).
  func nulCount() -> Int {
    var n = 0
    forEachNul { _ in n += 1 }
    return n
  }

  private func forEachNul(_ body: (Int) -> Void) {
    data.withUnsafeBytes { raw in
      let bytes = raw.bindMemory(to: UInt8.self)
      let lower = Int(base)
      for i in 0..<Int(size) where bytes[lower + i] == 0 { body(i) }
    }
  }

  /// Length of the NUL-terminated string at `off`, excluding the NUL. Nil if `off` is outside
  /// the window, the NUL is not inside the window, or the string is longer than `maxLen`
  /// (never a silent truncation or an unterminated string accepted as complete).
  func cStringLength(_ off: UInt64, maxLen: Int = 4096) -> Int? {
    guard off < size else { return nil }
    let n = Int(min(size - off, UInt64(maxLen) + 1))
    let start = data.startIndex + Int(base + off)
    var i = 0
    while i < n {
      if data[start + i] == 0 { return i }
      i += 1
    }
    return nil
  }

  /// NUL-terminated string; nil under the conditions of ``cStringLength(_:maxLen:)``.
  func cString(_ off: UInt64, maxLen: Int = 4096) -> String? {
    guard let n = cStringLength(off, maxLen: maxLen) else { return nil }
    let start = data.startIndex + Int(base + off)
    return String(decoding: data[start..<start + n], as: UTF8.self)
  }

  /// Fixed-width name field (e.g. 16-byte segment names).
  func fixedString(_ off: UInt64, _ len: UInt64) throws -> String {
    let r = try sub(off, len)
    let start = data.startIndex + Int(r.base)
    let field = data[start..<start + Int(len)]
    return String(decoding: field.prefix { $0 != 0 }, as: UTF8.self)
  }
}
