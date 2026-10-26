import Foundation

/// A parsed Mach-O file: either a single thin image or a FAT (universal) container.
///
/// Parsing is eager and treats `data` as untrusted: all reads are bounds-checked, malformed
/// input throws ``MachOError`` and nothing is executed or mapped.
public struct MachOFile: Sendable, Hashable {
  /// True if the file was a FAT container (even with a single architecture).
  public let isFat: Bool
  /// One slice for a thin file, otherwise one per FAT architecture, in file order.
  public let slices: [MachOSlice]

  /// Maximum FAT architecture count accepted; a larger or zero count throws ``MachOError/malformed(_:)``.
  public static let maxFatArchitectures: UInt32 = 64

  /// Estimated symbol-table memory bound for the whole file, shared by all slices: symbol
  /// entries (including array growth slack), decoded name bytes and name-cache storage.
  /// Slices parsed after it is used up get fewer (possibly zero) symbols and a warning.
  public static let maxSymbolMemory = 256 << 20

  /// Parses a thin Mach-O or FAT32/FAT64 file.
  ///
  /// FAT slices must lie inside the file and must not overlap each other, so no region is parsed
  /// more than once. Throws ``MachOError`` for unrecoverable problems; recoverable ones end up in
  /// each slice's ``MachOSlice/parseWarnings``.
  public init(data: Data) throws {
    try self.init(data: data, limits: SymbolLimits())
  }

  init(data: Data, limits: SymbolLimits) throws {
    let budget = SymbolBudget(limit: limits.maxSymbolMemory)
    let file = Reader(data: data, bigEndian: true)
    guard file.size >= 4 else { throw MachOError.truncated("file shorter than magic") }
    let magic = try file.u32(0)
    guard magic == MachOMagic.fat32 || magic == MachOMagic.fat64 else {
      isFat = false
      slices = [
        try MachOSliceParser.parse(
          file: file, fileOffset: 0, size: file.size, limits: limits, budget: budget)
      ]
      return
    }
    let is64 = magic == MachOMagic.fat64
    let count = try file.u32(4)
    guard count > 0, count <= Self.maxFatArchitectures else {
      throw MachOError.malformed("invalid fat arch count \(count)")
    }
    let entrySize: UInt64 = is64 ? 32 : 20
    var result: [MachOSlice] = []
    var ranges: [Range<UInt64>] = []
    for i in 0..<UInt64(count) {
      let e = 8 + i * entrySize
      let offset = is64 ? try file.u64(e + 8) : UInt64(try file.u32(e + 8))
      let size = is64 ? try file.u64(e + 16) : UInt64(try file.u32(e + 12))
      guard offset <= file.size, size <= file.size - offset else {
        throw MachOError.truncated("fat slice \(i) exceeds file")
      }
      // Overlapping slices would let one region be parsed up to 64 times.
      guard !ranges.contains(where: { $0.overlaps(offset..<offset + size) }) else {
        throw MachOError.malformed("fat slice \(i) overlaps another slice")
      }
      ranges.append(offset..<offset + size)
      result.append(
        try MachOSliceParser.parse(
          file: file, fileOffset: offset, size: size, limits: limits, budget: budget))
    }
    isFat = true
    slices = result
  }

  /// Cheap magic-number sniff (thin or FAT, either byte order); does not validate the rest.
  public static func isMachO(_ data: Data) -> Bool {
    guard let m = try? Reader(data: data, bigEndian: true).u32(0) else { return false }
    return [
      MachOMagic.thin32, MachOMagic.thin64, MachOMagic.thin32Swapped, MachOMagic.thin64Swapped,
      MachOMagic.fat32, MachOMagic.fat64,
    ].contains(m)
  }
}
