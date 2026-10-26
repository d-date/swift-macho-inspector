# MachOInspector

A small, pure-Swift, read-only parser for Mach-O and FAT (universal) binaries.
Foundation only; builds and tests on macOS and Linux.

## What it parses

- Thin Mach-O (32/64-bit, little/big-endian) and FAT32 / FAT64 containers
- Header fields and flags (PIE, stack/heap execution), architecture names
- Load commands, segments and sections, linked dylibs, rpaths, UUID
- Build version / minimum OS (`LC_BUILD_VERSION`, `LC_VERSION_MIN_*`)
- FairPlay encryption info and the absolute encrypted file ranges
- Symbol table (`nlist`), imported symbols, debug (stab) symbols
- Code signature structure: SuperBlob, CodeDirectory (team ID, hash type,
  flags), entitlements (XML and DER), requirements and CMS blob presence

## Installation

```swift
dependencies: [
  .package(url: "https://github.com/d-date/swift-macho-inspector.git", from: "0.1.0")
],
targets: [
  .target(name: "YourTarget", dependencies: [
    .product(name: "MachOInspector", package: "swift-macho-inspector")
  ])
]
```

Platforms: macOS 13+ and Linux (Swift 6 toolchain). Pure Foundation, no other dependencies.

## Usage

```swift
import Foundation
import MachOInspector

let url = URL(fileURLWithPath: "/path/to/binary")
let file = try MachOFile(data: try Data(contentsOf: url))
for slice in file.slices {
  print(slice.architecture, slice.isPIE, slice.isEncrypted)
  for warning in slice.parseWarnings { print("warning:", warning) }
}
```

`MachOFile.isMachO(_:)` is a cheap magic-number sniff for deciding whether to parse at all.

## Safety guarantees

Input is treated as untrusted. Every read is bounds-checked against the
containing slice or command, malformed input throws `MachOError` (or adds an
entry to `parseWarnings` when the rest of the file is still usable), and
loops and allocations are capped (10,000 load commands, 64 FAT architectures,
4,000,000 symbols per slice, one 256 MiB estimated symbol-memory bound shared by all slices of a file, bounded string reads). Nothing is ever executed.

## Limitations

- Only the first `LC_SYMTAB` and the first `LC_CODE_SIGNATURE` are parsed (as dyld does);
  repeats produce a warning. At most 6 CodeDirectories are read.
- Symbols: at most 4,000,000 `nlist` entries per slice. One aggregate budget of 256 MiB
  (`MachOFile.maxSymbolMemory`) covers symbol entries (with array growth slack), decoded name
  bytes and name-cache storage across *all* slices of a file, and is checked before each
  allocation; once it is used up decoding stops with a warning, so a FAT file cannot multiply it.
  Empty names are never cached and the name cache holds at most 1,048,576 entries. `N_OPT` stabs
  are not counted as debug info.
- C strings (symbol names, dylib paths, rpaths, signing identifiers) need a NUL inside their
  window and at most 4096 bytes. Otherwise nothing is truncated or guessed: the symbol name is
  left empty (counted in one aggregated warning) or the dylib/rpath/identifier is skipped with a
  parse warning. Fixed-width segment/section names are unaffected.
- `importedSymbols` lists undefined external symbols with `n_value == 0`. `Symbol.isUndefined` is
  the raw `N_UNDF` test and also matches common symbols (`N_UNDF | N_EXT`, `n_value != 0`), which
  are exposed via `Symbol.isCommon` and are not imports.
- Encryption: an `LC_ENCRYPTION_INFO(_64)` range must lie inside its slice. Otherwise the record
  keeps its raw values with `isWithinSlice == false`, a parse warning is added, and the range is
  left out of `encryptedFileRanges` (so it can never cover a neighbouring FAT slice).
  `isEncrypted` stays `true` when `cryptid != 0` (fail safe); check `hasInvalidEncryptionRange`
  and treat the encrypted extent as unknown.
- Code signatures: duplicate SuperBlob slot types, blobs that start inside the index table and
  overlapping blobs make the signature unparsable (`codeSignature == nil` plus a warning).
  `CodeDirectory.codeLimit` is `codeLimit64` when non-zero (version 0x20300+), else `codeLimit`.
- FAT files with overlapping slices are rejected.
- Values such as segment and section offsets are reported as declared, not cross-validated.
- Everything is read eagerly from an in-memory `Data`; very large files need to fit in memory.

## Test support

The separate `MachOFixtures` product builds synthetic (including malformed) Mach-O images for
tests. It is test support only and is not covered by semantic-versioning guarantees.

## Non-goals

- No cryptographic verification of code signatures (no CMS/hash checking)
- No disassembly, no dyld info / chained fixups decoding

## License

MIT
