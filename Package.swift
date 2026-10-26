// swift-tools-version: 6.0
import PackageDescription

let package = Package(
  name: "MachOInspector",
  platforms: [.macOS(.v13)],
  products: [
    .library(name: "MachOInspector", targets: ["MachOInspector"]),
    .library(name: "MachOFixtures", targets: ["MachOFixtures"]),
  ],
  targets: [
    .target(name: "MachOInspector"),
    .target(name: "MachOFixtures"),
    .testTarget(name: "MachOInspectorTests", dependencies: ["MachOInspector", "MachOFixtures"]),
  ]
)
