// swift-tools-version:6.2
import PackageDescription

let package = Package(
    name: "Clauduo",
    platforms: [.macOS(.v26)],
    targets: [.executableTarget(name: "Clauduo", path: "Sources/Clauduo", swiftSettings: [.swiftLanguageMode(.v5)])]
)
