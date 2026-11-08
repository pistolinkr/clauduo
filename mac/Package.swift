// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "Clauduo",
    platforms: [.macOS(.v13)],
    targets: [.executableTarget(name: "Clauduo", path: "Sources/Clauduo")]
)
