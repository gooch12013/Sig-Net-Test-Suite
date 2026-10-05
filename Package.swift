// swift-tools-version:5.10
import Foundation
import PackageDescription

// SigNet (protocol core) and sig-net (CLI) build on macOS, Linux and Windows.
var targets: [Target] = [
    .target(name: "SigNet", dependencies: [.product(name: "Crypto", package: "swift-crypto")]),
    .executableTarget(name: "sig-net", dependencies: ["SigNet"]),
]

#if os(macOS)
// The app links the shared library in vendor/signet (populate it with
// scripts/build-signet.sh). Override with SIGNET_PREFIX=/path/to/install.
let prefix = ProcessInfo.processInfo.environment["SIGNET_PREFIX"]
    ?? URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .appendingPathComponent("vendor/signet").path

targets += [
    .systemLibrary(name: "CSignet", path: "Sources/CSignet"),
    .executableTarget(
        name: "SignetTestSuite",
        dependencies: ["SigNet", "CSignet"],
        resources: [.process("Resources")],
        swiftSettings: [.unsafeFlags(["-Xcc", "-I\(prefix)/include"])],
        linkerSettings: [.unsafeFlags(["-L\(prefix)/lib", "-Xlinker", "-rpath", "-Xlinker", "\(prefix)/lib"])]
    ),
]
#endif

let package = Package(
    name: "SignetTestSuite",
    platforms: [.macOS(.v13)],
    dependencies: [.package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0")],
    targets: targets
)
