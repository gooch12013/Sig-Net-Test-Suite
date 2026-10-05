// swift-tools-version:5.10
import PackageDescription

// SigNet (protocol core) and sig-net (CLI) build on macOS, Linux and Windows; the SwiftUI app is macOS-only.
var targets: [Target] = [
    .target(name: "SigNet", dependencies: [.product(name: "Crypto", package: "swift-crypto")]),
    .executableTarget(name: "sig-net", dependencies: ["SigNet"]),
]

#if os(macOS)
targets.append(.executableTarget(name: "SignetTestSuite", dependencies: ["SigNet"], resources: [.process("Resources")]))
#endif

let package = Package(
    name: "SignetTestSuite",
    platforms: [.macOS(.v13)],
    dependencies: [.package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0")],
    targets: targets
)
