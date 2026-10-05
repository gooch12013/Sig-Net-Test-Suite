// swift-tools-version:5.10
import Foundation
import PackageDescription

// Links the shared library in vendor/signet (populate it with
// scripts/build-signet.sh). Override with SIGNET_PREFIX=/path/to/install.
let prefix = ProcessInfo.processInfo.environment["SIGNET_PREFIX"]
    ?? URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .appendingPathComponent("vendor/signet").path

let package = Package(
    name: "SignetTestSuite",
    platforms: [.macOS(.v13)],
    targets: [
        .systemLibrary(name: "CSignet", path: "Sources/CSignet"),
        // E1.37-4 firmware upload controller (with FTC_FILELIST) + Responder emulator.
        .target(name: "CFTC", path: "Sources/CFTC"),
        .executableTarget(
            name: "SignetTestSuite",
            dependencies: ["CSignet", "CFTC"],
            resources: [.process("Resources")],
            swiftSettings: [.unsafeFlags(["-Xcc", "-I\(prefix)/include"])],
            linkerSettings: [.unsafeFlags(["-L\(prefix)/lib", "-Xlinker", "-rpath", "-Xlinker", "\(prefix)/lib"])]
        ),
    ]
)
