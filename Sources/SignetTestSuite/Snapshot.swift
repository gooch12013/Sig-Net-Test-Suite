import AppKit
import SwiftUI

/// Developer aid for looking at the UI without Screen Recording permission:
///   SignetTestSuite --tab manager --passphrase <p> --interface <ip> --start-manager --snapshot out.png [--after 6]
/// sets up the app, waits, writes the window to a PNG and quits.
enum Snapshot {
    static let args = CommandLine.arguments
    static func arg(_ name: String) -> String? { args.firstIndex(of: name).flatMap { $0 + 1 < args.count ? args[$0 + 1] : nil } }

    /// Tab to open on launch (transmit, receive, device, manager).
    static var launchTab: String { arg("--tab") ?? "transmit" }

    /// The view to render; set by main.swift.
    static var render: () -> AnyView = { AnyView(EmptyView()) }

    static func configure(settings: SecuritySettings, manager: Manager, fixtures: FixtureStore) {
        if args.contains("--demo-channels") {
            // Synthetic fixture for checking the Transmit channel headings in a snapshot; never used by the app itself.
            var f = FixtureStore.Fixture()
            f.universe = 1
            f.values[0x00F0] = [0, 3]
            for (i, name) in ["Dimmer", "Red", "Green", "Blue", "White", "Strobe", "Program", "Program speed"].enumerated() { f.channels[UInt16(i)] = name }
            fixtures.byUID["DEMO00000001"] = f
        }
        if let p = arg("--passphrase") { settings.mode = .secure; settings.passphrase = p }
        if let s = arg("--scope") { settings.scope = s }
        if let i = arg("--interface") { settings.interface = i }
        if args.contains("--start-manager") { DispatchQueue.main.async { manager.start() } }
        guard let path = arg("--snapshot") else { return }
        let delay = Double(arg("--after") ?? "6") ?? 6
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
            // Render in an off-screen window: works even where the app's own window never appears.
            let size = NSSize(width: Double(arg("--width") ?? "1280") ?? 1280, height: Double(arg("--height") ?? "900") ?? 900)
            let window = NSWindow(contentRect: NSRect(origin: NSPoint(x: -10_000, y: -10_000), size: size),
                                  styleMask: [.titled], backing: .buffered, defer: false)
            window.contentView = NSHostingView(rootView: render().background(Color(nsColor: .windowBackgroundColor)))
            window.orderFrontRegardless()
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                guard let view = window.contentView, let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else {
                    print("snapshot: no bitmap"); exit(1)
                }
                view.cacheDisplay(in: view.bounds, to: rep)
                do { try rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: path)) } catch {
                    print("snapshot: \(error)")
                }
                manager.stop()
                exit(0)
            }
        }
    }
}
