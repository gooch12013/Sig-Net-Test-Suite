import AppKit
import SigNet
import SwiftUI

// Before the globals below: a self-test or probe never touches the GUI roles' TUIDs.
if CommandLine.arguments.contains("--selftest") { exit(SelfTest.run(CommandLine.arguments)) }
if CommandLine.arguments.contains("--probe") { exit(ManagerEngine.probe(CommandLine.arguments)) }

let settings = SecuritySettings()
settings.interface = UserDefaults.standard.string(forKey: "interface") ?? "" // GUI only; selftest/probe start from the OS default
let transmitter = Transmitter(settings: settings)
let receiver = Receiver(settings: settings)
/// What RDM has learned about fixtures; Manager fills it, Transmit labels its faders from it.
let fixtureStore = FixtureStore()
// Snapshot runs get their own TUIDs so they never collide with a running GUI Manager or Device on the same node.
let snapshotRun = Snapshot.args.contains("--snapshot")
let fakeDevice = FakeDevice(settings: settings, tuid: Identity.tuid(snapshotRun ? "snapshot-device" : "device-v2"))
let manager = Manager(settings: settings, tuid: Identity.tuid(snapshotRun ? "snapshot" : "manager-v2"))

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_: Notification) {
        NSApp.setActivationPolicy(.regular) // SwiftPM executables start as background apps
        NSApp.activate(ignoringOtherApps: true)
        Snapshot.render = {
            AnyView(AppView(settings: settings, transmitter: transmitter, receiver: receiver, device: fakeDevice, manager: manager, fixtures: fixtureStore))
        }
        Snapshot.configure(settings: settings, manager: manager, device: fakeDevice, fixtures: fixtureStore)
    }
    func applicationShouldTerminateAfterLastWindowClosed(_: NSApplication) -> Bool { true }
    func applicationWillTerminate(_: Notification) {
        transmitter.stop()
        receiver.stop()
        fakeDevice.stop()
        manager.stop()
    }
}

struct SignetTestApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate

    var body: some Scene {
        WindowGroup("Sig-Net Test Suite") {
            AppView(settings: settings, transmitter: transmitter, receiver: receiver, device: fakeDevice, manager: manager, fixtures: fixtureStore)
        }
    }
}

SignetTestApp.main()
