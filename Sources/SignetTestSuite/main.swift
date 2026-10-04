import AppKit
import SwiftUI

let settings = SecuritySettings()
let transmitter = Transmitter(settings: settings)
let receiver = Receiver(settings: settings)
let fakeDevice = FakeDevice(settings: settings)
let manager = Manager(settings: settings)

/// `swift run SignetTestSuite --selftest`: exercises every part without the
/// UI, in both security modes. Exit status 0 = all passed.
func selfTest() -> Int32 {
    var failed = false
    func report(_ label: String, _ ok: Bool, _ detail: String = "") {
        print("\(ok ? "PASS" : "FAIL") \(label)\(detail.isEmpty ? "" : ": \(detail)")")
        failed = failed || !ok
    }
    report("timecode counter", Transmitter.selfTestTimecode())
    for mode in SecurityMode.allCases {
        let s = SecuritySettings()
        s.mode = mode
        s.passphrase = "Sig-Net-Test-9"
        let tag = mode.rawValue.lowercased()

        for run in 1...2 { // second Secure run reloads the saved session record
            let tx = Transmitter(settings: s)
            tx.start()
            tx.setAll(128)
            RunLoop.main.run(until: Date().addingTimeInterval(1))
            report("transmit \(tag) #\(run)", tx.running && tx.sendFailures == 0, tx.status)
            tx.stop()
        }
        report("receive \(tag)", Receiver.selfTest(settings: s))
        report("device \(tag)", FakeDevice.selfTest(settings: s))
        report("manager \(tag)", Manager.selfTest(settings: s))
        for (l, ok, d) in LoopbackTests.run(settings: s) { report("\(l) \(tag)", ok, d) }
    }
    return failed ? 1 : 0
}

if CommandLine.arguments.contains("--selftest") { exit(selfTest()) }

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_: Notification) {
        NSApp.setActivationPolicy(.regular) // SwiftPM executables start as background apps
        NSApp.activate(ignoringOtherApps: true)
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
            AppView(settings: settings, transmitter: transmitter, receiver: receiver, device: fakeDevice, manager: manager)
        }
    }
}

SignetTestApp.main()
