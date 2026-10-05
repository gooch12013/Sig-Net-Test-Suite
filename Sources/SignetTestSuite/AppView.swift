import AppKit
import SigNet
import SwiftUI

extension Color {
    /// Sig-Net teal for live values on the faceplate (the brand #065A60, lifted for contrast on graphite).
    static let sigNet = Color.lampLatch
}

/// The instrument: a top strip with the brand and security controls, role keys, then the active role's panel.
struct AppView: View {
    @ObservedObject var settings: SecuritySettings
    @ObservedObject var transmitter: Transmitter
    @ObservedObject var receiver: Receiver
    @ObservedObject var device: FakeDevice
    @ObservedObject var manager: Manager
    let fixtures: FixtureStore
    @State private var tab = Snapshot.launchTab
    @StateObject private var entry = NumberEntry()

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            topStrip
            HStack {
                ModeKeys(options: [("transmit", "Transmit"), ("receive", "Receive"), ("device", "Device"), ("manager", "Manager")],
                         selection: $tab, lit: running)
                Spacer()
            }
            .padding(.horizontal, 16).padding(.top, 14).padding(.bottom, 4)
            HStack(alignment: .top, spacing: 12) {
            Group {
                switch tab {
                case "receive": ReceiveView(rx: receiver).environment(\.readoutKeyColumns, 1)
                case "device": DeviceView(device: device).environment(\.readoutKeyColumns, 1)
                case "manager": ManagerView(manager: manager, fixtures: fixtures)
                default: TransmitView(tx: transmitter, fixtures: fixtures).environment(\.readoutKeyColumns, 1)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                KeypadPanel().frame(width: 252)
            }
            .padding(16)
            .onChange(of: tab) { _ in entry.cancel() }
            .onAppear {
                // Snapshot aid: --switch-to <tab> --switch-after <s> (e.g. let RDM load on Manager, then show Transmit).
                if let t = Snapshot.arg("--switch-to") {
                    DispatchQueue.main.asyncAfter(deadline: .now() + (Double(Snapshot.arg("--switch-after") ?? "20") ?? 20)) { tab = t }
                }
            }
        }
        .environmentObject(entry)
        .frame(minWidth: 980, minHeight: 680)
        .faceplate()
    }

    /// A role key's lamp shows that role is running.
    private func running(_ role: String) -> Color? {
        switch role {
        case "transmit": return transmitter.running ? .lampOnline : nil
        case "receive": return receiver.running ? .lampOnline : nil
        case "device": return device.running ? .lampOnline : nil
        case "manager": return manager.running ? .lampOnline : nil
        default: return nil
        }
    }

    private var topStrip: some View {
        HStack(spacing: 12) {
            // Fixed height, aspect kept: the style guide forbids stretching the logo.
            // Bundle.main first: in the packaged .app the logo sits in Contents/Resources (see scripts/make-app.sh).
            Image(nsImage: NSImage(contentsOf: (Bundle.main.url(forResource: "SigNetLogo", withExtension: "png")
                ?? Bundle.module.url(forResource: "SigNetLogo", withExtension: "png"))!)!)
                .resizable()
                .aspectRatio(contentMode: .fit)
                .frame(height: 28)
                .accessibilityLabel("Sig-Net")
            Text("Test Suite").font(.system(size: 17, weight: .semibold)).foregroundStyle(Color.ink)
            Spacer(minLength: 24)
            SecurityPanel(settings: settings)
        }
        .padding(.horizontal, 16).padding(.vertical, 10)
        .background(Color.module)
        .overlay(alignment: .bottom) { Rectangle().fill(Color.brandStripe).frame(height: 2) }
    }
}

/// Mode, passphrase and scope shared by every device the app creates; locked while any device runs.
struct SecurityPanel: View {
    @ObservedObject var settings: SecuritySettings

    var body: some View {
        HStack(spacing: 10) {
            ModeKeys(options: SecurityMode.allCases.map { ($0, $0.rawValue) }, selection: $settings.mode)
                .help("Security mode for every device the app creates")
            if settings.mode == .secure {
                ReadoutWindow(signal: settings.passphraseProblem == nil ? .idle : .refused("")) {
                    SecureField("Passphrase", text: $settings.passphrase)
                        .textFieldStyle(.plain).font(.system(size: 13, design: .monospaced)).foregroundStyle(Color.ink)
                }
                .frame(width: 220)
                .help(settings.passphraseProblem ?? "Passphrase OK")
                Lamp(color: settings.passphraseProblem == nil ? .lampOnline : .lampFault)
                    .help(settings.passphraseProblem ?? "Passphrase OK")
                    .accessibilityLabel(settings.passphraseProblem ?? "Passphrase OK")
            }
            Silkscreen("Scope")
            ReadoutWindow {
                TextField("local", text: $settings.scope)
                    .textFieldStyle(.plain).font(.system(size: 13, design: .monospaced)).foregroundStyle(Color.ink)
            }
            .frame(width: 110)
            Silkscreen("NIC")
            InterfaceMenu(settings: settings)
                .onChange(of: settings.interface) { UserDefaults.standard.set($0, forKey: "interface") }
            if settings.locked {
                Image(systemName: "lock.fill").foregroundStyle(Color.silk)
                    .help("Stop every running device to change security settings")
                    .accessibilityLabel("Locked while devices are running")
            }
        }
        .disabled(settings.locked)
    }
}
