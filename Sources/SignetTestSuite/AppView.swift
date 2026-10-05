import AppKit
import SwiftUI

extension Color {
    /// Sig-Net green/blue #065A60 (style guide), lightened in Dark Mode so
    /// tinted controls keep their contrast.
    static let sigNet = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            ? NSColor(srgbRed: 0x3F / 255, green: 0xA7 / 255, blue: 0xAE / 255, alpha: 1)
            : NSColor(srgbRed: 0x06 / 255, green: 0x5A / 255, blue: 0x60 / 255, alpha: 1)
    })
}

struct AppView: View {
    @ObservedObject var settings: SecuritySettings
    let transmitter: Transmitter
    let receiver: Receiver
    let device: FakeDevice
    let manager: Manager
    @State private var tab = Snapshot.launchTab

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                // Fixed height, aspect kept: the style guide forbids stretching the logo.
                Image(nsImage: NSImage(contentsOf: Bundle.module.url(forResource: "SigNetLogo", withExtension: "png")!)!)
                    .resizable()
                    .aspectRatio(contentMode: .fit)
                    .frame(height: 30)
                    .accessibilityLabel("Sig-Net")
                Text("Test Suite").font(.title2.weight(.semibold))
                Spacer(minLength: 24)
                SecurityPanel(settings: settings)
            }
            .padding()
            Divider()
            TabView(selection: $tab) {
                TransmitView(tx: transmitter).tabItem { Text("Transmit") }.tag("transmit")
                ReceiveView(rx: receiver).tabItem { Text("Receive") }.tag("receive")
                DeviceView(device: device).tabItem { Text("Device") }.tag("device")
                ManagerView(manager: manager).tabItem { Text("Manager") }.tag("manager")
            }
            .padding()
        }
        .frame(minWidth: 760, minHeight: 640)
        .tint(.sigNet)
    }
}

/// Mode, passphrase and scope shared by every device the app creates.
struct SecurityPanel: View {
    @ObservedObject var settings: SecuritySettings

    var body: some View {
        HStack(spacing: 10) {
            Picker("Security", selection: $settings.mode) {
                ForEach(SecurityMode.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented).labelsHidden().fixedSize()
            .help("Security mode for every device the app creates")
            if settings.mode == .secure {
                SecureField("Passphrase", text: $settings.passphrase).frame(minWidth: 160, maxWidth: 240)
                    .help(settings.passphraseProblem ?? "Passphrase OK")
                Image(systemName: settings.passphraseProblem == nil ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                    .foregroundStyle(settings.passphraseProblem == nil ? .green : .orange)
                    .help(settings.passphraseProblem ?? "Passphrase OK")
                    .accessibilityLabel(settings.passphraseProblem ?? "Passphrase OK")
            }
            TextField("Scope", text: $settings.scope).frame(width: 110).help("Scope (local if empty)")
            if settings.locked {
                Image(systemName: "lock.fill").foregroundStyle(.secondary)
                    .help("Stop every running device to change security settings")
                    .accessibilityLabel("Locked while devices are running")
            }
        }
        .disabled(settings.locked)
    }
}
