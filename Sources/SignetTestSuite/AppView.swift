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
            }
            .padding([.horizontal, .top])
            SecurityPanel(settings: settings).padding()
            Divider()
            TabView {
                TransmitView(tx: transmitter).tabItem { Text("Transmit") }
                ReceiveView(rx: receiver).tabItem { Text("Receive") }
                DeviceView(device: device).tabItem { Text("Device") }
                ManagerView(manager: manager).tabItem { Text("Manager") }
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
        Form {
            Picker("Security", selection: $settings.mode) {
                ForEach(SecurityMode.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            if settings.mode == .secure {
                SecureField("Passphrase", text: $settings.passphrase)
                if let problem = settings.passphraseProblem {
                    Text(problem).font(.caption).foregroundStyle(.orange)
                } else {
                    Text("Passphrase OK").font(.caption).foregroundStyle(.green)
                }
            }
            TextField("Scope", text: $settings.scope)
            if settings.locked {
                Text("Stop every running device to change security settings.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .disabled(settings.locked)
    }
}
