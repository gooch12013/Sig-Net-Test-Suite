import SwiftUI

struct AppView: View {
    @ObservedObject var settings: SecuritySettings
    let transmitter: Transmitter
    let receiver: Receiver
    let device: FakeDevice
    let manager: Manager

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
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
