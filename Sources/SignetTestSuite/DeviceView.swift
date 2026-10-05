import Combine
import SigNet
import SwiftUI

/// The Swift Node (SigNet.DeviceEngine), observable for SwiftUI.
final class FakeDevice: DeviceEngine, ObservableObject {
    let objectWillChange = ObservableObjectPublisher()
    override func willChange() { objectWillChange.send() }
    var securitySettings: SecuritySettings { settings as! SecuritySettings } // the app only makes devices with these
}

// MARK: - View

/// Device: a fake fixture that external Managers find and configure, drawn as one instrument.
/// Main panel uses plain names; parameter codes and hex stay in Debug with the handler log.
struct DeviceView: View {
    @ObservedObject var device: FakeDevice
    @ObservedObject private var settings: SecuritySettings
    @State private var mode = "panel"

    init(device: FakeDevice) {
        self.device = device
        settings = device.securitySettings
    }

    /// Ports on the display: the live ones while running, the configured count while stopped.
    private var portCount: Int { device.running ? device.live.count : min(8, max(1, device.endpointCount)) }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            controlStrip
            display
            HStack {
                ModeKeys(options: [("panel", "Panel"), ("debug", "Debug")], selection: $mode)
                Spacer()
            }
            ScrollView {
                Group {
                    if mode == "debug" { debug } else { panel }
                }
                .padding(.bottom, 12)
            }
        }
    }

    // MARK: Control strip and display

    private var statusText: String {
        guard device.running else { return device.status }
        let n = device.live.count
        return "Running · \(n) port\(n == 1 ? "" : "s") · \(settings.mode.rawValue) Mode · scope \(settings.scopeOrDefault)"
    }

    private var controlStrip: some View {
        HStack(spacing: 10) {
            if device.running {
                Button("Stop") { device.stop() }
                    .buttonStyle(SoftKeyStyle(lamp: .lampOnline))
                    .keyboardShortcut(.return, modifiers: .command)
            } else {
                Button("Start device") { device.start() }
                    .buttonStyle(SoftKeyStyle(prominent: true))
                    .keyboardShortcut(.return, modifiers: .command)
                    .disabled(!settings.ready)
                    .help(settings.ready ? "Start answering Managers on the network" : "Fix the passphrase first")
            }
            Text(statusText)
                .font(.system(size: 11.5))
                .foregroundStyle(device.running || device.status == "Stopped" ? Color.silk : Color.lampFault)
                .lineLimit(1).truncationMode(.middle)
                .textSelection(.enabled)
            Spacer()
        }
    }

    private var display: some View {
        HStack(alignment: .center, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text(device.modelName.isEmpty ? "Unnamed model" : device.modelName)
                    .font(.system(size: 22, weight: .semibold)).foregroundStyle(Color.ink)
                Text(device.label.isEmpty ? "No label" : device.label)
                    .font(.system(size: 13, weight: .medium)).foregroundStyle(Color.inkDim)
                HStack(spacing: 6) {
                    Silkscreen("Device ID")
                    Text(Identity.hex(device.tuid)).font(.system(size: 11.5, design: .monospaced)).foregroundStyle(Color.silk)
                        .textSelection(.enabled)
                }
            }
            Spacer()
            VStack(spacing: 5) {
                Lamp(color: device.running ? .lampOnline : nil, size: 10)
                Silkscreen("Running")
            }
            .frame(minWidth: 52)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(device.running ? "Running" : "Stopped")
            portLamps
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
        .background(
            RoundedRectangle(cornerRadius: 7, style: .continuous).fill(Color.readoutWindow)
                .overlay(RoundedRectangle(cornerRadius: 7, style: .continuous).strokeBorder(Color.black.opacity(0.7), lineWidth: 1))
                .overlay(alignment: .bottom) { Rectangle().fill(Color.brandStripe).frame(height: 2).padding(.horizontal, 1) }
                .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
        )
    }

    /// Two rows of lamps, one column per port: levels arriving, and identify from a Manager.
    private var portLamps: some View {
        Grid(horizontalSpacing: 12, verticalSpacing: 6) {
            GridRow {
                Silkscreen("Port").gridColumnAlignment(.trailing)
                ForEach(0..<portCount, id: \.self) { i in
                    Text("\(i + 1)").font(.system(size: 10.5, weight: .semibold, design: .monospaced)).foregroundStyle(Color.silk)
                }
            }
            GridRow {
                Silkscreen("Levels")
                ForEach(0..<portCount, id: \.self) { i in
                    let on = receiving(i)
                    Lamp(color: on ? .lampOnline : nil, size: 10)
                        .accessibilityHidden(false)
                        .accessibilityLabel("Port \(i + 1) levels: \(on ? "receiving" : "none")")
                }
            }
            GridRow {
                Silkscreen("Identify")
                ForEach(0..<portCount, id: \.self) { i in
                    let on = identifying(i)
                    IdentifyLamp(on: on)
                        .accessibilityLabel("Port \(i + 1) identify: \(on ? "on" : "off")")
                }
            }
        }
    }

    private func receiving(_ i: Int) -> Bool { device.live.indices.contains(i) && device.live[i].sources > 0 }
    private func identifying(_ i: Int) -> Bool { device.identifying.indices.contains(i) && device.identifying[i] }

    // MARK: Panel

    private var panel: some View {
        VStack(alignment: .leading, spacing: 12) {
            identity
            ports
            behaviour
        }
    }

    private var identity: some View {
        ModulePanel("Identity") {
            Button("Notify change") { device.notifyLabelChange() }
                .buttonStyle(.softKey)
                .disabled(!device.running)
                .help("Tell Managers the label changed so they read it again")
        } content: {
            ReadoutRow(label: "Model name", value: device.modelName.isEmpty ? nil : device.modelName,
                       set: .text(initial: device.modelName) { text, done in
                           guard !text.isEmpty else { return done(.refused("The model name can't be empty")) }
                           device.modelName = text
                           done(.latched)
                       },
                       enabled: !device.running)
            ReadoutRow(label: "Label", value: device.label.isEmpty ? nil : device.label,
                       set: .text(initial: device.label) { text, done in
                           guard device.running else { device.label = text; return done(.latched) }
                           guard !text.isEmpty else { return done(.refused("The label can't be empty while running")) }
                           device.label = text
                           done(device.applyLabel() ? .latched : .refused("The device refused this label"))
                       })
            ReadoutRow(label: "Firmware", value: device.firmwareLabel.isEmpty ? nil : device.firmwareLabel,
                       set: .text(initial: device.firmwareLabel) { text, done in
                           device.firmwareLabel = text
                           done(.latched)
                       },
                       enabled: !device.running)
            if device.running {
                note("Model name and firmware are fixed while running. Stop the device to change them.")
            }
        }
    }

    private var ports: some View {
        ModulePanel("Ports") {
            ReadoutRow(label: "Port count", value: "\(portCount)",
                       set: .choices((1...8).map(String.init)) { i, done in
                           device.endpointCount = i + 1
                           done(.latched)
                       },
                       enabled: !device.running)
            ForEach(0..<portCount, id: \.self) { i in
                Divider().overlay(Color.black.opacity(0.4)).padding(.vertical, 2)
                ReadoutRow(label: "Port \(i + 1) universe", value: "\(device.universes[i])",
                           set: .number(initial: "\(device.universes[i])", range: 1...63999) { text, done in
                               guard let u = Int(text.trimmingCharacters(in: .whitespaces)), (1...63999).contains(u)
                               else { return done(.refused("A universe is a number from 1 to 63999")) }
                               device.universes[i] = u
                               done(.latched)
                           },
                           enabled: !device.running)
                levelsRow(i)
            }
        }
    }

    private func levelsRow(_ i: Int) -> some View {
        let live = device.live.indices.contains(i) ? device.live[i] : nil
        return HStack(spacing: 8) {
            Text("Port \(i + 1) levels")
                .font(.system(size: 12.5, weight: .medium)).foregroundStyle(Color.inkDim)
                .frame(width: ReadoutRow.labelWidth, alignment: .leading)
            LevelStrip(levels: live?.levels ?? [])
                .accessibilityLabel("Port \(i + 1) levels, first 32 channels")
            VStack(alignment: .leading, spacing: 3) {
                miniReadout("Channels", live.map { "\($0.slots)" })
                miniReadout("Sources", live.map { "\($0.sources)" })
            }
            .frame(width: ReadoutRow.keyWidth * 2 + 8)
        }
        .frame(maxWidth: 860, alignment: .leading)
    }

    private func miniReadout(_ title: String, _ value: String?) -> some View {
        HStack(spacing: 4) {
            Silkscreen(title)
            Spacer(minLength: 2)
            Text(value ?? "—").font(.system(size: 12, weight: .medium, design: .monospaced))
                .foregroundStyle(value == nil ? Color.silk : Color.ink)
        }
        .accessibilityElement(children: .combine)
    }

    private var behaviour: some View {
        ModulePanel("Behaviour") {
            ReadoutRow(label: "Simulate fresh power-on", value: device.freshPowerOn ? "On" : "Off",
                       set: .choices(["Off", "On"]) { i, done in device.freshPowerOn = i == 1; done(.latched) },
                       enabled: !device.running)
            note("On: a Manager can offboard the device for 300 s after start, as after a real power-on.")
            ReadoutRow(label: "Accept network changes", value: device.acceptNetwork ? "On" : "Off",
                       set: .choices(["Off", "On"]) { i, done in device.acceptNetwork = i == 1; done(.latched) },
                       enabled: !device.running)
            note("On: address changes from a Manager are accepted and logged. This Mac's network is never touched.")
        }
    }

    private func note(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 11)).foregroundStyle(Color.silk)
            .padding(.leading, ReadoutRow.labelWidth + 8)
            .fixedSize(horizontal: false, vertical: true)
    }

    // MARK: Debug

    private var debug: some View {
        ModulePanel("Handler log") {
            Text("\(device.log.count)").font(.system(size: 11, design: .monospaced)).foregroundStyle(Color.silk)
            Button("Clear") { device.clearLog() }.buttonStyle(.softKey).disabled(device.log.isEmpty)
        } content: {
            if device.log.isEmpty {
                Text("No handler calls yet. Start the device and point a Manager at it.")
                    .font(.system(size: 12)).foregroundStyle(Color.silk)
            }
            LazyVStack(alignment: .leading, spacing: 2) {
                ForEach(Array(device.log.reversed().enumerated()), id: \.offset) { _, line in
                    Text(line).font(.system(size: 11, design: .monospaced)).foregroundStyle(Color.inkDim)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .accessibilityLabel("Handler log, newest first")
        }
    }
}

/// First 32 channels as teal bars in a recessed window.
private struct LevelStrip: View {
    let levels: [UInt8]

    var body: some View {
        HStack(alignment: .bottom, spacing: 2) {
            ForEach(0..<32, id: \.self) { i in
                let v = i < levels.count ? levels[i] : 0
                Rectangle()
                    .fill(v == 0 ? Color.silk.opacity(0.18) : Color.lampLatch)
                    .frame(maxWidth: .infinity)
                    .frame(height: max(1, 26 * CGFloat(v) / 255))
            }
        }
        .frame(height: 26, alignment: .bottom)
        .padding(.horizontal, 8).padding(.vertical, 5)
        .frame(maxWidth: .infinity)
        .background(
            RoundedRectangle(cornerRadius: 4, style: .continuous).fill(Color.readoutWindow)
                .overlay(RoundedRectangle(cornerRadius: 4, style: .continuous).strokeBorder(Color.black.opacity(0.7), lineWidth: 1))
                .shadow(color: .white.opacity(0.05), radius: 0, y: 1)
        )
        .accessibilityElement()
        .accessibilityValue(levels.isEmpty ? "no levels" : levels.map(String.init).joined(separator: ", "))
    }
}

/// Blinks teal while a Manager has identify on; holds steady under reduced motion.
private struct IdentifyLamp: View {
    let on: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Group {
            if on && !reduceMotion {
                TimelineView(.periodic(from: .now, by: 0.4)) { context in
                    let lit = Int(context.date.timeIntervalSinceReferenceDate / 0.4) % 2 == 0
                    Lamp(color: lit ? .lampLatch : nil, size: 10)
                }
            } else {
                Lamp(color: on ? .lampLatch : nil, size: 10)
            }
        }
        .accessibilityElement()
    }
}
