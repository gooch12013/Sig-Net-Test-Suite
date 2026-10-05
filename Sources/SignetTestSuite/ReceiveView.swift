import Combine
import Foundation
import SigNet
import SwiftUI

/// SigNet's ReceiverEngine (a data-plane-only Node), observable for SwiftUI.
final class Receiver: ReceiverEngine, ObservableObject {
    let objectWillChange = ObservableObjectPublisher()
    override func willChange() { objectWillChange.send() }
    var securitySettings: SecuritySettings { settings as! SecuritySettings } // the app only makes Receivers with these
}

private func parseList(_ text: String, max: UInt16, what: String) throws -> [UInt16] {
    try ReceiverEngine.parseList(text, max: max, what: what)
}

// MARK: - View

/// Receive as one instrument: a control strip, the local settings, then Monitor, Timecode & preview, or Debug.
/// Hex, drop reasons and the receiver log live only in Debug.
struct ReceiveView: View {
    @ObservedObject var rx: Receiver
    @ObservedObject private var settings: SecuritySettings
    @State private var mode = Snapshot.arg("--receive-tab") ?? "monitor"

    init(rx: Receiver) {
        self.rx = rx
        settings = rx.securitySettings
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            controlStrip
            HStack {
                ModeKeys(options: [("monitor", "Monitor"), ("timecode", "Timecode & preview"), ("debug", "Debug")], selection: $mode)
                Spacer()
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    switch mode {
                    case "timecode": ReceiveTimecode(rx: rx); ReceivePreview(rx: rx)
                    case "debug": ReceiveDebugView(rx: rx)
                    default: settingsModule; ReceiveMonitor(rx: rx)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    private var controlStrip: some View {
        HStack(spacing: 10) {
            if rx.running {
                Button("Stop") { rx.stop() }.buttonStyle(SoftKeyStyle(lamp: .lampOnline))
            } else {
                Button("Start receiving") { rx.start() }
                    .buttonStyle(SoftKeyStyle(prominent: true))
                    .disabled(!settings.ready)
            }
            // Not running and not "Stopped" means start failed; the status holds the reason.
            let failed = !rx.running && rx.status != "Stopped"
            if failed { Lamp(color: .lampFault) }
            Text(rx.running || failed ? rx.status : settings.ready ? "Stopped. Set the universes below, then Start." : "Stopped. Fix the security settings above to start.")
                .font(.system(size: 11.5))
                .foregroundStyle(failed ? Color.lampFault : Color.silk)
                .lineLimit(1).truncationMode(.middle)
            Spacer()
        }
    }

    private var settingsModule: some View {
        ModulePanel("Settings") {
            if rx.running { Silkscreen("Locked while receiving") }
        } content: {
            ReadoutRow(label: "Universes", value: rx.universesText.isEmpty ? nil : rx.universesText,
                       set: .text(initial: rx.universesText) { t, done in
                           commitList(t, max: 63999, what: "universe", done) { rx.universesText = $0 } },
                       enabled: !rx.running)
            ReadoutRow(label: "Preview universes", value: rx.previewText.isEmpty ? "None" : rx.previewText,
                       set: .text(initial: rx.previewText) { t, done in
                           commitList(t, max: 63999, what: "preview universe", done) { rx.previewText = $0 } },
                       enabled: !rx.running)
            ReadoutRow(label: "Timecode streams", value: rx.timecodeText.isEmpty ? "None" : rx.timecodeText,
                       set: .text(initial: rx.timecodeText) { t, done in
                           commitList(t, max: 255, what: "timecode stream", done) { rx.timecodeText = $0 } },
                       enabled: !rx.running)
            ReadoutRow(label: "Sources per universe", value: "\(rx.sourcesPerUniverse)",
                       set: .number(initial: "\(rx.sourcesPerUniverse)", range: 1...64) { t, done in
                           guard let n = Int(t.trimmingCharacters(in: .whitespaces)), (1...64).contains(n) else { return done(.refused("Enter 1–64")) }
                           rx.sourcesPerUniverse = n
                           done(.latched)
                       },
                       enabled: !rx.running)
        }
    }

    /// Checks a list locally before storing it, so a typo is refused here rather than at Start.
    private func commitList(_ text: String, max: UInt16, what: String, _ done: (Signal) -> Void, store: (String) -> Void) {
        do {
            _ = try parseList(text, max: max, what: what)
            store(text.trimmingCharacters(in: .whitespaces))
            done(.latched)
        } catch {
            done(.refused("\(error)"))
        }
    }
}

/// Live levels for one universe, with the frame's vital signs.
private struct ReceiveMonitor: View {
    @ObservedObject var rx: Receiver

    /// While stopped, the list that Start would use.
    private var universes: [UInt16] {
        rx.running || !rx.universes.isEmpty ? rx.universes : (try? parseList(rx.universesText, max: 63999, what: "")) ?? []
    }
    private var selection: Binding<UInt16> {
        Binding(get: { UInt16(clamping: rx.selected) }, set: { rx.selected = Int($0) })
    }

    var body: some View {
        let f = rx.frame
        ModulePanel("Monitor") {
            chooser
        } content: {
            HStack(spacing: 8) {
                vital("Channels driven", f.map { "\($0.slotCount)" })
                vital("Sources", f.map { "\($0.sourceCount)" })
                vital("Frame age", f.map { "\(max(0, (rx.nowNs - $0.publishedNs) / 1_000_000)) ms" })
                vital("Frame rate", f.map { _ in String(format: "%.1f fps", rx.fps) })
            }
            ZStack {
                LevelGrid(levels: f == nil ? Array(repeating: 0, count: 512) : rx.levels, numbers: f != nil, name: "Universe \(rx.selected) levels")
                    .opacity(f == nil ? 0.55 : 1)
                if f == nil {
                    Text(!rx.running ? "Stopped" : universes.contains(UInt16(clamping: rx.selected)) ? "Waiting for universe \(rx.selected)" : "Universe \(rx.selected) is not in the list")
                        .font(.system(size: 13, weight: .medium, design: .monospaced))
                        .foregroundStyle(Color.inkDim)
                        .padding(.horizontal, 12).padding(.vertical, 6)
                        .background(RoundedRectangle(cornerRadius: 4).fill(Color.readoutWindow.opacity(0.92)))
                }
            }
            .frame(height: 340)
        }
    }

    @ViewBuilder private var chooser: some View {
        HStack(spacing: 8) {
            Silkscreen("Universe")
            if universes.count > 1 && universes.count <= 8 {
                ModeKeys(options: universes.map { ($0, "\($0)") }, selection: selection)
            } else if universes.count > 8 {
                Menu {
                    ForEach(universes, id: \.self) { u in Button("Universe \(u)") { rx.selected = Int(u) } }
                } label: { Text("\(rx.selected)") }
                    .menuStyle(.borderlessButton).fixedSize()
                    .help("Choose the universe to show")
            } else {
                Text("\(rx.selected)").font(.system(size: 13, weight: .semibold, design: .monospaced)).foregroundStyle(Color.ink)
            }
        }
    }

    private func vital(_ label: String, _ value: String?) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Silkscreen(label)
            ReadoutWindow {
                Text(value ?? "—")
                    .font(.system(size: 18, weight: .medium, design: .monospaced)).monospacedDigit()
                    .foregroundStyle(value == nil ? Color.silk : Color.ink)
                    .padding(.vertical, 4)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(label)
        .accessibilityValue(value ?? "no value")
    }
}

/// Each timecode stream as a large display with its rate and a running/lost lamp.
private struct ReceiveTimecode: View {
    @ObservedObject var rx: Receiver

    private var streams: [UInt16] {
        let live = rx.timecodes.keys.sorted()
        if !live.isEmpty { return live }
        return rx.running ? rx.timecodeStreams : (try? parseList(rx.timecodeText, max: 255, what: "")) ?? []
    }

    var body: some View {
        ModulePanel("Timecode") {
            Button("Scan streams") { rx.scanTimecode() }
                .buttonStyle(.softKey)
                .disabled(!rx.running)
                .help("Look for timecode on every stream, 1 to 255, and show the live ones")
        } content: {
            if streams.isEmpty {
                Text(rx.running ? "No timecode streams. Press Scan streams." : "No timecode streams set.")
                    .font(.system(size: 12)).foregroundStyle(Color.silk)
            }
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 300), spacing: 12, alignment: .leading)], alignment: .leading, spacing: 12) {
                ForEach(streams, id: \.self) { s in display(s, rx.timecodes[s]) }
            }
        }
    }

    private func display(_ s: UInt16, _ tc: TimecodeFrame?) -> some View {
        let v = tc?.value
        let drop = v.map { [0x02, 0x06, 0x09].contains($0[4]) } ?? false
        let time = v.map { String(format: "%02d:%02d:%02d%@%02d", $0[0], $0[1], $0[2], drop ? ";" : ":", $0[3]) } ?? "--:--:--:--"
        let lost = tc?.lost ?? false
        let state = tc == nil ? (rx.running ? "Waiting" : "Stopped") : lost ? "Lost" : "Running"
        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Silkscreen("Stream \(s)")
                Spacer()
                Lamp(color: tc == nil ? nil : lost ? .lampFault : .lampOnline)
                Text(state).font(.system(size: 11, weight: .semibold)).foregroundStyle(lost ? Color.lampFault : Color.inkDim)
            }
            ReadoutWindow(signal: lost ? .refused("") : .idle) {
                HStack(alignment: .firstTextBaseline) {
                    Text(time)
                        .font(.system(size: 34, weight: .medium, design: .monospaced)).monospacedDigit()
                        .foregroundStyle(tc == nil ? Color.silk : lost ? Color.inkDim : Color.lampLatch)
                    Spacer()
                    Text(v.map { String(format: "%g fps", Receiver.timecodeFPS($0[4])) } ?? "")
                        .font(.system(size: 12, design: .monospaced)).foregroundStyle(Color.inkDim)
                }
                .padding(.vertical, 8)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Timecode stream \(s)")
        .accessibilityValue("\(tc == nil ? "no timecode" : time), \(state)")
    }
}

/// Preview universes: the look a console is about to send.
private struct ReceivePreview: View {
    @ObservedObject var rx: Receiver

    private var universes: [UInt16] {
        rx.running || !rx.previewUniverses.isEmpty ? rx.previewUniverses : (try? parseList(rx.previewText, max: 63999, what: "")) ?? []
    }

    var body: some View {
        ModulePanel("Preview") {
            if universes.isEmpty {
                Text("No preview universes set. Add them under Monitor, Settings.")
                    .font(.system(size: 12)).foregroundStyle(Color.silk)
            }
            ForEach(universes, id: \.self) { u in
                let p = rx.previews[u]
                VStack(alignment: .leading, spacing: 6) {
                    HStack(spacing: 14) {
                        Silkscreen("Universe \(u)")
                        if let p {
                            Text("\(p.frame.slotCount) channels  ·  \(max(0, (rx.nowNs - p.frame.publishedNs) / 1_000_000)) ms old")
                                .font(.system(size: 11, design: .monospaced)).monospacedDigit().foregroundStyle(Color.inkDim)
                        } else {
                            Text(rx.running ? "No preview yet" : "Stopped").font(.system(size: 11)).foregroundStyle(Color.silk)
                        }
                    }
                    LevelGrid(levels: p?.levels ?? Array(repeating: 0, count: 512), numbers: false, name: "Preview universe \(u)")
                        .frame(height: 110)
                }
            }
        }
    }
}

/// 32×16 slot grid in one Canvas so 20 Hz redraws stay cheap: recessed window, teal by level.
private struct LevelGrid: View {
    let levels: [UInt8]
    let numbers: Bool
    let name: String

    var body: some View {
        Canvas { ctx, size in
            let pad: CGFloat = 6
            let w = (size.width - pad * 2) / 32, h = (size.height - pad * 2) / 16
            for (i, v) in levels.prefix(512).enumerated() {
                let rect = CGRect(x: pad + CGFloat(i % 32) * w, y: pad + CGFloat(i / 32) * h, width: w - 2, height: h - 2)
                let cell = Path(roundedRect: rect, cornerRadius: 2)
                ctx.fill(cell, with: .color(Color.module.opacity(0.55)))
                if v > 0 { ctx.fill(cell, with: .color(Color.lampLatch.opacity(0.18 + 0.82 * Double(v) / 255))) }
                if numbers {
                    ctx.draw(Text("\(v)").font(.system(size: 9, design: .monospaced))
                        .foregroundColor(v > 150 ? Color.readoutWindow : v > 0 ? Color.ink : Color.silk.opacity(0.6)),
                             at: CGPoint(x: rect.midX, y: rect.midY))
                }
            }
        }
        .background(RoundedRectangle(cornerRadius: 4, style: .continuous).fill(Color.readoutWindow)
            .overlay(RoundedRectangle(cornerRadius: 4, style: .continuous).strokeBorder(Color.black.opacity(0.7), lineWidth: 1)))
        .accessibilityElement()
        .accessibilityLabel(name)
        .accessibilityValue("\(levels.filter { $0 > 0 }.count) of 512 channels above zero, highest \(levels.max() ?? 0), channel 1 at \(levels.first ?? 0)")
    }
}
