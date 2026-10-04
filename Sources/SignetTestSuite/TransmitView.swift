import SwiftUI

struct TransmitView: View {
    @ObservedObject var tx: Transmitter

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            settings.disabled(tx.running)
            extras

            HStack {
                Button(tx.running ? "Stop" : "Start") { tx.running ? tx.stop() : tx.start() }
                    .keyboardShortcut(.return, modifiers: .command)
                    .disabled(!tx.running && !tx.settings.ready)
                Text(tx.status).foregroundStyle(.secondary).lineLimit(2)
                Spacer()
                if tx.sendFailures > 0 {
                    Text("\(tx.sendFailures) send failures").foregroundStyle(.red)
                }
                Button("All 0") { tx.setAll(0) }
                Button("All Full") { tx.setAll(255) }
            }

            Divider()

            if tx.count > 1 {
                Picker("Edit universe", selection: $tx.selected) {
                    ForEach(0..<tx.count, id: \.self) { Text("\(tx.universe + $0)").tag($0) }
                }
                .pickerStyle(.segmented)
            }

            HStack(alignment: .top, spacing: 12) {
                Fader(value: $tx.master, label: "M", name: "Master", tint: .orange)
                Divider()
                ScrollView(.horizontal) {
                    LazyHStack(spacing: 2) {
                        ForEach(0..<tx.levels.count, id: \.self) { i in
                            Fader(value: channel(i), label: "\(i + 1)", name: "Channel \(i + 1)")
                                .padding(.leading, i > 0 && i % 8 == 0 ? 8 : 0) // gap every 8, like a console bank
                        }
                    }
                    .padding(.bottom, 12)
                }
            }
            .frame(minHeight: 220)
        }
        .padding()
    }

    private var settings: some View {
        Form {
            TextField("Universe (1–63999)", value: $tx.universe, format: .number.grouping(.never))
            Stepper("Universes: \(tx.count)", value: $tx.count, in: 1...16)
            TextField("Max fps", value: $tx.maxFps, format: .number)
            LabeledContent("TUID", value: Identity.hex(tx.tuid))
        }
    }

    /// Live controls: usable while transmitting.
    private var extras: some View {
        DisclosureGroup("Priority · Sync · Timecode · Preview · Patterns") {
            Form {
                Toggle("Send priority", isOn: $tx.sendPriority)
                Stepper("Universe \(tx.universe + tx.selected) priority: \(tx.priorities[tx.selected])",
                        value: $tx.priorities[tx.selected], in: 0...200)
                    .disabled(!tx.sendPriority)
                Toggle("Synchronized output (TID_SYNC)", isOn: $tx.sync)
                LabeledContent("Synchronized fps", value: tx.running ? "\(tx.syncFps)" : "–")
                Toggle("Also send preview (10 Hz, selected universe)", isOn: $tx.preview)
                Picker("Test pattern", selection: $tx.pattern) {
                    ForEach(Transmitter.Pattern.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                Slider(value: $tx.patternSpeed, in: 1...30) { Text("Speed \(Int(tx.patternSpeed)) steps/s") }
                HStack {
                    Stepper("Timecode stream \(tx.tcStream)", value: $tx.tcStream, in: 1...255)
                    Picker("Rate", selection: $tx.tcRate) {
                        ForEach(Transmitter.timecodeRates.indices, id: \.self) { Text(Transmitter.timecodeRates[$0]).tag(UInt8($0)) }
                    }
                    .fixedSize()
                }
                .disabled(tx.tcRunning)
                HStack {
                    Text(tx.tcDisplay).font(.title3.monospacedDigit())
                    Button(tx.tcRunning ? "Stop" : "Start") { tx.tcRunning ? tx.stopTimecode() : tx.startTimecode() }
                        .disabled(!tx.running)
                    Button("Reset") { tx.resetTimecode() }
                }
            }
        }
    }

    private func channel(_ i: Int) -> Binding<Double> {
        Binding(get: { Double(tx.levels[i]) }, set: { tx.levels[i] = UInt8($0.rounded()) })
    }
}

/// Vertical console-style fader, 0...255. Click jumps to the position; drag follows.
struct Fader: View {
    @Binding var value: Double
    let label: String
    let name: String
    var tint: Color = .accentColor

    private let capHeight: CGFloat = 8

    var body: some View {
        VStack(spacing: 4) {
            Text("\(Int(value.rounded()))").font(.caption2.monospacedDigit())
            GeometryReader { geo in
                let travel = geo.size.height - capHeight
                ZStack(alignment: .bottom) {
                    RoundedRectangle(cornerRadius: 3).fill(.quaternary)
                    RoundedRectangle(cornerRadius: 3).fill(tint.opacity(0.55))
                        .frame(height: capHeight / 2 + travel * value / 255)
                    RoundedRectangle(cornerRadius: 2).fill(.primary)
                        .frame(height: capHeight)
                        .offset(y: -travel * value / 255)
                }
                .contentShape(Rectangle())
                .gesture(DragGesture(minimumDistance: 0).onChanged { drag in
                    let fraction = 1 - (drag.location.y - capHeight / 2) / travel
                    value = (min(1, max(0, fraction)) * 255).rounded()
                })
            }
            .frame(width: 20)
            Text(label).font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
        }
        .frame(width: 30)
        .accessibilityElement()
        .accessibilityLabel(name)
        .accessibilityValue("\(Int(value.rounded()))")
        .accessibilityAdjustableAction { direction in
            switch direction {
            case .increment: value = min(255, value + 5)
            case .decrement: value = max(0, value - 5)
            @unknown default: break
            }
        }
    }
}
