import SwiftUI

/// Transmit: a control strip, four modules of local settings, then the channel fader bank.
/// Every setting is a readout with SET; nothing here is fetched from a device, so there is no GET.
struct TransmitView: View {
    @ObservedObject var tx: Transmitter
    @ObservedObject var fixtures: FixtureStore

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                controlStrip
                HStack(alignment: .top, spacing: 12) {
                    VStack(spacing: 12) { output; prioritySync }
                    VStack(spacing: 12) { timecode; previewPatterns }
                }
                channels
            }
        }
    }

    // MARK: Control strip

    private var controlStrip: some View {
        HStack(spacing: 10) {
            if tx.running {
                Button("Stop") { tx.stop() }
                    .buttonStyle(SoftKeyStyle(lamp: .lampOnline))
                    .keyboardShortcut(.return, modifiers: .command)
                    .help("Stop sending")
            } else {
                Button("Start") { tx.start() }
                    .buttonStyle(SoftKeyStyle(prominent: true))
                    .keyboardShortcut(.return, modifiers: .command)
                    .disabled(!tx.settings.ready)
                    .help("Start sending levels")
            }
            Text(tx.status)
                .font(.system(size: 11.5))
                .foregroundStyle(Color.silk)
                .lineLimit(1).truncationMode(.middle)
            if tx.sendFailures > 0 {
                Lamp(color: .lampFault)
                Text("\(tx.sendFailures) send failures")
                    .font(.system(size: 11.5))
                    .foregroundStyle(Color.lampFault)
            }
            Spacer()
            Silkscreen("Sender ID")
            Text(Identity.hex(tx.tuid))
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(Color.silk)
                .textSelection(.enabled)
                .accessibilityLabel("Sender ID \(Identity.hex(tx.tuid))")
        }
    }

    // MARK: Modules

    private var output: some View {
        ModulePanel("Output") {
            if tx.running { Text("Locked while sending").font(.system(size: 11)).foregroundStyle(Color.silk) }
        } content: {
            ReadoutRow(label: "Universe", value: "\(tx.universe)",
                       set: number(initial: tx.universe, in: 1...63999) { tx.universe = $0 }, enabled: !tx.running)
            ReadoutRow(label: "Universes", value: tx.count == 1 ? "1" : "\(tx.count)  (\(tx.universe)–\(tx.universe + tx.count - 1))",
                       set: number(initial: tx.count, in: 1...16) { tx.count = $0 }, enabled: !tx.running)
            ReadoutRow(label: "Max frame rate", value: "\(tx.maxFps) per second",
                       set: number(initial: tx.maxFps, in: 1...65535) { tx.maxFps = $0 }, enabled: !tx.running)
            if tx.count > 1 {
                HStack(spacing: 8) {
                    rowLabel("Editing universe")
                    ScrollView(.horizontal, showsIndicators: false) {
                        ModeKeys(options: (0..<tx.count).map { ($0, "\(tx.universe + $0)") }, selection: $tx.selected)
                            .padding(.vertical, 2)
                    }
                }
                .accessibilityElement(children: .contain)
                .accessibilityLabel("Editing universe")
            }
        }
    }

    private var prioritySync: some View {
        ModulePanel("Priority & sync") {
            ReadoutRow(label: "Send priority", value: tx.sendPriority ? "On" : "Off",
                       set: onOff { tx.sendPriority = $0 })
            ReadoutRow(label: "Priority", value: "\(tx.priorities[tx.selected])" + (tx.count > 1 ? "  (universe \(tx.universe + tx.selected))" : ""),
                       set: number(initial: tx.priorities[tx.selected], in: 0...200) { tx.priorities[tx.selected] = $0 },
                       enabled: tx.sendPriority)
            ReadoutRow(label: "Synchronised output", value: tx.sync ? "On" : "Off",
                       set: onOff { tx.sync = $0 })
            ReadoutRow(label: "Synchronised rate", value: tx.running && tx.sync ? "\(tx.syncFps) per second" : nil)
        }
    }

    private var timecode: some View {
        ModulePanel("Timecode") {
            HStack(spacing: 6) {
                Lamp(color: tx.tcRunning ? .lampOnline : nil)
                Silkscreen(tx.tcRunning ? "Running" : "Stopped", color: tx.tcRunning ? .inkDim : .silk)
            }
            .accessibilityElement(children: .combine)
        } content: {
            HStack(spacing: 12) {
                ReadoutWindow {
                    Text(tx.tcDisplay)
                        .font(.system(size: 34, weight: .medium, design: .monospaced).monospacedDigit())
                        .foregroundStyle(tx.tcRunning ? Color.ink : Color.inkDim)
                        .padding(.vertical, 6)
                        .frame(maxWidth: .infinity)
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("Timecode")
                .accessibilityValue(tx.tcDisplay)
                VStack(spacing: 6) {
                    if tx.tcRunning {
                        Button("Stop") { tx.stopTimecode() }.buttonStyle(SoftKeyStyle(lamp: .lampOnline))
                            .help("Stop the timecode generator")
                    } else {
                        Button("Start") { tx.startTimecode() }.buttonStyle(.softKey)
                            .disabled(!tx.running)
                            .help(tx.running ? "Start the timecode generator" : "Start sending first")
                    }
                    Button("Reset") { tx.resetTimecode() }.buttonStyle(.softKey)
                        .help("Return timecode to 00:00:00:00")
                }
                .frame(width: 70)
            }
            ReadoutRow(label: "Timecode stream", value: "\(tx.tcStream)",
                       set: number(initial: tx.tcStream, in: 1...255) { tx.tcStream = $0 }, enabled: !tx.tcRunning)
            ReadoutRow(label: "Rate", value: rateName(tx.tcRate),
                       set: .choices(Transmitter.timecodeRates.map(rateName)) { i, done in tx.tcRate = UInt8(i); done(.latched) },
                       enabled: !tx.tcRunning)
        }
    }

    private var previewPatterns: some View {
        ModulePanel("Preview & patterns") {
            ReadoutRow(label: "Send preview", value: tx.preview ? "On, universe \(tx.universe + tx.selected)" : "Off",
                       set: onOff { tx.preview = $0 })
            HStack(spacing: 8) {
                rowLabel("Test pattern")
                ModeKeys(options: Transmitter.Pattern.allCases.map { ($0, $0.rawValue) }, selection: $tx.pattern)
            }
            .accessibilityElement(children: .contain)
            .accessibilityLabel("Test pattern")
            ReadoutRow(label: "Speed", value: "\(Int(tx.patternSpeed)) steps per second",
                       set: number(initial: Int(tx.patternSpeed), in: 1...30) { tx.patternSpeed = Double($0) })
        }
    }

    private var channels: some View {
        ModulePanel(tx.count > 1 ? "Channels, universe \(tx.universe + tx.selected)" : "Channels") {
            Button("All 0") { tx.setAll(0) }.buttonStyle(.softKey).help("Set every channel to 0")
            Button("All full") { tx.setAll(255) }.buttonStyle(.softKey).help("Set every channel to 255")
        } content: {
            let names = fixtures.channelNames(universe: tx.universe + tx.selected)
            let spans = fixtures.spans(universe: tx.universe + tx.selected)
            let headed = !names.isEmpty
            let bracketed = !spans.isEmpty
            HStack(alignment: .top, spacing: 12) {
                VStack(spacing: 0) {
                    if headed { Color.clear.frame(height: Self.headingHeight) } // keeps the master level with the headed bank
                    Fader(value: $tx.master, label: "Master", name: "Master")
                        .frame(height: 270) // same height as the bank so the slots line up
                }
                .fixedSize(horizontal: true, vertical: false) // the spacer must not widen the master column
                Rectangle().fill(Color.black.opacity(0.4)).frame(width: 1).padding(.vertical, 4)
                ScrollView(.horizontal) {
                    LazyHStack(alignment: .bottom, spacing: 2) {
                        ForEach(0..<tx.levels.count, id: \.self) { i in
                            VStack(spacing: 0) {
                                if headed { heading(names[i + 1]) }
                                Fader(value: channel(i), label: "\(i + 1)", name: names[i + 1].map { "Channel \(i + 1), \($0)" } ?? "Channel \(i + 1)")
                                if bracketed { Color.clear.frame(width: 30, height: Self.bracketHeight) }
                            }
                            .padding(.leading, i > 0 && i % 8 == 0 ? 10 : 0) // gap every 8, like a console bank
                        }
                    }
                    .overlay(alignment: .bottomLeading) {
                        ZStack(alignment: .topLeading) {
                            ForEach(spans, id: \.self) { span in
                                let left = Self.columnX(span.start - 1) + 3, right = Self.columnX(span.end - 1) + 27
                                FixtureBracket(name: span.name).frame(width: right - left, height: Self.bracketHeight).offset(x: left)
                            }
                        }
                        .frame(height: Self.bracketHeight, alignment: .topLeading)
                    }
                    .frame(height: 270 + (headed ? Self.headingHeight : 0) + (bracketed ? Self.bracketHeight : 0))
                }
                .scrollIndicators(.visible)
                // Fade the trailing edge so a cut fader reads as "more this way", not as a clipped control.
                .mask(LinearGradient(stops: [.init(color: .black, location: 0), .init(color: .black, location: 0.93),
                                             .init(color: .clear, location: 1)], startPoint: .leading, endPoint: .trailing))
            }
            .frame(height: 290 + (fixtures.channelNames(universe: tx.universe + tx.selected).isEmpty ? 0 : Self.headingHeight)
                   + (fixtures.spans(universe: tx.universe + tx.selected).isEmpty ? 0 : Self.bracketHeight))
        }
    }

    // MARK: Helpers

    static let headingHeight: CGFloat = 78
    static let bracketHeight: CGFloat = 26

    /// Left edge of fader column `i` in the bank: 30 wide, 2 apart, plus a 10 gap before every bank of 8.
    static func columnX(_ i: Int) -> CGFloat { CGFloat(i * 32 + 10 * (i / 8)) }

    /// A channel name set at 35°, rising from the fader like a spreadsheet column heading.
    private func heading(_ text: String?) -> some View {
        ZStack(alignment: .bottomLeading) {
            if let text {
                Text(text)
                    .font(.system(size: 10.5, weight: .medium))
                    .foregroundStyle(Color.inkDim)
                    .lineLimit(1).fixedSize()
                    .rotationEffect(.degrees(-35), anchor: .bottomLeading)
                    .offset(x: 13, y: -4)
                    .help(text)
            }
        }
        .frame(width: 30, height: Self.headingHeight, alignment: .bottomLeading)
        .accessibilityHidden(true) // the fader's own label carries the name
    }

    private func rowLabel(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 12.5, weight: .medium))
            .foregroundStyle(Color.inkDim)
            .frame(width: ReadoutRow.labelWidth, alignment: .leading)
    }

    /// Whole-number SET that refuses anything outside `range` and says why.
    private func number(initial: Int, in range: ClosedRange<Int>, apply: @escaping (Int) -> Void) -> SetMode {
        .number(initial: "\(initial)", range: Int64(range.lowerBound)...Int64(range.upperBound)) { text, done in
            guard let n = Int(text.trimmingCharacters(in: .whitespaces)), range.contains(n) else {
                done(.refused("Enter a whole number from \(range.lowerBound) to \(range.upperBound)")); return
            }
            apply(n)
            done(.latched)
        }
    }

    private func onOff(_ apply: @escaping (Bool) -> Void) -> SetMode {
        .choices(["Off", "On"]) { i, done in apply(i == 1); done(.latched) }
    }

    /// "29.97 DF" reads as "29.97 fps drop frame"; the rest are plain frames per second.
    private func rateName(_ code: UInt8) -> String {
        Int(code) < Transmitter.timecodeRates.count ? rateName(Transmitter.timecodeRates[Int(code)]) : "\(code)"
    }
    private func rateName(_ raw: String) -> String {
        raw.hasSuffix(" DF") ? raw.dropLast(3) + " fps drop frame" : raw + " fps"
    }

    private func channel(_ i: Int) -> Binding<Double> {
        Binding(get: { Double(tx.levels[i]) }, set: { tx.levels[i] = UInt8($0.rounded()) })
    }
}

/// Vertical instrument fader, 0...255: a recessed slot, teal fill and a ribbed cap.
/// Click jumps to the position; drag follows; arrow keys and VoiceOver step it.
/// The master (label "Master") gets a wider cap with an ink stripe.
struct Fader: View {
    @Binding var value: Double
    let label: String
    let name: String
    var tint: Color = .sigNet
    @FocusState private var focused: Bool

    private var isMaster: Bool { label == "Master" }
    private let capHeight: CGFloat = 16
    private var capWidth: CGFloat { isMaster ? 30 : 18 }

    var body: some View {
        VStack(spacing: 4) {
            Text("\(Int(value.rounded()))")
                .font(.system(size: 10, weight: .medium, design: .monospaced).monospacedDigit())
                .foregroundStyle(focused ? Color.lampLatch : value > 0 ? Color.ink : Color.silk)
            GeometryReader { geo in
                let travel = geo.size.height - capHeight
                let y = travel * value / 255
                ZStack(alignment: .bottom) {
                    // Recessed slot with the level lit inside it.
                    RoundedRectangle(cornerRadius: 3, style: .continuous)
                        .fill(Color.readoutWindow)
                        .overlay(RoundedRectangle(cornerRadius: 3, style: .continuous).strokeBorder(Color.black.opacity(0.7), lineWidth: 1))
                        .frame(width: 6)
                    RoundedRectangle(cornerRadius: 2, style: .continuous)
                        .fill(tint.opacity(0.85))
                        .frame(width: 4, height: max(0, capHeight / 2 + y - 1))
                        .padding(.bottom, 1)
                    cap.offset(y: -y)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .bottom)
                .contentShape(Rectangle())
                .gesture(DragGesture(minimumDistance: 0).onChanged { drag in
                    let fraction = 1 - (drag.location.y - capHeight / 2) / travel
                    value = (min(1, max(0, fraction)) * 255).rounded()
                })
            }
            .frame(width: capWidth + 4)
            Silkscreen(label, color: isMaster ? .inkDim : .silk)
                .lineLimit(1).fixedSize()
        }
        .frame(width: isMaster ? 48 : 30)
        .focusable()
        .focused($focused)
        .noFocusRing() // the lit value and teal cap edge show focus instead of the system's blue box
        .onMoveCommand { direction in
            switch direction {
            case .up: value = min(255, value + 1)
            case .down: value = max(0, value - 1)
            default: break
            }
        }
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

    /// Raised key-face cap: highlight line on top, three ribs, and an ink stripe on the master.
    private var cap: some View {
        RoundedRectangle(cornerRadius: 2.5, style: .continuous)
            .fill(Color.keyFace)
            .overlay(alignment: .top) { Rectangle().fill(Color.white.opacity(0.22)).frame(height: 1).padding(.horizontal, 2).padding(.top, 1) }
            .overlay {
                VStack(spacing: 2.5) {
                    ForEach(0..<3, id: \.self) { _ in Rectangle().fill(Color.black.opacity(0.4)).frame(height: 1) }
                }
                .padding(.horizontal, 3)
            }
            .overlay { if isMaster { Rectangle().fill(Color.ink).frame(width: 2) } }
            .overlay(RoundedRectangle(cornerRadius: 2.5, style: .continuous)
                .strokeBorder(focused ? Color.lampLatch : Color.black.opacity(0.55), lineWidth: 1))
            .frame(width: capWidth, height: capHeight)
            .shadow(color: .black.opacity(0.5), radius: 1.5, y: 1)
    }
}


/// A box without its top: down-strokes at a fixture's first and last channel, joined underneath, its name in the middle.
private struct FixtureBracket: View {
    let name: String

    var body: some View {
        GeometryReader { geo in
            let w = geo.size.width, y: CGFloat = 13
            ZStack(alignment: .topLeading) {
                Path { p in
                    p.move(to: CGPoint(x: 0.75, y: 2)); p.addLine(to: CGPoint(x: 0.75, y: y))
                    p.addLine(to: CGPoint(x: w - 0.75, y: y)); p.addLine(to: CGPoint(x: w - 0.75, y: 2))
                }
                .stroke(Color.silk, style: StrokeStyle(lineWidth: 1.5, lineJoin: .round))
                Text(name)
                    .font(.system(size: 10.5, weight: .semibold))
                    .foregroundStyle(Color.inkDim)
                    .lineLimit(1).fixedSize()
                    .padding(.horizontal, 6)
                    .background(Color.module) // breaks the line around the name
                    .position(x: w / 2, y: y)
            }
        }
        .accessibilityElement()
        .accessibilityLabel("\(name) channels")
    }
}
