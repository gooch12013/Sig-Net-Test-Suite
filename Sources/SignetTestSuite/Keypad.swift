import SwiftUI

/// The number currently being entered: which row, its limits, and how to send it.
/// One per window; every numeric SET routes here and the docked keypad edits it.
final class NumberEntry: ObservableObject {
    struct Target {
        let id: UUID
        let label: String
        let range: ClosedRange<Int64>?
        let unit: String
        let commit: (String) -> Void
    }

    @Published private(set) var target: Target?
    @Published var draft = ""
    @Published var problem: String?

    func begin(_ target: Target, initial: String) {
        self.target = target
        draft = initial
        problem = nil
    }

    func cancel() { target = nil; draft = ""; problem = nil }

    func press(_ key: String) {
        guard target != nil else { return }
        problem = nil
        switch key {
        case "⌫": if !draft.isEmpty { draft.removeLast() }
        case "CLR": draft = ""
        case "±": draft = draft.hasPrefix("-") ? String(draft.dropFirst()) : "-" + draft
        case ".": if !draft.contains(".") { draft += draft.isEmpty ? "0." : "." }
        default: draft = draft == "0" ? key : draft + key
        }
    }

    /// Checks the range here so a bad number never leaves the keypad.
    func enter() {
        guard let t = target else { return }
        let text = draft.trimmingCharacters(in: .whitespaces)
        guard let v = Int64(text) ?? Double(text).map({ Int64($0.rounded()) }) else { problem = "Type a number"; return }
        if let r = t.range, !r.contains(v) { problem = "Use \(r.lowerBound)–\(r.upperBound)"; return }
        t.commit(text)
        cancel()
    }
}

/// A test-gear keypad docked at the right of the main area.
struct KeypadPanel: View {
    @EnvironmentObject private var entry: NumberEntry
    @FocusState private var focused: Bool

    private let rows = [["7", "8", "9"], ["4", "5", "6"], ["1", "2", "3"], ["±", "0", "."]]

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            DSKYDisplay(entry: entry)
                .overlay {
                    // Invisible field so the keyboard types into the display; digits, sign and point only.
                    TextField("", text: $entry.draft)
                        .textFieldStyle(.plain).opacity(0.02)
                        .focused($focused)
                        .disabled(entry.target == nil)
                        .onSubmit { entry.enter() }
                        .onExitCommand { entry.cancel() }
                        .onChange(of: entry.draft) { v in
                            let clean = v.filter { $0.isNumber || $0 == "." || $0 == "-" }
                            if clean != v { entry.draft = clean }
                        }
                        .accessibilityLabel(entry.target.map { "Value for \($0.label)" } ?? "Keypad display")
                        .accessibilityValue(entry.draft)
                }
            Text(entry.problem ?? (entry.target == nil ? "Press SET on a number to enter it here." : "Type on the keypad or keyboard, then Enter."))
                .font(.system(size: 11.5))
                .foregroundStyle(entry.problem == nil ? Color.silk : Color.lampFault)
                .fixedSize(horizontal: false, vertical: true)
            Grid(horizontalSpacing: 6, verticalSpacing: 6) {
                ForEach(rows, id: \.self) { row in
                    GridRow {
                        ForEach(row, id: \.self) { key in
                            Button { entry.press(key) } label: { Text(key).font(.system(size: 16, weight: .semibold, design: .monospaced)).frame(minHeight: 34) }
                                .buttonStyle(SoftKeyStyle(fill: true))
                                .accessibilityLabel(key == "±" ? "Plus or minus" : key == "." ? "Decimal point" : key)
                        }
                    }
                }
                GridRow {
                    Button { entry.press("⌫") } label: { Image(systemName: "delete.left").frame(minHeight: 30) }
                        .buttonStyle(SoftKeyStyle(fill: true)).accessibilityLabel("Delete")
                    Button { entry.press("CLR") } label: { Text("Clear").frame(minHeight: 30) }
                        .buttonStyle(SoftKeyStyle(fill: true)).gridCellColumns(2)
                }
                GridRow {
                    Button { entry.cancel() } label: { Text("Cancel").frame(minHeight: 34) }
                        .buttonStyle(SoftKeyStyle(fill: true))
                    Button { entry.enter() } label: { Text("Enter").frame(minHeight: 34) }
                        .buttonStyle(SoftKeyStyle(prominent: true, fill: true)).gridCellColumns(2)
                        .keyboardShortcut(.defaultAction)
                }
            }
            .disabled(entry.target == nil)
            Spacer(minLength: 0)
        }
        .padding(14)
        .frame(maxHeight: .infinity, alignment: .top)
        .background(
            RoundedRectangle(cornerRadius: 7, style: .continuous).fill(Color.module)
                .overlay(RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .strokeBorder(LinearGradient(colors: [.white.opacity(0.07), .black.opacity(0.35)], startPoint: .top, endPoint: .bottom), lineWidth: 1))
                .shadow(color: .black.opacity(0.45), radius: 3, y: 2)
        )
        .onChange(of: entry.target?.id) { id in focused = id != nil }
    }
}


// MARK: - DSKY display

extension Color {
    /// Electroluminescent segment green, lit and unlit.
    static let segmentLit = Color(red: 0x8C / 255, green: 0xFF / 255, blue: 0x8A / 255)
    static let segmentDark = Color(red: 0x12 / 255, green: 0x24 / 255, blue: 0x17 / 255)
}

/// The keypad's display, after the Apollo guidance computer's DSKY: caution tiles, labelled fields
/// and green seven-segment digits behind a black bezel.
private struct DSKYDisplay: View {
    @ObservedObject var entry: NumberEntry

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                tile("Entry", lit: entry.target != nil, color: .ink)
                tile("Opr err", lit: entry.problem != nil, color: .lampFault)
            }
            Silkscreen(entry.target?.label ?? "No entry", color: entry.target == nil ? .silk : .segmentLit.opacity(0.85))
                .lineLimit(1)
            HStack {
                Spacer(minLength: 0)
                SevenSegmentText(text: entry.target == nil ? "" : (entry.draft.isEmpty ? "0" : entry.draft), digits: 6, height: 30)
            }
            .padding(.vertical, 7).padding(.leading, 24).padding(.trailing, 8) // leading room for the R1 legend
            .background(RoundedRectangle(cornerRadius: 3).fill(Color.black))
            .overlay(alignment: .topLeading) { Text("R1").font(.system(size: 8.5, weight: .bold)).foregroundStyle(Color.segmentLit.opacity(0.6)).padding(4) }
            HStack(alignment: .bottom, spacing: 10) {
                field("Lo", entry.target?.range.map { "\($0.lowerBound)" } ?? "")
                field("Hi", entry.target?.range.map { "\($0.upperBound)" } ?? "")
                Spacer(minLength: 0)
                VStack(alignment: .trailing, spacing: 3) {
                    Text("UNIT").font(.system(size: 8.5, weight: .bold)).tracking(0.6).foregroundStyle(Color.segmentLit.opacity(0.6))
                    Text(entry.target?.unit.isEmpty == false ? entry.target!.unit : "—")
                        .font(.system(size: 12, weight: .semibold, design: .monospaced)).foregroundStyle(Color.segmentLit.opacity(entry.target == nil ? 0.25 : 0.9))
                }
            }
        }
        .padding(10)
        .background(
            RoundedRectangle(cornerRadius: 6, style: .continuous).fill(Color(red: 0.05, green: 0.06, blue: 0.065))
                .overlay(RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .strokeBorder(LinearGradient(colors: [.black.opacity(0.8), .white.opacity(0.06)], startPoint: .top, endPoint: .bottom), lineWidth: 2))
        )
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(entry.target.map { "Entering \($0.label)" } ?? "Keypad display, no entry")
        .accessibilityValue(entry.draft)
    }

    /// A caution tile: dark when off, backlit with its colour when on.
    private func tile(_ title: String, lit: Bool, color: Color) -> some View {
        Text(title.uppercased())
            .font(.system(size: 9, weight: .heavy)).tracking(0.6)
            .foregroundStyle(lit ? Color.black : Color.silk.opacity(0.35))
            .frame(maxWidth: .infinity, minHeight: 20)
            .background(RoundedRectangle(cornerRadius: 2).fill(lit ? color : Color.white.opacity(0.04)))
            .shadow(color: lit ? color.opacity(0.6) : .clear, radius: 4)
    }

    private func field(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title.uppercased()).font(.system(size: 8.5, weight: .bold)).tracking(0.6).foregroundStyle(Color.segmentLit.opacity(0.6))
            SevenSegmentText(text: value, digits: 5, height: 15)
                .padding(.horizontal, 4).padding(.vertical, 3)
                .background(RoundedRectangle(cornerRadius: 2).fill(Color.black))
        }
    }
}

/// Seven-segment digits drawn as paths: lit segments glow, unlit ones show faintly, like a real display.
/// Handles 0-9, minus and a decimal point; right-aligned in `digits` cells.
struct SevenSegmentText: View {
    let text: String
    var digits = 6
    var height: CGFloat = 30

    private static let map: [Character: String] = [
        "0": "abcdef", "1": "bc", "2": "abged", "3": "abgcd", "4": "fgbc", "5": "afgcd",
        "6": "afgedc", "7": "abc", "8": "abcdefg", "9": "abcdfg", "-": "g", " ": "",
    ]

    /// Characters with any decimal point folded into the cell before it.
    private var cells: [(Character, Bool)] {
        var out: [(Character, Bool)] = []
        for ch in text {
            if ch == ".", !out.isEmpty { out[out.count - 1].1 = true } else if ch == "." { out.append(("0", true)) }
            else { out.append((Self.map[ch] == nil ? " " : ch, false)) }
        }
        let shown = Array(out.suffix(digits))
        return Array(repeating: (" ", false), count: max(0, digits - shown.count)) + shown
    }

    var body: some View {
        let w = height * 0.56, gap = height * 0.18
        Canvas { ctx, _ in
            for (i, cell) in cells.enumerated() {
                let x = CGFloat(i) * (w + gap)
                let lit = Set(Self.map[cell.0] ?? "")
                for seg in "abcdefg" {
                    let path = Self.segment(seg, x: x, w: w, h: height)
                    if lit.contains(seg) {
                        ctx.drawLayer { l in
                            l.addFilter(.shadow(color: Color.segmentLit.opacity(0.75), radius: height * 0.08))
                            l.fill(path, with: .color(.segmentLit))
                        }
                    } else {
                        ctx.fill(path, with: .color(.segmentDark))
                    }
                }
                let dot = Path(ellipseIn: CGRect(x: x + w + gap * 0.18, y: height * 0.9, width: height * 0.1, height: height * 0.1))
                ctx.fill(dot, with: .color(cell.1 ? .segmentLit : .segmentDark))
            }
        }
        .frame(width: CGFloat(digits) * (w + gap), height: height)
        .accessibilityHidden(true)
    }

    /// One segment as a hexagon inside a w × h digit cell.
    private static func segment(_ s: Character, x: CGFloat, w: CGFloat, h: CGFloat) -> Path {
        let t = h * 0.11, half = t / 2, mid = h / 2, g = t * 0.18
        func horizontal(_ y: CGFloat) -> Path {
            var p = Path()
            p.move(to: CGPoint(x: x + half + g, y: y))
            p.addLine(to: CGPoint(x: x + t + g, y: y - half)); p.addLine(to: CGPoint(x: x + w - t - g, y: y - half))
            p.addLine(to: CGPoint(x: x + w - half - g, y: y)); p.addLine(to: CGPoint(x: x + w - t - g, y: y + half))
            p.addLine(to: CGPoint(x: x + t + g, y: y + half)); p.closeSubpath()
            return p
        }
        func vertical(_ cx: CGFloat, _ y0: CGFloat, _ y1: CGFloat) -> Path {
            var p = Path()
            p.move(to: CGPoint(x: cx, y: y0 + half + g))
            p.addLine(to: CGPoint(x: cx + half, y: y0 + t + g)); p.addLine(to: CGPoint(x: cx + half, y: y1 - t - g))
            p.addLine(to: CGPoint(x: cx, y: y1 - half - g)); p.addLine(to: CGPoint(x: cx - half, y: y1 - t - g))
            p.addLine(to: CGPoint(x: cx - half, y: y0 + t + g)); p.closeSubpath()
            return p
        }
        switch s {
        case "a": return horizontal(half)
        case "g": return horizontal(mid)
        case "d": return horizontal(h - half)
        case "f": return vertical(x + half, 0, mid)
        case "b": return vertical(x + w - half, 0, mid)
        case "e": return vertical(x + half, mid, h)
        default: return vertical(x + w - half, mid, h) // c
        }
    }
}
