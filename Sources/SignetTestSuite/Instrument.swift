import AppKit
import SwiftUI

// The bench-instrument faceplate: graphite panels, recessed readouts, soft keys and lamps.
// Every screen builds from these pieces so the whole app reads as one piece of test gear.

extension Color {
    static let faceplate = Color(red: 0x1E / 255, green: 0x23 / 255, blue: 0x26 / 255)
    static let module = Color(red: 0x2C / 255, green: 0x33 / 255, blue: 0x38 / 255)
    static let readoutWindow = Color(red: 0x12 / 255, green: 0x16 / 255, blue: 0x1A / 255)
    static let ink = Color(red: 0xE9 / 255, green: 0xEE / 255, blue: 0xF0 / 255)
    static let inkDim = Color(red: 0xA9 / 255, green: 0xB4 / 255, blue: 0xBA / 255)
    static let silk = Color(red: 0x8F / 255, green: 0x9B / 255, blue: 0xA2 / 255)
    static let keyFace = Color(red: 0x3A / 255, green: 0x42 / 255, blue: 0x47 / 255)
    static let keyPressed = Color(red: 0x30 / 255, green: 0x37 / 255, blue: 0x3B / 255)
    static let lampOnline = Color(red: 0x7E / 255, green: 0xD9 / 255, blue: 0x57 / 255)
    static let lampLatch = Color(red: 0x3F / 255, green: 0xA7 / 255, blue: 0xAE / 255)
    /// Reserved for a request in flight. Nothing else uses it.
    static let lampPending = Color(red: 0xF0 / 255, green: 0xB4 / 255, blue: 0x29 / 255)
    static let lampFault = Color(red: 0xFF / 255, green: 0x6B / 255, blue: 0x5B / 255)
    static let brandStripe = Color(red: 0x06 / 255, green: 0x5A / 255, blue: 0x60 / 255)
}

/// What a lamp or readout is saying.
enum Signal: Equatable {
    case idle, pending, latched, refused(String), silent(String)

    var color: Color? {
        switch self {
        case .idle: return nil
        case .pending: return .lampPending
        case .latched: return .lampLatch
        case .refused, .silent: return .lampFault
        }
    }

    var message: String? {
        switch self {
        case .refused(let m), .silent(let m): return m
        default: return nil
        }
    }
}

/// Uppercase silkscreened panel lettering.
struct Silkscreen: View {
    let text: String
    var color: Color = .silk
    init(_ text: String, color: Color = .silk) { self.text = text; self.color = color }

    var body: some View {
        Text(text.uppercased())
            .font(.system(size: 10.5, weight: .semibold))
            .tracking(0.9)
            .foregroundStyle(color)
    }
}

/// A panel lamp: dark when off, lit with a soft glow when on, pulsing while pending.
struct Lamp: View {
    var color: Color?
    var pulsing = false
    var size: CGFloat = 8
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var dim = false

    var body: some View {
        Circle()
            .fill(color ?? Color.readoutWindow)
            .overlay(Circle().strokeBorder(Color.black.opacity(color == nil ? 0.6 : 0.25), lineWidth: 1))
            .frame(width: size, height: size)
            .shadow(color: (color ?? .clear).opacity(0.7), radius: color == nil ? 0 : 3, y: 0.5)
            .opacity(pulsing && dim ? 0.35 : 1)
            .onAppear(perform: animate)
            .onChange(of: pulsing) { _ in animate() }
            .accessibilityHidden(true)
    }

    private func animate() {
        guard pulsing, !reduceMotion else { dim = false; return }
        withAnimation(.easeInOut(duration: 1 / 2.4).repeatForever(autoreverses: true)) { dim = true }
    }
}

/// A raised module on the faceplate with its silkscreened title.
struct ModulePanel<Content: View, Accessory: View>: View {
    let title: String
    @ViewBuilder var accessory: Accessory
    @ViewBuilder var content: Content

    init(_ title: String, @ViewBuilder accessory: () -> Accessory = { EmptyView() }, @ViewBuilder content: () -> Content) {
        self.title = title
        self.accessory = accessory()
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Silkscreen(title)
                Spacer(minLength: 8)
                accessory
            }
            content
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 7, style: .continuous)
                .fill(Color.module)
                .overlay(RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .strokeBorder(LinearGradient(colors: [.white.opacity(0.07), .black.opacity(0.35)], startPoint: .top, endPoint: .bottom), lineWidth: 1))
                .shadow(color: .black.opacity(0.45), radius: 3, y: 2)
        )
    }
}

/// The recessed display window a value is shown in.
struct ReadoutWindow<Content: View>: View {
    var signal: Signal = .idle
    @ViewBuilder var content: Content
    @State private var flash = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        content
            .padding(.horizontal, 10)
            .frame(minHeight: 28)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 4, style: .continuous)
                    .fill(Color.readoutWindow)
                    .overlay(RoundedRectangle(cornerRadius: 4, style: .continuous)
                        .fill(Color.lampLatch.opacity(flash ? 0.22 : 0)))
                    .overlay(RoundedRectangle(cornerRadius: 4, style: .continuous)
                        .strokeBorder(signal.color?.opacity(0.85) ?? Color.black.opacity(0.7), lineWidth: 1))
                    .shadow(color: .white.opacity(0.05), radius: 0, y: 1)
            )
            .onChange(of: signal) { s in
                guard s == .latched, !reduceMotion else { return } // the teal border alone carries the latch
                flash = true
                withAnimation(.easeOut(duration: 0.4)) { flash = false }
            }
    }
}

/// Small flat raised key with an optional status lamp, used for GET, SET and every panel action.
struct SoftKeyStyle: ButtonStyle {
    var lamp: Color? = nil
    var pulsing = false
    var prominent = false
    /// A selected mode key: held down, face dark like a readout, legend fully lit.
    var latched = false
    /// Stretch to the width offered (keypad keys) instead of hugging the legend.
    var fill = false
    @Environment(\.isEnabled) private var enabled

    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 6) {
            if lamp != nil || pulsing { Lamp(color: lamp, pulsing: pulsing, size: 6) }
            configuration.label
                .font(.system(size: 11, weight: .semibold))
                .tracking(0.6)
                .textCase(.uppercase)
                .lineLimit(1)
                .fixedSize()
                .foregroundStyle(prominent ? Color.faceplate : latched ? Color.ink : Color.inkDim)
        }
        .padding(.horizontal, 10)
        .frame(maxWidth: fill ? .infinity : nil, minHeight: 24)
        .background(
            RoundedRectangle(cornerRadius: 4, style: .continuous)
                .fill(prominent ? Color.lampLatch : latched ? Color.readoutWindow : (configuration.isPressed ? Color.keyPressed : Color.keyFace))
                .overlay(RoundedRectangle(cornerRadius: 4, style: .continuous)
                    .strokeBorder(LinearGradient(colors: latched ? [.black.opacity(0.6), .white.opacity(0.06)]
                                                         : [.white.opacity(configuration.isPressed ? 0.03 : 0.12), .black.opacity(0.5)],
                                                 startPoint: .top, endPoint: .bottom), lineWidth: 1))
                .shadow(color: .black.opacity(latched || configuration.isPressed ? 0.2 : 0.5), radius: latched || configuration.isPressed ? 0.5 : 1.5,
                        y: latched || configuration.isPressed ? 0 : 1)
        )
        .offset(y: latched || configuration.isPressed ? 1 : 0)
        .opacity(enabled ? 1 : 0.38)
        .animation(.easeOut(duration: 0.1), value: configuration.isPressed)
        .contentShape(Rectangle())
    }
}

extension ButtonStyle where Self == SoftKeyStyle {
    static var softKey: SoftKeyStyle { SoftKeyStyle() }
}

/// A bank of soft keys acting as a mode selector, seated in one recessed tray so it never reads as a row of actions.
/// The selected key latches down; lamps stay free to show state (`lit`, e.g. a role that is running).
struct ModeKeys<Value: Hashable>: View {
    let options: [(Value, String)]
    @Binding var selection: Value
    var lit: (Value) -> Color? = { _ in nil }

    var body: some View {
        HStack(spacing: 3) {
            ForEach(options, id: \.0) { value, title in
                Button(title) { selection = value }
                    .buttonStyle(SoftKeyStyle(lamp: lit(value), latched: selection == value))
                    .accessibilityAddTraits(selection == value ? .isSelected : [])
            }
        }
        .padding(3)
        .background(RoundedRectangle(cornerRadius: 6, style: .continuous).fill(Color.black.opacity(0.28))
            .overlay(RoundedRectangle(cornerRadius: 6, style: .continuous).strokeBorder(Color.black.opacity(0.45), lineWidth: 1)))
    }
}

/// How a row's value can be set.
enum SetMode {
    /// Free text or a number; `initial` is what the field opens with.
    case text(initial: String, commit: (String, @escaping (Signal) -> Void) -> Void)
    /// A fixed list of choices.
    case choices([String], commit: (Int, @escaping (Signal) -> Void) -> Void)
    /// A number, entered on the docked keypad (range checked there).
    case number(initial: String, range: ClosedRange<Int64>? = nil, unit: String = "", commit: (String, @escaping (Signal) -> Void) -> Void)
}

/// One value on the panel: label, readout, GET and SET.
/// The row owns its signal: amber while a request is in flight, a teal latch on success, red on refusal or silence.
struct ReadoutRow: View {
    let label: String
    let value: String?
    var get: ((@escaping (Signal) -> Void) -> Void)? = nil
    var set: SetMode? = nil
    var enabled = true

    /// 2 where rows read from a device (GET and SET), 1 where they hold local settings (SET only).
    @Environment(\.readoutKeyColumns) private var keyColumns
    @EnvironmentObject private var entry: NumberEntry
    @State private var rowID = UUID()
    @State private var signal: Signal = .idle
    @State private var editing = false
    @State private var draft = ""
    @FocusState private var focused: Bool

    static let labelWidth: CGFloat = 170
    static let keyWidth: CGFloat = 54

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 8) {
                Text(label)
                    .font(.system(size: 12.5, weight: .medium))
                    .foregroundStyle(Color.inkDim)
                    .frame(width: Self.labelWidth, alignment: .leading)
                ReadoutWindow(signal: signal) {
                    if onKeypad {
                        Text(entry.draft.isEmpty ? " " : entry.draft)
                            .font(.system(size: 13, weight: .medium, design: .monospaced))
                            .foregroundStyle(Color.ink)
                            .overlay(alignment: .trailing) { Rectangle().fill(Color.ink).frame(width: 1.5, height: 15).offset(x: 4) }
                    } else if editing {
                        TextField(label, text: $draft)
                            .textFieldStyle(.plain)
                            .font(.system(size: 13, design: .monospaced))
                            .foregroundStyle(Color.ink)
                            .focused($focused)
                            .onSubmit(commitText)
                            .onExitCommand { editing = false }
                    } else {
                        Text(value ?? "—")
                            .font(.system(size: 13, weight: value == nil ? .regular : .medium, design: .monospaced))
                            .foregroundStyle(value == nil ? Color.silk : Color.ink)
                            .lineLimit(1).truncationMode(.middle)
                            .textSelection(.enabled)
                    }
                }
                .overlay(RoundedRectangle(cornerRadius: 4, style: .continuous).strokeBorder(Color.ink.opacity(onKeypad ? 0.85 : 0), lineWidth: 1.5))
                keys
            }
            .frame(maxWidth: 860, alignment: .leading)
            if let message = signal.message {
                Text(message)
                    .font(.system(size: 11))
                    .foregroundStyle(Color.lampFault)
                    .padding(.leading, Self.labelWidth + 8)
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(label)
        .accessibilityValue(value ?? "no value")
    }

    @ViewBuilder private var keys: some View {
        if editing {
            Button { editing = false } label: { keyLabel("Cancel") }
                .buttonStyle(.softKey).frame(minWidth: Self.keyWidth)
            Button(action: commitText) { keyLabel("Enter") }
                .buttonStyle(SoftKeyStyle(prominent: true)).frame(minWidth: Self.keyWidth)
        } else {
            if let get {
                Button { run(get) } label: { keyLabel("Get") }
                    .buttonStyle(SoftKeyStyle(lamp: signal == .pending ? .lampPending : nil, pulsing: signal == .pending))
                    .frame(minWidth: Self.keyWidth)
                    .disabled(!enabled || signal == .pending)
                    .help("Read \(label.lowercased()) from the device")
            } else if keyColumns == 2 {
                Color.clear.frame(width: Self.keyWidth, height: 1) // keeps the SET column aligned
            }
            switch set {
            case .text(let initial, _):
                Button { draft = initial; editing = true; focused = true; signal = .idle } label: { keyLabel("Set") }
                    .buttonStyle(.softKey).frame(minWidth: Self.keyWidth)
                    .disabled(!enabled || signal == .pending)
                    .help("Change \(label.lowercased())")
            case .number(let initial, let range, let unit, let commit):
                Button {
                    if onKeypad { return entry.cancel() }
                    signal = .idle
                    entry.begin(.init(id: rowID, label: label, range: range, unit: unit, commit: { text in run { done in commit(text, done) } }),
                                initial: initial)
                } label: { keyLabel("Set") }
                    .buttonStyle(SoftKeyStyle(latched: onKeypad)).frame(minWidth: Self.keyWidth)
                    .disabled(!enabled || signal == .pending)
                    .help("Enter a new \(label.lowercased()) on the keypad")
            case .choices(let names, let commit):
                Menu {
                    ForEach(names.indices, id: \.self) { i in
                        Button(names[i]) { run { done in commit(i, done) } }
                    }
                } label: {
                    Text("Set").font(.system(size: 11, weight: .semibold)).tracking(0.6).textCase(.uppercase).foregroundStyle(Color.ink)
                }
                    .menuStyle(.borderlessButton).menuIndicator(.hidden).tint(Color.ink)
                    .buttonStyle(.softKey).fixedSize()
                    .padding(.horizontal, 10).frame(width: Self.keyWidth, height: 24)
                    .background(RoundedRectangle(cornerRadius: 4, style: .continuous).fill(Color.keyFace)
                        .overlay(RoundedRectangle(cornerRadius: 4, style: .continuous)
                            .strokeBorder(LinearGradient(colors: [.white.opacity(0.12), .black.opacity(0.5)], startPoint: .top, endPoint: .bottom), lineWidth: 1))
                        .shadow(color: .black.opacity(0.5), radius: 1.5, y: 1))
                    .disabled(!enabled || signal == .pending)
                    .help("Change \(label.lowercased())")
            case nil:
                Color.clear.frame(width: Self.keyWidth, height: 1)
            }
        }
    }

    private var onKeypad: Bool { entry.target?.id == rowID }

    /// Key labels fill the key's fixed width so GET, SET and list keys line up exactly.
    private func keyLabel(_ title: String) -> some View {
        Text(title).frame(minWidth: Self.keyWidth - 20) // grows for longer words such as CANCEL
    }

    private func commitText() {
        guard case .text(_, let commit) = set else { return }
        editing = false
        let text = draft
        run { done in commit(text, done) }
    }

    private func run(_ action: (@escaping (Signal) -> Void) -> Void) {
        signal = .pending
        action { result in
            signal = result
            if result == .latched {
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) { if signal == .latched { signal = .idle } }
            }
        }
    }
}

private struct ReadoutKeyColumnsKey: EnvironmentKey { static let defaultValue = 2 }

extension EnvironmentValues {
    /// How many key columns ReadoutRows reserve on this screen.
    var readoutKeyColumns: Int {
        get { self[ReadoutKeyColumnsKey.self] }
        set { self[ReadoutKeyColumnsKey.self] = newValue }
    }
}

/// Gives a container the faceplate ground and the dark appearance the instrument is drawn for.
struct FaceplateBackground: ViewModifier {
    func body(content: Content) -> some View {
        content
            .background(Color.faceplate)
            .preferredColorScheme(.dark)
            .tint(.lampLatch)
    }
}

extension View {
    func faceplate() -> some View { modifier(FaceplateBackground()) }

    /// Drops the system's blue focus ring where the control draws its own focus state (macOS 14+).
    @ViewBuilder func noFocusRing() -> some View {
        if #available(macOS 14, *) { focusEffectDisabled() } else { self }
    }
}
