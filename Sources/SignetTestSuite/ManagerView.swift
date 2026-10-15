import AppKit
import SigNet
import SwiftUI

/// Manager: a rack of discovered devices on the left, the selected device's panel on the right.
/// Every value is a readout with GET and SET; protocol codes live only in Debug.
struct ManagerView: View {
    @ObservedObject var manager: Manager
    @ObservedObject private var settings: SecuritySettings
    @ObservedObject var fixtures: FixtureStore
    @State private var selected: String?
    @State private var tab = Snapshot.arg("--manager-tab") ?? "info"
    @State private var showPoll = false

    init(manager: Manager, fixtures: FixtureStore) {
        self.manager = manager
        self.fixtures = fixtures
        settings = manager.securitySettings
    }

    private var devices: [ManagerDevice] {
        manager.devices.values.sorted { ManagerLabels.displayName($0).localizedStandardCompare(ManagerLabels.displayName($1)) == .orderedAscending }
    }
    private var device: ManagerDevice? { selected.flatMap { manager.devices[$0] } }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            controlStrip
            if showPoll { ManagerPollModule(manager: manager, selected: selected) }
            HStack(alignment: .top, spacing: 12) {
                rack.frame(width: 240)
                Group {
                    if let device {
                        ManagerDevicePanel(manager: manager, device: device, fixtures: fixtures, tab: $tab)
                    } else {
                        emptyPanel
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            }
        }
        .onAppear(perform: selectFirstIfNeeded)
        .onChange(of: manager.devices.count) { _ in selectFirstIfNeeded() }
    }

    private func selectFirstIfNeeded() {
        if selected == nil || manager.devices[selected!] == nil { selected = devices.first?.id }
    }

    private var controlStrip: some View {
        HStack(spacing: 10) {
            if manager.running {
                Button("Stop") { manager.stop() }.buttonStyle(SoftKeyStyle(lamp: .lampOnline))
            } else {
                Button("Start Manager") { manager.start() }
                    .buttonStyle(SoftKeyStyle(prominent: true))
                    .disabled(!settings.ready)
            }
            Button("Find devices") { manager.poll(level: 2, ep: 0xFFFF) }
                .buttonStyle(.softKey)
                .disabled(!manager.running)
                .help("Ask every device on the network to report in")
            Text(manager.running ? "Running · \(settings.mode.rawValue) Mode · scope \(settings.scopeOrDefault)" : "Stopped")
                .font(.system(size: 11.5))
                .foregroundStyle(Color.silk)
                .lineLimit(1).truncationMode(.middle)
            Spacer()
            Button("Poll options") { showPoll.toggle() }
                .buttonStyle(SoftKeyStyle(lamp: showPoll ? .lampLatch : nil))
        }
    }

    private var rack: some View {
        ModulePanel("Devices") {
            Text("\(devices.count)").font(.system(size: 11, design: .monospaced)).foregroundStyle(Color.silk)
        } content: {
            if devices.isEmpty {
                Text(manager.running ? "No devices yet. Press Find devices, or check the network and passphrase." : "Start the Manager to find devices.")
                    .font(.system(size: 12)).foregroundStyle(Color.silk)
                    .frame(maxWidth: .infinity, minHeight: 80, alignment: .topLeading)
            }
            ScrollView {
                VStack(spacing: 4) {
                    ForEach(devices) { d in
                        Button { selected = d.id } label: { ManagerRackRow(device: d, selected: d.id == selected) }
                            .buttonStyle(.plain)
                            .accessibilityAddTraits(d.id == selected ? .isSelected : [])
                    }
                }
            }
        }
        .frame(maxHeight: .infinity, alignment: .top)
    }

    private var emptyPanel: some View {
        ModulePanel("Panel") {
            Text(manager.running ? "Select a device from the rack." : "Start the Manager. It uses the security settings at the top.")
                .font(.system(size: 13)).foregroundStyle(Color.inkDim)
                .frame(maxWidth: .infinity, minHeight: 120, alignment: .topLeading)
        }
    }
}

private struct ManagerRackRow: View {
    let device: ManagerDevice
    let selected: Bool

    var body: some View {
        HStack(alignment: .top, spacing: 9) {
            Lamp(color: lampColor(device)).padding(.top, 4)
            VStack(alignment: .leading, spacing: 2) {
                Text(ManagerLabels.displayName(device)).font(.system(size: 13, weight: .semibold)).foregroundStyle(Color.ink)
                Text([device.model, device.ip].filter { !$0.isEmpty }.joined(separator: "  "))
                    .font(.system(size: 10.5, design: .monospaced)).foregroundStyle(Color.silk)
                if !device.anomaly.isEmpty { Text("Needs attention").font(.system(size: 10.5)).foregroundStyle(Color.lampFault) }
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 10).padding(.vertical, 8)
        .background(
            RoundedRectangle(cornerRadius: 5, style: .continuous)
                .fill(selected ? Color.readoutWindow : Color.clear)
                .overlay(RoundedRectangle(cornerRadius: 5, style: .continuous)
                    .strokeBorder(selected ? Color.lampLatch.opacity(0.7) : Color.clear, lineWidth: 1))
        )
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityValue(device.state)
    }
}

/// Online green; lost, unreachable or suspicious red; offboarded beacons grey.
func lampColor(_ d: ManagerDevice) -> Color {
    if !d.anomaly.isEmpty { return .lampFault }
    if d.state.hasPrefix("Online") { return .lampOnline }
    if d.state == "Beacon" { return .silk }
    return .lampFault
}

/// Network interface menu; "Automatic" leaves multicast routing to the OS.
struct InterfaceMenu: View {
    @ObservedObject var settings: SecuritySettings
    @State private var interfaces = UDPSocket.interfaces()

    var body: some View {
        Picker("Network", selection: $settings.interface) {
            Text("Automatic").tag("")
            ForEach(interfaces, id: \.ip) { Text("\($0.name)  \($0.ip)").tag($0.ip) }
            if !settings.interface.isEmpty, !interfaces.contains(where: { $0.ip == settings.interface }) {
                Text("\(settings.interface) (not found)").tag(settings.interface)
            }
        }
        .labelsHidden()
        .frame(maxWidth: 200)
        .help("Network interface every device sends and joins multicast on")
        .onHover { if $0 { interfaces = UDPSocket.interfaces() } } // pick up NICs plugged in after launch
    }
}

/// Poll shapes and engine switches for protocol testing.
private struct ManagerPollModule: View {
    @ObservedObject var manager: Manager
    let selected: String?
    @State private var kind = "Broadcast"
    @State private var level: UInt8 = 2
    @State private var lo = "000000000000"
    @State private var hi = "FFFFFFFFFFFF"
    @State private var ep = "65535"

    var body: some View {
        ModulePanel("Poll options") {
            HStack(spacing: 14) {
                Toggle("Heartbeat poll every 3 s", isOn: $manager.heartbeat)
                Toggle("Send commands by unicast", isOn: $manager.unicast)
                    .help("Off: commands go to the multicast command group. Retries always go multicast.")
                Spacer()
            }
            .font(.system(size: 12)).foregroundStyle(Color.inkDim)
            HStack(spacing: 10) {
                Picker("Poll", selection: $kind) { ForEach(["Broadcast", "Range", "Selected device"], id: \.self) { Text($0) } }
                    .labelsHidden().frame(width: 150)
                if kind == "Range" {
                    TextField("From device ID", text: $lo).frame(width: 120)
                    TextField("To device ID", text: $hi).frame(width: 120)
                }
                Picker("Detail", selection: $level) {
                    Text("Heartbeat").tag(UInt8(0)); Text("Config").tag(UInt8(1)); Text("Full").tag(UInt8(2)); Text("Extended").tag(UInt8(3))
                }
                .labelsHidden().frame(width: 120)
                TextField("Endpoint", text: $ep).frame(width: 70).help("0 root, 65535 all endpoints")
                Button("Send poll", action: send).buttonStyle(.softKey)
                    .disabled(!manager.running || (kind == "Selected device" && selected == nil))
            }
            .font(.system(size: 12, design: .monospaced))
        }
    }

    private func send() {
        var l = [UInt8](repeating: 0, count: 6), h = [UInt8](repeating: 0xFF, count: 6), ip: String?
        switch kind {
        case "Range":
            guard let a = mgrBytes(hex: lo), let b = mgrBytes(hex: hi), a.count == 6, b.count == 6 else { return }
            (l, h) = (a, b)
        case "Selected device":
            guard let id = selected, let d = manager.devices[id] else { return }
            (l, h) = (d.tuid, d.tuid)
            ip = manager.unicast ? d.ip : nil
        default: break
        }
        manager.poll(lo: l, hi: h, level: level, ep: UInt16(ep) ?? 0xFFFF, to: ip)
    }
}

/// The device's display window and its four panels.
private struct ManagerDevicePanel: View {
    @ObservedObject var manager: Manager
    let device: ManagerDevice
    @ObservedObject var fixtures: FixtureStore
    @Binding var tab: String

    private var ports: [UInt16] {
        let n = device.root(0x0602).map(mgrU16) ?? 0
        return n == 0 ? [] : Array(1...n)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            display
            HStack {
                ModeKeys(options: [("info", "Info"), ("parameters", "Parameters"), ("rdm", "RDM"), ("debug", "Debug")], selection: $tab)
                Spacer()
            }
            ScrollView {
                Group {
                    switch tab {
                    case "parameters": ManagerSettingsView(manager: manager, device: device)
                    case "rdm": ManagerFixturesView(manager: manager, device: device, store: fixtures)
                    case "debug": ManagerDebugView(manager: manager, device: device)
                    default: ManagerInfoView(manager: manager, device: device)
                    }
                }
                .padding(.bottom, 12)
            }
            .scrollIndicators(.hidden) // a legacy scroller would pull the modules short of the display window's edge
        }
    }

    private var display: some View {
        HStack(alignment: .center, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text(ManagerLabels.displayName(device))
                    .font(.system(size: 22, weight: .semibold)).foregroundStyle(Color.ink)
                Text([device.model, device.ip].filter { !$0.isEmpty }.joined(separator: "   "))
                    .font(.system(size: 11.5, design: .monospaced)).foregroundStyle(Color.silk)
                    .textSelection(.enabled)
                if !device.anomaly.isEmpty {
                    Text(device.anomaly).font(.system(size: 11.5)).foregroundStyle(Color.lampFault).textSelection(.enabled)
                }
            }
            Spacer()
            indicator("Online", lampColor(device))
            indicator(device.auth == "OK" ? "Verified" : device.auth.hasPrefix("Open") ? "Open" : "Auth", authColor)
            ForEach(ports, id: \.self) { ep in
                indicator("Port \(ep)", receiving(ep) ? .lampOnline : nil)
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
        .background(
            RoundedRectangle(cornerRadius: 7, style: .continuous).fill(Color.readoutWindow)
                .overlay(RoundedRectangle(cornerRadius: 7, style: .continuous).strokeBorder(Color.black.opacity(0.7), lineWidth: 1))
                .overlay(alignment: .bottom) { Rectangle().fill(Color.brandStripe).frame(height: 2).padding(.horizontal, 1) }
                .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
        )
        .accessibilityElement(children: .combine)
    }

    private var authColor: Color? {
        switch device.auth {
        case "OK": return .lampLatch
        case "": return nil
        case let a where a.hasPrefix("Open") || a.hasPrefix("none"): return .silk
        default: return .lampFault
        }
    }

    /// EP_STATUS bit 3: the port is receiving levels.
    private func receiving(_ ep: UInt16) -> Bool {
        (device.params[ep]?[0x0907].map { mgrU32([UInt8](repeating: 0, count: max(0, 4 - $0.count)) + $0) & 0x08 != 0 }) ?? false
    }

    private func indicator(_ title: String, _ color: Color?) -> some View {
        VStack(spacing: 5) {
            Lamp(color: color, size: 10)
            Silkscreen(title)
        }
        .frame(minWidth: 46)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(title): \(color == nil ? "off" : "on")")
    }
}

// MARK: - Get/Set plumbing shared by the panels

extension Manager {
    /// GET one parameter and report it as a panel signal.
    func getSignal(_ target: [UInt8], ep: UInt16, tid: UInt16, done: @escaping (Signal) -> Void) {
        get(target, ep: ep, tids: [tid]) { r in
            done(r.tlvs.contains { $0.tid == tid } ? .latched : .silent(r.text.hasPrefix("Busy") ? "Busy with another request" : "No reply from the device"))
        }
    }

    /// SET one parameter; refusal and silence are reported differently.
    func setSignal(_ target: [UInt8], ep: UInt16, tid: UInt16, value: [UInt8], done: @escaping (Signal) -> Void) {
        set(target, ep: ep, tlvs: [ManagerTLV(tid: tid, value: value)]) { r in
            if r.ok { return done(.latched) }
            if r.text.contains("refused") { return done(.refused("The device refused this value")) }
            done(.silent(r.text.hasPrefix("Busy") ? "Busy with another request" : "No confirmation from the device"))
        }
    }
}

/// A readout row for one device parameter: plain name, decoded value, GET, and SET when the parameter allows it here.
func parameterRow(_ manager: Manager, _ device: ManagerDevice, ep: UInt16, tid: UInt16) -> ReadoutRow {
    let current = device.params[ep]?[tid]
    let target = device.tuid
    if tid >= 0x8000, tid <= 0xFF00, let m = ManufacturerTIDs.entry(esta: mgrU16(target), tid: tid) {
        return manufacturerRow(manager, device, ep: ep, tid: tid, m)
    }
    // RT_REBOOT (§11.6.10) and RT_OFFBOARD are commands, not settings: SET only (they can't be read), each with its
    // fixed magic word, and asked for first.
    if tid == 0x060A || tid == 0x0401 {
        let boot = Array("BOOT".utf8)
        let options: [(label: String, value: [UInt8], warning: String)] = tid == 0x060A
            ? [("Restart software", [0xFE] + boot, "The device restarts its software and drops off the network for a moment."),
               ("Reboot hardware", [0xFF] + boot, "The device reboots completely and is off the network until it's back up.")]
            : [("Offboard", Array("WIPE".utf8), "The device forgets its passphrase and leaves Secure mode. Devices usually only accept this shortly after power-on.")]
        return ReadoutRow(label: ManagerLabels.title(tid), value: nil,
                          set: .choices(options.map(\.label)) { i, done in
                              guard confirm("\(options[i].label)?", options[i].warning, button: options[i].label) else { return done(.refused("Cancelled")) }
                              manager.setSignal(target, ep: ep, tid: tid, value: options[i].value, done: done)
                          },
                          enabled: manager.running && !manager.busy)
    }
    let setMode: SetMode?
    if let options = ManagerLabels.multiByteChoices[tid] {
        return ReadoutRow(label: ManagerLabels.title(tid), value: current.map { ManagerLabels.value(tid, $0) },
                          get: { done in manager.getSignal(target, ep: ep, tid: tid, done: done) },
                          set: .choices(options.map(\.1)) { i, done in manager.setSignal(target, ep: ep, tid: tid, value: options[i].0, done: done) },
                          enabled: manager.running && !manager.busy)
    }
    switch ManagerLabels.editor(tid) {
    case .choice(let options):
        setMode = .choices(options.map(\.1)) { i, done in
            if tid == 0x090B, !confirmProtocol(manager, ep: ep, value: [options[i].0]) { return done(.refused("Cancelled")) }
            manager.setSignal(target, ep: ep, tid: tid, value: [options[i].0], done: done)
        }
    case .number(let r):
        setMode = .number(initial: ManagerLabels.draft(tid, current), range: Int64(r.lowerBound)...Int64(r.upperBound)) { text, done in
            guard let v = ManagerLabels.encode(tid, text) else { return done(.refused("Not a valid value for \(ManagerLabels.title(tid).lowercased())")) }
            manager.setSignal(target, ep: ep, tid: tid, value: v, done: done)
        }
    case .some:
        setMode = .text(initial: ManagerLabels.draft(tid, current)) { text, done in
            guard let v = ManagerLabels.encode(tid, text) else { return done(.refused("Not a valid value for \(ManagerLabels.title(tid).lowercased())")) }
            manager.setSignal(target, ep: ep, tid: tid, value: v, done: done)
        }
    case nil where ManagerTID.byTID[tid] == nil && tid >= 0x8000:
        // A manufacturer TID the catalogue doesn't know: raw hex both ways; the device refuses what it won't take.
        setMode = .text(initial: current.map(mgrHex) ?? "") { text, done in
            guard let v = mgrBytes(hex: text), !v.isEmpty else { return done(.refused("Enter the value as hex bytes")) }
            manager.setSignal(target, ep: ep, tid: tid, value: v, done: done)
        }
    case nil:
        setMode = nil
    }
    let gettable = ManagerTID.byTID[tid]?.get ?? (tid >= 0x8000)
    return ReadoutRow(label: ManagerLabels.title(tid),
                      value: current.map { ManagerLabels.value(tid, $0) },
                      get: gettable ? { done in manager.getSignal(target, ep: ep, tid: tid, done: done) } : nil,
                      set: setMode,
                      enabled: manager.running && !manager.busy)
}

/// A manufacturer TID named in ManufacturerTIDs: its name, and a number in its range (or raw hex) both ways.
private func manufacturerRow(_ manager: Manager, _ device: ManagerDevice, ep: UInt16, tid: UInt16, _ m: ManufacturerTIDs.Entry) -> ReadoutRow {
    let current = device.params[ep]?[tid], target = device.tuid
    let width = [1, 2, 4].contains(m.bytes ?? 1) ? m.bytes ?? 1 : 1
    let number = m.min != nil || m.max != nil
    // Unsigned, so never wider than `width` bytes hold: a max of 1000 on one byte would otherwise send 1000 & 0xFF.
    let cap = (Int64(1) << (8 * width)) - 1, lo = min(max(m.min ?? 0, 0), cap)
    let range = lo...max(lo, min(m.max ?? cap, cap))
    let decimal = { (v: [UInt8]) -> Int64? in v.count == width ? v.reduce(Int64(0)) { $0 << 8 | Int64($1) } : nil }
    // Every SET goes through here: the entry's warning first, when it has one.
    let send = { (v: [UInt8], done: @escaping (Signal) -> Void) in
        if let warning = m.confirm, v.contains(where: { $0 != 0 }), !confirm("Send \(m.name)?", warning, button: "Send") {
            return done(.refused("Cancelled"))
        }
        manager.setSignal(target, ep: ep, tid: tid, value: v, done: done)
    }
    let setMode: SetMode?
    if m.settable == false {
        setMode = nil
    } else if let choices = m.choices, !choices.isEmpty {
        setMode = .choices(choices.map(\.label)) { i, done in
            guard let v = mgrBytes(hex: choices[i].hex), !v.isEmpty else { return done(.refused("\(choices[i].label): not hex in the table")) }
            send(v, done)
        }
    } else if number {
        setMode = .number(initial: current.flatMap(decimal).map(String.init) ?? "", range: range) { text, done in
            guard let n = Int64(text), range.contains(n) else { return done(.refused("\(m.name): \(range.lowerBound)-\(range.upperBound)")) }
            send((0..<width).reversed().map { UInt8(truncatingIfNeeded: n >> (8 * $0)) }, done)
        }
    } else {
        setMode = .text(initial: current.map(mgrHex) ?? "") { text, done in
            guard let v = mgrBytes(hex: text), !v.isEmpty else { return done(.refused("Enter the value as hex bytes")) }
            send(v, done)
        }
    }
    // Named parts of the value ("Patched 3 · Unaddressed 0"), big-endian; anything left over or short stays hex.
    let described = { (v: [UInt8]) -> String? in
        guard let fields = m.fields, fields.reduce(0, { $0 + $1.bytes }) == v.count else { return nil }
        var i = 0
        return fields.map { f in
            defer { i += f.bytes }
            return "\(f.name) \(v[i..<i + f.bytes].reduce(Int64(0)) { $0 << 8 | Int64($1) })"
        }.joined(separator: " · ")
    }
    return ReadoutRow(label: m.name,
                      value: current.map { v in described(v) ?? (number ? decimal(v).map(String.init) ?? mgrHex(v) : mgrHex(v)) },
                      get: { done in manager.getSignal(target, ep: ep, tid: tid, done: done) },
                      set: setMode,
                      enabled: manager.running && !manager.busy)
}

/// §11.7.11: switching a Secure Node's port to Art-Net/sACN drops authentication from its level data, so the Manager
/// shall warn and get the operator's confirmation first. Every EP_PROTOCOL SET in the app goes through here; true = go ahead.
func confirmProtocol(_ manager: Manager, ep: UInt16, value: [UInt8]) -> Bool {
    guard (value.first ?? 0) != 0, manager.securitySettings.mode == .secure else { return true }
    let all = ep == 0xFFFF
    return confirm("Switch \(all ? "every port" : "Port \(ep)") to \(ManagerLabels.value(0x090B, value))?",
                   "Level data on \(all ? "these ports" : "this port") will no longer be authenticated: anyone on the network can drive it. Sig-Net management stays secure.",
                   button: "Switch")
}

/// A modal warning with Cancel as the default; true = the operator chose `button`.
private func confirm(_ title: String, _ detail: String, button: String) -> Bool {
    let alert = NSAlert()
    alert.alertStyle = .warning
    alert.messageText = title
    alert.informativeText = detail
    alert.addButton(withTitle: "Cancel")
    alert.addButton(withTitle: button)
    return alert.runModal() == .alertSecondButtonReturn
}

// MARK: - Info

private struct ManagerInfoView: View {
    @ObservedObject var manager: Manager
    let device: ManagerDevice
    @State private var events: [ManagerTLV] = []
    @State private var eventsChecked = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            ModulePanel("Device") {
                Button("Refresh all") {
                    manager.poll(lo: device.tuid, hi: device.tuid, level: 3, ep: 0xFFFF, to: manager.unicast ? device.ip : nil)
                }
                .buttonStyle(.softKey).disabled(!manager.running)
            } content: {
                ForEach([UInt16(0x060B), 0x0605, 0x0604, 0x0609, 0x0602, 0x0603], id: \.self) { parameterRow(manager, device, ep: 0, tid: $0) }
            }
            ModulePanel("Connection") {
                ReadoutRow(label: "Address", value: device.ip.isEmpty ? nil : device.ip)
                ReadoutRow(label: "Authentication", value: ManagerLabels.auth(device.auth))
                ReadoutRow(label: "Last reply", value: device.lastSeen.formatted(date: .omitted, time: .standard))
                ReadoutRow(label: "Change count", value: device.changeCount.map(String.init))
            }
            ModulePanel("Health") {
                parameterRow(manager, device, ep: 0, tid: 0x0608)
                if events.isEmpty {
                    ReadoutRow(label: "Security events", value: eventsChecked ? "None reported" : nil, get: loadEvents, enabled: manager.running && !manager.busy)
                }
                ForEach(events, id: \.self) { e in
                    let code = mgrU16(e.value)
                    ReadoutRow(label: ManagerLabels.eventNames[code] ?? String(format: "Event %04X", code),
                               value: "\(mgrU32(e.value.dropFirst(2)))",
                               get: loadEvents, enabled: manager.running && !manager.busy)
                }
            }
            ModulePanel("Identity") {
                Button("Forget device") { manager.forget(device.id) }
                    .buttonStyle(.softKey)
                    .help("Drop it from the rack and clear its replay state, for example after it was re-keyed")
            } content: {
                ReadoutRow(label: "Device ID", value: device.id)
                ReadoutRow(label: "Product code", value: String(format: "%08X", device.soem))
            }
        }
        .onAppear { if !eventsChecked, manager.running, !manager.busy { loadEvents { _ in } } }
    }

    private func loadEvents(_ done: @escaping (Signal) -> Void) {
        manager.get(device.tuid, ep: 0, tids: [0xFF01]) { r in
            events = r.tlvs.filter { $0.tid == 0xFF01 && $0.value.count >= 6 }
            eventsChecked = r.ok
            done(r.ok ? .latched : .silent("No reply from the device"))
        }
    }
}
