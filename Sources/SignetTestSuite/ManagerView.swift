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
        settings = manager.settings
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
                ManagerInterfaceMenu(manager: manager)
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
private struct ManagerInterfaceMenu: View {
    @ObservedObject var manager: Manager
    private let interfaces = localIPv4Interfaces()

    var body: some View {
        Picker("Network", selection: $manager.interface) {
            Text("Automatic").tag("")
            ForEach(interfaces, id: \.ip) { Text("\($0.name)  \($0.ip)").tag($0.ip) }
            if !manager.interface.isEmpty, !interfaces.contains(where: { $0.ip == manager.interface }) {
                Text(manager.interface).tag(manager.interface)
            }
        }
        .labelsHidden()
        .frame(maxWidth: 200)
        .help("The network the devices are on")
    }
}

func localIPv4Interfaces() -> [(name: String, ip: String)] {
    var out: [(String, String)] = []
    var head: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&head) == 0 else { return [] }
    defer { freeifaddrs(head) }
    var p = head
    while let i = p?.pointee {
        defer { p = i.ifa_next }
        guard let sa = i.ifa_addr, sa.pointee.sa_family == UInt8(AF_INET), i.ifa_flags & UInt32(IFF_LOOPBACK) == 0 else { continue }
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(sa, socklen_t(sa.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else { continue }
        out.append((String(cString: i.ifa_name), String(cString: host)))
    }
    return out
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
    let setMode: SetMode?
    if let options = ManagerLabels.multiByteChoices[tid] {
        return ReadoutRow(label: ManagerLabels.title(tid), value: current.map { ManagerLabels.value(tid, $0) },
                          get: { done in manager.getSignal(target, ep: ep, tid: tid, done: done) },
                          set: .choices(options.map(\.1)) { i, done in manager.setSignal(target, ep: ep, tid: tid, value: options[i].0, done: done) },
                          enabled: manager.running && !manager.busy)
    }
    switch ManagerLabels.editor(tid) {
    case .choice(let options):
        setMode = .choices(options.map(\.1)) { i, done in manager.setSignal(target, ep: ep, tid: tid, value: [options[i].0], done: done) }
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
    case nil:
        setMode = nil
    }
    let gettable = ManagerTID.byTID[tid]?.get ?? false
    return ReadoutRow(label: ManagerLabels.title(tid),
                      value: current.map { ManagerLabels.value(tid, $0) },
                      get: gettable ? { done in manager.getSignal(target, ep: ep, tid: tid, done: done) } : nil,
                      set: setMode,
                      enabled: manager.running && !manager.busy)
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
