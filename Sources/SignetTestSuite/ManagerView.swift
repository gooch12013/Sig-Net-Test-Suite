import SwiftUI

/// Manager tab: start, find devices, pick one, then work with it.
/// Protocol-level controls live under Advanced (polls) and the Tools tab (raw TIDs/PIDs).
struct ManagerView: View {
    @ObservedObject var manager: Manager
    @ObservedObject private var settings: SecuritySettings
    @StateObject private var fixtures = FixtureStore()
    @State private var selected: String?
    @State private var tab = Snapshot.arg("--manager-tab") ?? "Overview"
    @State private var showAdvanced = false

    init(manager: Manager) {
        self.manager = manager
        settings = manager.settings
    }

    private var devices: [ManagerDevice] {
        manager.devices.values.sorted { ManagerLabels.displayName($0).localizedStandardCompare(ManagerLabels.displayName($1)) == .orderedAscending }
    }
    private var device: ManagerDevice? { selected.flatMap { manager.devices[$0] } }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            topBar
            if showAdvanced { ManagerAdvancedBar(manager: manager, selected: selected) }
            HSplitView {
                deviceList.frame(minWidth: 210, idealWidth: 240, maxWidth: 320)
                Group {
                    if let device {
                        ManagerDeviceDetail(manager: manager, device: device, fixtures: fixtures, tab: $tab)
                    } else {
                        placeholder(manager.running ? "Select a device" : "Start the Manager to find devices",
                                    detail: manager.running ? nil : "Uses the security settings above.")
                    }
                }
                .frame(minWidth: 460, maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .onAppear(perform: selectFirstIfNeeded)
        .onChange(of: manager.devices.count) { _ in selectFirstIfNeeded() }
    }

    private func selectFirstIfNeeded() {
        if selected == nil || manager.devices[selected!] == nil { selected = devices.first?.id }
    }

    private var topBar: some View {
        HStack(spacing: 12) {
            if manager.running {
                Button("Stop") { manager.stop() }
            } else {
                Button("Start Manager") { manager.start() }
                    .buttonStyle(.borderedProminent)
                    .disabled(!settings.ready)
                ManagerInterfacePicker(manager: manager)
            }
            Button("Find devices") { manager.poll(level: 2, ep: 0xFFFF) }
                .disabled(!manager.running)
                .help("Broadcast poll at full detail")
            Text(manager.running ? manager.status : "Stopped")
                .font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            Spacer()
            Toggle("Advanced", isOn: $showAdvanced).toggleStyle(.button)
        }
    }

    private var deviceList: some View {
        List(devices, selection: $selected) { d in
            HStack(alignment: .top, spacing: 8) {
                Circle().fill(statusColor(d)).frame(width: 8, height: 8).padding(.top, 5)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(ManagerLabels.displayName(d)).fontWeight(.medium)
                    Text([d.model, d.ip].filter { !$0.isEmpty }.joined(separator: " · "))
                        .font(.caption).foregroundStyle(.secondary)
                    if !d.anomaly.isEmpty { Text("Needs attention").font(.caption).foregroundStyle(.red) }
                }
            }
            .padding(.vertical, 2)
            .accessibilityElement(children: .combine)
            .accessibilityValue(d.state)
            .tag(d.id)
        }
        .overlay {
            if devices.isEmpty {
                placeholder(manager.running ? "No devices yet" : "Not running",
                            detail: manager.running ? "Press Find devices, or check the interface and passphrase." : nil)
            }
        }
        .accessibilityLabel("Devices")
    }

    private func placeholder(_ title: String, detail: String?) -> some View {
        VStack(spacing: 6) {
            Text(title).font(.headline).foregroundStyle(.secondary)
            if let detail { Text(detail).font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center) }
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

func statusColor(_ d: ManagerDevice) -> Color {
    if !d.anomaly.isEmpty { return .red }
    if d.state.hasPrefix("Online") { return .green }
    if d.state == "Beacon" { return .gray }
    return .orange
}

/// Local IPv4 interfaces for multicast; "Automatic" leaves it to the OS.
private struct ManagerInterfacePicker: View {
    @ObservedObject var manager: Manager
    private let interfaces = localIPv4Interfaces()

    var body: some View {
        Picker("Network", selection: $manager.interface) {
            Text("Automatic").tag("")
            ForEach(interfaces, id: \.ip) { Text("\($0.name) · \($0.ip)").tag($0.ip) }
            if !manager.interface.isEmpty, !interfaces.contains(where: { $0.ip == manager.interface }) {
                Text(manager.interface).tag(manager.interface)
            }
        }
        .frame(maxWidth: 240)
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

/// Poll options and engine switches most people never need.
private struct ManagerAdvancedBar: View {
    @ObservedObject var manager: Manager
    let selected: String?
    @State private var kind = "Broadcast"
    @State private var level: UInt8 = 2
    @State private var lo = "000000000000"
    @State private var hi = "FFFFFFFFFFFF"
    @State private var ep = "65535"

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 16) {
                    Toggle("Heartbeat poll every 3 s", isOn: $manager.heartbeat)
                    Toggle("Send commands by unicast", isOn: $manager.unicast)
                        .help("Off: commands go to multicast 239.254.255.251. Retries always go multicast.")
                }
                HStack {
                    Picker("Poll", selection: $kind) {
                        ForEach(["Broadcast", "Range", "Selected device"], id: \.self) { Text($0) }
                    }
                    .frame(width: 210)
                    if kind == "Range" {
                        TextField("From TUID", text: $lo).frame(width: 120).font(.body.monospaced())
                        TextField("To TUID", text: $hi).frame(width: 120).font(.body.monospaced())
                    }
                    Picker("Detail", selection: $level) {
                        Text("Heartbeat").tag(UInt8(0)); Text("Config").tag(UInt8(1))
                        Text("Full").tag(UInt8(2)); Text("Extended").tag(UInt8(3))
                    }
                    .frame(width: 170)
                    TextField("Endpoint", text: $ep).frame(width: 70).help("0 root, 65535 all endpoints")
                    Button("Send poll", action: send).disabled(!manager.running || (kind == "Selected device" && selected == nil))
                }
            }
            .padding(4)
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

/// Header plus Overview / Settings / Fixtures / Traffic / Tools for one device.
private struct ManagerDeviceDetail: View {
    @ObservedObject var manager: Manager
    let device: ManagerDevice
    @ObservedObject var fixtures: FixtureStore
    @Binding var tab: String

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(ManagerLabels.displayName(device)).font(.title2.weight(.semibold))
                    Text([device.model, device.ip, device.id].filter { !$0.isEmpty }.joined(separator: " · "))
                        .font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                }
                Spacer()
                Label(device.state, systemImage: "circle.fill")
                    .labelStyle(.titleAndIcon).font(.callout)
                    .foregroundStyle(statusColor(device))
                authBadge
            }
            if !device.anomaly.isEmpty {
                Label(device.anomaly, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red).textSelection(.enabled)
            }
            Picker("View", selection: $tab) {
                ForEach(["Overview", "Settings", "Fixtures", "Traffic", "Tools"], id: \.self) { Text($0) }
            }
            .pickerStyle(.segmented).labelsHidden()
            switch tab {
            case "Settings": ManagerSettingsView(manager: manager, device: device)
            case "Fixtures": ManagerFixturesView(manager: manager, device: device, store: fixtures)
            case "Traffic": ManagerTrafficView(manager: manager, device: device)
            case "Tools": ManagerToolsView(manager: manager, device: device)
            default: ManagerOverviewView(manager: manager, device: device)
            }
        }
        .padding(.leading, 8)
    }

    private var authBadge: some View {
        let (text, icon, color): (String, String, Color) = switch device.auth {
        case "OK": ("Verified", "lock.fill", .green)
        case let a where a.hasPrefix("Open"): ("Unauthenticated", "lock.open.fill", .orange)
        case let a where a.hasPrefix("none"): ("Beacon", "dot.radiowaves.left.and.right", .gray)
        case "": ("—", "lock", .secondary)
        default: ("Check failed", "lock.trianglebadge.exclamationmark.fill", .red)
        }
        return Label(text, systemImage: icon).font(.callout).foregroundStyle(color)
            .help("Last reply: \(device.auth)")
    }
}

private struct ManagerOverviewView: View {
    @ObservedObject var manager: Manager
    let device: ManagerDevice
    @State private var events: [ManagerTLV] = []
    @State private var eventsNote = ""

    var body: some View {
        Form {
            Section("Device") {
                row(0x060B); row(0x0605); row(0x0604); row(0x0609); row(0x0602)
            }
            Section("Connection") {
                LabeledContent("Address", value: device.ip.isEmpty ? "—" : device.ip)
                LabeledContent("Authentication", value: ManagerLabels.auth(device.auth))
                LabeledContent("Last seen", value: device.lastSeen.formatted(.relative(presentation: .named)))
                LabeledContent("Change count", value: device.changeCount.map(String.init) ?? "—")
                    .help("Goes up each time a saved setting changes")
            }
            Section("Health") {
                row(0x0608)
                LabeledContent("Security events") {
                    VStack(alignment: .trailing, spacing: 2) {
                        if events.isEmpty { Text(eventsNote.isEmpty ? "—" : eventsNote).foregroundStyle(.secondary) }
                        ForEach(events, id: \.self) { e in
                            let code = mgrU16(e.value), count = mgrU32(e.value.dropFirst(2))
                            Text("\(ManagerLabels.eventNames[code] ?? String(format: "Code 0x%04X", code)): \(count)")
                                .foregroundStyle(count > 0 ? .orange : .secondary)
                        }
                    }
                }
            }
            Section("Identifiers") {
                LabeledContent("TUID", value: device.id)
                LabeledContent("SoemCode", value: String(format: "0x%08X", device.soem))
                row(0x0603)
            }
            Section {
                HStack {
                    Button("Refresh") { refresh() }.disabled(manager.busy)
                    Button("Check security events") { loadEvents() }.disabled(manager.busy)
                    Spacer()
                    Button("Forget device", role: .destructive) { manager.forget(device.id) }
                        .help("Drop it from the list and clear its replay state, e.g. after it was re-keyed")
                }
            }
        }
        .formStyle(.grouped)
        .textSelection(.enabled)
        .onAppear { if events.isEmpty, !manager.busy { loadEvents() } }
    }

    private func row(_ tid: UInt16) -> some View {
        LabeledContent(ManagerLabels.title(tid), value: device.root(tid).map { ManagerLabels.value(tid, $0) } ?? "—")
    }

    private func refresh() {
        manager.poll(lo: device.tuid, hi: device.tuid, level: 3, ep: 0xFFFF, to: manager.unicast ? device.ip : nil)
    }

    private func loadEvents() {
        eventsNote = "Checking…"
        manager.get(device.tuid, ep: 0, tids: [0xFF01]) { r in
            events = r.tlvs.filter { $0.tid == 0xFF01 && $0.value.count >= 6 }
            eventsNote = r.ok ? (events.isEmpty ? "None reported" : "") : "Not supported or no reply"
        }
    }
}

private struct ManagerTrafficView: View {
    @ObservedObject var manager: Manager
    let device: ManagerDevice
    @State private var everything = false

    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Toggle("Show all devices", isOn: $everything)
                Spacer()
                Button("Clear") { manager.clearLog() }
            }
            List(manager.log.reversed().filter { everything || $0.sender.hasPrefix(device.id) || $0.uri.contains(device.id) }) { e in
                DisclosureGroup {
                    Text(e.tlvs).font(.caption.monospaced())
                    Text("\(e.peer) · \(e.sender) · \(e.mode) · \(e.lane)").font(.caption.monospaced()).foregroundStyle(.secondary)
                    Text(e.hex).font(.caption2.monospaced()).foregroundStyle(.secondary)
                } label: {
                    HStack(spacing: 8) {
                        Text(e.time.formatted(date: .omitted, time: .standard)).monospacedDigit().foregroundStyle(.secondary)
                        Image(systemName: e.tx ? "arrow.up.right" : "arrow.down.left")
                            .foregroundStyle(e.tx ? Color.sigNet : .primary)
                            .accessibilityLabel(e.tx ? "Sent" : "Received")
                        Text(e.uri.split(separator: "/").dropFirst(3).joined(separator: "/")).font(.callout.monospaced())
                        Text(e.tlvs).lineLimit(1).foregroundStyle(.secondary)
                        Spacer()
                        if !e.tx { Text(e.auth).font(.caption).foregroundStyle(trafficAuthColor(e.auth)) }
                    }
                    .font(.callout)
                }
                .textSelection(.enabled)
            }
        }
    }
}

private func trafficAuthColor(_ auth: String) -> Color {
    auth == "OK" ? .green : (auth.hasPrefix("FAIL") || auth.hasPrefix("REPLAY") || auth.hasPrefix("MAL")) ? .red : .secondary
}
