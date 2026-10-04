import SwiftUI

struct ManagerView: View {
    @ObservedObject var manager: Manager
    @ObservedObject private var settings: SecuritySettings
    @State private var selected: String?
    @State private var tab = "Info"
    @State private var pollKind = "Broadcast"
    @State private var level: UInt8 = 2
    @State private var lo = "000000000000"
    @State private var hi = "FFFFFFFFFFFF"
    @State private var pollEP = "65535"

    init(manager: Manager) {
        self.manager = manager
        settings = manager.settings
    }

    private var device: ManagerDevice? { selected.flatMap { manager.devices[$0] } }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Button(manager.running ? "Stop" : "Start") { manager.running ? manager.stop() : manager.start() }
                    .disabled(!manager.running && !settings.ready)
                Toggle("Heartbeat poll (3 s)", isOn: $manager.heartbeat)
                Toggle("Unicast commands", isOn: $manager.unicast)
                    .help("Off: send to 239.254.255.251. Retries always go multicast.")
                TextField("Interface IPv4 (default)", text: $manager.interface)
                    .frame(width: 170).disabled(manager.running)
            }
            Text(manager.status).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
            pollBar.disabled(!manager.running)
            HSplitView {
                List(manager.devices.values.sorted { $0.id < $1.id }, selection: $selected) { d in
                    VStack(alignment: .leading) {
                        Text(d.id).font(.body.monospaced())
                        Text("\(d.model.isEmpty ? "?" : d.model) · \(d.state)").font(.caption)
                            .foregroundStyle(d.anomaly.isEmpty ? Color.secondary : .red)
                    }
                    .accessibilityElement(children: .combine)
                    .tag(d.id)
                }
                .frame(minWidth: 200, idealWidth: 230)
                .accessibilityLabel("Discovered devices")
                VStack(alignment: .leading) {
                    Picker("View", selection: $tab) {
                        ForEach(["Info", "Parameters", "RDM", "Log"], id: \.self) { Text($0) }
                    }
                    .pickerStyle(.segmented).labelsHidden()
                    switch tab {
                    case "Log": ManagerLogView(manager: manager, filter: selected)
                    case _ where device == nil: Text("Select a device").foregroundStyle(.secondary).frame(maxWidth: .infinity, maxHeight: .infinity)
                    case "Parameters": ManagerParamsView(manager: manager, device: device!)
                    case "RDM": ManagerRDMView(manager: manager, device: device!)
                    default: ManagerInfoView(manager: manager, device: device!)
                    }
                }
                .padding(.leading, 6)
                .frame(minWidth: 420)
            }
        }
    }

    private var pollBar: some View {
        HStack {
            Picker("Poll", selection: $pollKind) {
                ForEach(["Broadcast", "Range", "Targeted"], id: \.self) { Text($0) }
            }
            .frame(width: 170)
            if pollKind != "Broadcast" {
                TextField("TUID lo", text: $lo).frame(width: 110).font(.body.monospaced())
                if pollKind == "Range" { TextField("TUID hi", text: $hi).frame(width: 110).font(.body.monospaced()) }
            }
            Picker("Level", selection: $level) {
                Text("0 Heartbeat").tag(UInt8(0)); Text("1 Config").tag(UInt8(1))
                Text("2 Full").tag(UInt8(2)); Text("3 Extended").tag(UInt8(3))
            }
            .frame(width: 170)
            TextField("EP", text: $pollEP).frame(width: 55).help("0 root, 65535 all endpoints")
            Button("Poll") {
                let target = pollKind == "Targeted" ? (selected ?? lo) : lo
                let l = pollKind == "Broadcast" ? [UInt8](repeating: 0, count: 6) : (mgrBytes(hex: target) ?? [])
                let h = pollKind == "Broadcast" ? [UInt8](repeating: 0xFF, count: 6) : pollKind == "Targeted" ? l : (mgrBytes(hex: hi) ?? [])
                guard l.count == 6, h.count == 6 else { return }
                let ip = pollKind == "Targeted" && manager.unicast ? manager.devices[Identity.hex(l)]?.ip : nil
                manager.poll(lo: l, hi: h, level: level, ep: UInt16(pollEP) ?? 0xFFFF, to: ip)
            }
        }
    }
}

private struct ManagerInfoView: View {
    @ObservedObject var manager: Manager
    let device: ManagerDevice

    var body: some View {
        Form {
            if !device.anomaly.isEmpty { Text("⚠︎ \(device.anomaly)").foregroundStyle(.red) }
            LabeledContent("TUID", value: device.id)
            LabeledContent("IP", value: device.ip)
            LabeledContent("State", value: device.state)
            LabeledContent("Last auth", value: device.auth)
            LabeledContent("Last seen", value: device.lastSeen.formatted(date: .omitted, time: .standard))
            LabeledContent("Model", value: device.model)
            LabeledContent("Label", value: device.label)
            LabeledContent("Roles", value: device.roles)
            LabeledContent("Endpoints", value: device.text(0x0602))
            LabeledContent("Firmware", value: device.text(0x0604))
            LabeledContent("Protocol version", value: device.text(0x0603))
            LabeledContent("SoemCode", value: String(format: "0x%08X", device.soem))
            LabeledContent("CHANGE_COUNT", value: device.changeCount.map(String.init) ?? "–")
            LabeledContent("Status", value: device.text(0x0608))
            LabeledContent("OTW capability (raw)", value: device.root(0x060D).map(mgrHex) ?? "–")
            HStack {
                Button("Targeted full poll") {
                    manager.poll(lo: device.tuid, hi: device.tuid, level: 2, ep: 0xFFFF, to: manager.unicast ? device.ip : nil)
                }
                Button("Forget TUID") { manager.forget(device.id) }
                    .help("Drop the device and its replay state (after a rekey, §8.3)")
            }
        }
        .textSelection(.enabled)
    }
}

private struct ManagerParamsView: View {
    @ObservedObject var manager: Manager
    let device: ManagerDevice
    @State private var ep = "0"
    @State private var tid: UInt16? = 0x0605
    @State private var value = ""

    var body: some View {
        VStack(alignment: .leading) {
            Table(ManagerTID.all, selection: $tid) {
                TableColumn("TID", value: \.hex).width(60)
                TableColumn("Name", value: \.name)
                TableColumn("Family", value: \.family).width(70)
                TableColumn("Ops") { Text(($0.get ? "G" : "") + ($0.set ? "S" : "") + " " + $0.scope) }.width(45)
                TableColumn("Value layout", value: \.layout)
            }
            .frame(minHeight: 180)
            HStack {
                TextField("Endpoint", text: $ep).frame(width: 70).help("0 root, 1…n data, 65535 broadcast")
                TextField("SET value (labels: text, numbers: decimal/0x, IPv4: dotted, else hex; 'hex:' forces hex)", text: $value)
                Button("GET") { if let t = tid { manager.get(device.tuid, ep: UInt16(ep) ?? 0, tids: [t]) } }
                    .disabled(!(tid.flatMap { ManagerTID.byTID[$0]?.get } ?? false) || manager.busy)
                Button("SET") {
                    guard let t = tid, let v = ManagerTID.parse(t, value) else { return }
                    manager.set(device.tuid, ep: UInt16(ep) ?? 0, tlvs: [ManagerTLV(tid: t, value: v)])
                }
                .disabled(!(tid.flatMap { ManagerTID.byTID[$0]?.set } ?? false) || manager.busy
                    || tid.flatMap { ManagerTID.parse($0, value) } == nil)
            }
            Text(manager.result).font(.callout).textSelection(.enabled)
            Text("Cached values, EP \(ep)").font(.headline)
            List((device.params[UInt16(ep) ?? 0] ?? [:]).sorted { $0.key < $1.key }, id: \.key) { kv in
                Text("\(ManagerTID.name(kv.key)): \(ManagerTID.describe(kv.key, kv.value))").textSelection(.enabled)
            }
        }
    }
}

private struct ManagerRDMView: View {
    @ObservedObject var manager: Manager
    let device: ManagerDevice
    @State private var ep = "1"
    @State private var uid = ""
    @State private var pid: UInt16 = 0x0060
    @State private var data = ""

    var body: some View {
        let e = UInt16(ep) ?? 1
        VStack(alignment: .leading) {
            HStack {
                TextField("Endpoint", text: $ep).frame(width: 70)
                Button("Request ToD") { manager.requestToD(device.tuid, ep: e) }.disabled(manager.busy)
                Picker("UID", selection: $uid) {
                    Text("–").tag("")
                    ForEach((device.tod[e] ?? []).map(Identity.hex), id: \.self) { Text($0).tag($0) }
                }
                .frame(width: 220)
            }
            HStack {
                Picker("PID", selection: $pid) {
                    ForEach(ManagerRDM.pids.sorted { $0.key < $1.key }, id: \.key) { Text($0.value).tag($0.key) }
                }
                .frame(width: 260)
                TextField("SET data (text for labels, else hex)", text: $data)
                Button("GET") { send(set: false) }
                Button("SET") { send(set: true) }
            }
            .disabled(uid.isEmpty || manager.busy)
            Text(manager.result).font(.callout).textSelection(.enabled)
            Text("RDM responses seen").font(.headline)
            List(device.rdm.reversed(), id: \.self) { Text($0).font(.caption.monospaced()).textSelection(.enabled) }
        }
    }

    private func send(set: Bool) {
        guard let dest = mgrBytes(hex: uid) else { return }
        let pd = !set ? [] : (pid == 0x0082 ? Array(data.utf8.prefix(32)) : mgrBytes(hex: data) ?? [])
        manager.rdm(device.tuid, ep: UInt16(ep) ?? 1, dest: dest, set: set, pid: pid, pd: pd)
    }
}

private struct ManagerLogView: View {
    @ObservedObject var manager: Manager
    let filter: String?
    @State private var onlySelected = false

    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Toggle("Only selected device", isOn: $onlySelected).disabled(filter == nil)
                Spacer()
                Button("Clear") { manager.clearLog() }
            }
            List(manager.log.reversed().filter { !onlySelected || filter == nil || $0.sender.hasPrefix(filter!) || $0.uri.contains(filter!) }) { e in
                DisclosureGroup {
                    Text(e.tlvs).font(.caption.monospaced())
                    Text(e.hex).font(.caption2.monospaced()).foregroundStyle(.secondary)
                } label: {
                    Text("\(e.time.formatted(date: .omitted, time: .standard)) \(e.tx ? "→" : "←") \(e.peer) \(e.uri)  \(e.sender) \(e.mode) \(e.lane) auth: \(e.auth)")
                        .font(.caption.monospaced())
                        .foregroundStyle(e.auth.hasPrefix("FAIL") || e.auth.hasPrefix("REPLAY") || e.auth.hasPrefix("MAL") ? .red : .primary)
                }
                .textSelection(.enabled)
                .accessibilityLabel("\(e.tx ? "Sent" : "Received") \(e.uri), auth \(e.auth)")
            }
        }
    }
}
