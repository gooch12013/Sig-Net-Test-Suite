import SwiftUI

/// What we've learned about each RDM fixture, kept across tab switches.
final class FixtureStore: ObservableObject {
    struct Fixture {
        var label = "", software = ""
        var model: UInt16?, category: UInt16?, footprint: UInt16?, start: UInt16?, sensors: UInt8?
        var personality: String?
        var identify = false
    }
    @Published var byUID: [String: Fixture] = [:]
}

/// RDM fixtures behind a port: discover them, then identify, rename or re-address one.
struct ManagerFixturesView: View {
    @ObservedObject var manager: Manager
    let device: ManagerDevice
    @ObservedObject var store: FixtureStore
    @State private var port: UInt16 = 1
    @State private var uid: String?
    @State private var note = ""

    /// Ports that can carry RDM (capability bit 2 or 3); all ports when unknown.
    private var ports: [UInt16] {
        let n = device.root(0x0602).map(mgrU16) ?? 0
        let all = n == 0 ? [UInt16(1)] : Array(1...n)
        let rdm = all.filter { (device.params[$0]?[0x0904].map { mgrU32($0) & 0x0C != 0 }) ?? true }
        return rdm.isEmpty ? all : rdm
    }
    private var uids: [String] { (device.tod[port] ?? []).map(Identity.hex) }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                if ports.count > 1 {
                    Picker("Port", selection: $port) { ForEach(ports, id: \.self) { Text("Port \($0)").tag($0) } }
                        .pickerStyle(.segmented).fixedSize()
                } else {
                    Text("Port \(port)").font(.headline)
                }
                Button("Discover fixtures", action: discover).disabled(manager.busy)
                    .help("Clears the port's fixture list and runs full RDM discovery, then reads the list")
                Button("Reload list", action: loadList).disabled(manager.busy)
                Text(note).font(.caption).foregroundStyle(.secondary)
                Spacer()
            }
            HSplitView {
                List(uids, id: \.self, selection: $uid) { u in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(store.byUID[u]?.label.isEmpty == false ? store.byUID[u]!.label : "Fixture").fontWeight(.medium)
                        Text(ManagerRDM.uid(mgrBytes(hex: u) ?? [0, 0, 0, 0, 0, 0])).font(.caption.monospaced()).foregroundStyle(.secondary)
                    }
                    .tag(u)
                }
                .overlay { if uids.isEmpty { Text("No fixtures listed. Press Discover fixtures.").foregroundStyle(.secondary).padding() } }
                .frame(minWidth: 180, idealWidth: 220, maxWidth: 280)
                Group {
                    if let uid { ManagerFixtureDetail(manager: manager, device: device, port: port, uid: uid, store: store) }
                    else { Text("Select a fixture").foregroundStyle(.secondary).frame(maxWidth: .infinity, maxHeight: .infinity) }
                }
                .frame(minWidth: 300, maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .onAppear {
            if !ports.contains(port) { port = ports.first ?? 1 }
            if uids.isEmpty, !manager.busy { loadList() }
        }
        .onChange(of: port) { _ in uid = nil; if uids.isEmpty { loadList() } }
        .onChange(of: uids) { list in if uid == nil || !list.contains(uid!) { uid = list.first } }
    }

    private func loadList() {
        note = "Reading fixture list…"
        manager.requestToD(device.tuid, ep: port) { r in note = r.ok ? "" : "No fixture list from the device" }
    }

    /// TOD_CONTROL 1 gets no reply (§10.5), so give the device time to rediscover the line, then read the list.
    private func discover() {
        note = "Discovering…"
        manager.flushToD(device.tuid, ep: port)
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) { loadList() }
    }
}

private struct ManagerFixtureDetail: View {
    @ObservedObject var manager: Manager
    let device: ManagerDevice
    let port: UInt16
    let uid: String
    @ObservedObject var store: FixtureStore
    @State private var labelDraft = ""
    @State private var startDraft = ""
    @State private var note = ""

    private var f: FixtureStore.Fixture { store.byUID[uid] ?? .init() }

    var body: some View {
        Form {
            Section("Fixture") {
                LabeledContent("Label") {
                    HStack {
                        TextField("Label", text: $labelDraft).labelsHidden().frame(maxWidth: 220).onSubmit(saveLabel)
                        Button("Save", action: saveLabel).disabled(labelDraft == f.label || manager.busy)
                    }
                }
                LabeledContent("DMX start address") {
                    HStack {
                        TextField("1–512", text: $startDraft).labelsHidden().frame(width: 70).onSubmit(saveStart)
                        Button("Save", action: saveStart)
                            .disabled(UInt16(startDraft).map { !(1...512).contains($0) || $0 == f.start } ?? true || manager.busy)
                    }
                }
                Toggle("Identify", isOn: Binding(get: { f.identify }, set: { on in
                    rdm(set: true, pid: 0x1000, pd: [on ? 1 : 0]) { ok in if ok { store.byUID[uid, default: .init()].identify = on } }
                }))
                .disabled(manager.busy)
            }
            Section("Details") {
                LabeledContent("Personality", value: f.personality ?? "—")
                LabeledContent("Channels used", value: f.footprint.map(String.init) ?? "—")
                LabeledContent("Software", value: f.software.isEmpty ? "—" : f.software)
                LabeledContent("Model ID", value: f.model.map { String(format: "0x%04X", $0) } ?? "—")
                LabeledContent("Category", value: f.category.map { String(format: "0x%04X", $0) } ?? "—")
                LabeledContent("Sensors", value: f.sensors.map(String.init) ?? "—")
                LabeledContent("UID", value: ManagerRDM.uid(mgrBytes(hex: uid) ?? [0, 0, 0, 0, 0, 0]))
            }
            Section {
                HStack {
                    Button("Reload", action: load).disabled(manager.busy)
                    Text(note).font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .formStyle(.grouped)
        .textSelection(.enabled)
        .onAppear(perform: load)
        .onChange(of: uid) { _ in load() }
    }

    /// DEVICE_INFO, DEVICE_LABEL, SOFTWARE_VERSION_LABEL, one after the other (one transaction at a time).
    private func load() {
        labelDraft = f.label
        startDraft = f.start.map(String.init) ?? ""
        note = "Reading…"
        get(0x0060) { pd in
            if pd.count >= 19 {
                store.byUID[uid, default: .init()].model = mgrU16(pd[2...])
                store.byUID[uid, default: .init()].category = mgrU16(pd[4...])
                store.byUID[uid, default: .init()].footprint = mgrU16(pd[10...])
                store.byUID[uid, default: .init()].personality = "\(pd[12]) of \(pd[13])"
                store.byUID[uid, default: .init()].start = mgrU16(pd[14...])
                store.byUID[uid, default: .init()].sensors = pd[18]
                startDraft = "\(mgrU16(pd[14...]))"
            }
            get(0x0082) { pd in
                store.byUID[uid, default: .init()].label = String(decoding: pd, as: UTF8.self)
                labelDraft = store.byUID[uid]?.label ?? ""
                get(0x00C0) { pd in
                    store.byUID[uid, default: .init()].software = String(decoding: pd, as: UTF8.self)
                    note = ""
                }
            }
        }
    }

    private func saveLabel() {
        rdm(set: true, pid: 0x0082, pd: Array(labelDraft.utf8.prefix(32))) { ok in
            if ok { store.byUID[uid, default: .init()].label = labelDraft }
        }
    }

    private func saveStart() {
        guard let a = UInt16(startDraft), (1...512).contains(a) else { return }
        rdm(set: true, pid: 0x00F0, pd: mgrBE16(a)) { ok in if ok { store.byUID[uid, default: .init()].start = a } }
    }

    /// GET a PID and hand back its parameter data on ACK.
    private func get(_ pid: UInt16, then: @escaping ([UInt8]) -> Void) {
        guard let dest = mgrBytes(hex: uid) else { return }
        manager.rdm(device.tuid, ep: port, dest: dest, set: false, pid: pid) { r in
            guard let pd = ack(r) else { note = "No answer for \(ManagerRDM.pids[pid] ?? String(format: "PID 0x%04X", pid))"; return }
            then(pd)
        }
    }

    private func rdm(set: Bool, pid: UInt16, pd: [UInt8], done: @escaping (Bool) -> Void) {
        guard let dest = mgrBytes(hex: uid) else { return }
        note = "Sending…"
        manager.rdm(device.tuid, ep: port, dest: dest, set: set, pid: pid, pd: pd) { r in
            let ok = ack(r) != nil
            note = ok ? "Done" : (r.ok ? "Fixture declined: \(ManagerRDM.describe(r.frame))" : r.text)
            done(ok)
        }
    }

    /// Parameter data of an ACK response, or nil (NACK, timeout, bad frame).
    private func ack(_ r: ManagerResult) -> [UInt8]? {
        guard r.ok, ManagerRDM.valid(r.frame), r.frame[16] == 0 else { return nil }
        return Array(r.frame.dropFirst(24).prefix(Int(r.frame[23])))
    }
}
