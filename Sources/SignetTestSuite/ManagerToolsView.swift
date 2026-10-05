import SwiftUI

/// Protocol-level tools: any TID on any endpoint, any RDM PID to any UID.
/// Nothing here is filtered or guarded beyond what the engine itself refuses.
struct ManagerToolsView: View {
    @ObservedObject var manager: Manager
    let device: ManagerDevice
    @State private var ep: UInt16 = 0
    @State private var tid: UInt16 = 0x0605
    @State private var value = ""
    @State private var rdmPort: UInt16 = 1
    @State private var uid = ""
    @State private var pid: UInt16 = 0x0060
    @State private var data = ""

    private var endpoints: [UInt16] {
        let n = device.root(0x0602).map(mgrU16) ?? 0
        return [0] + (n == 0 ? [] : Array(1...n)) + [0xFFFF]
    }
    private var families: [String] { ManagerTID.all.map(\.family).reduce(into: []) { if !$0.contains($1) { $0.append($1) } } }
    private var info: ManagerTID? { ManagerTID.byTID[tid] }

    var body: some View {
        Form {
            Section("Parameter (TID)") {
                Picker("Endpoint", selection: $ep) {
                    ForEach(endpoints, id: \.self) { e in Text(e == 0 ? "Root (0)" : e == 0xFFFF ? "All endpoints (65535)" : "Port \(e)").tag(e) }
                }
                Picker("TID", selection: $tid) {
                    ForEach(families, id: \.self) { fam in
                        Section(fam) {
                            ForEach(ManagerTID.all.filter { $0.family == fam }) { t in Text("\(t.hex)  \(t.name)").tag(t.tid) }
                        }
                    }
                }
                if let info {
                    LabeledContent("Layout", value: info.layout).font(.callout)
                    LabeledContent("Allowed", value: [info.get ? "GET" : nil, info.set ? "SET" : nil].compactMap { $0 }.joined(separator: " · ")
                        + " · " + (info.scope == "R" ? "root" : info.scope == "D" ? "ports" : "root and ports"))
                        .font(.callout)
                }
                TextField("Value for SET", text: $value, prompt: Text("labels: text · numbers: decimal or 0x · IPv4: dotted · else hex (hex: forces hex)"))
                HStack {
                    Button("GET") { manager.get(device.tuid, ep: ep, tids: [tid]) }
                        .disabled(!(info?.get ?? false) || manager.busy)
                    Button("SET") {
                        guard let v = ManagerTID.parse(tid, value) else { return }
                        manager.set(device.tuid, ep: ep, tlvs: [ManagerTLV(tid: tid, value: v)])
                    }
                    .disabled(!(info?.set ?? false) || manager.busy || ManagerTID.parse(tid, value) == nil)
                    if tid == 0x0401 || tid == 0x060A || (0x0502...0x0505).contains(tid) || (0x0581...0x0584).contains(tid) {
                        Label("This can wipe, reboot or re-address the device", systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange).font(.callout)
                    }
                }
            }
            Section("RDM (PID)") {
                Picker("Port", selection: $rdmPort) { ForEach(endpoints.filter { $0 != 0 && $0 != 0xFFFF }, id: \.self) { Text("Port \($0)").tag($0) } }
                Picker("Fixture UID", selection: $uid) {
                    Text("—").tag("")
                    ForEach((device.tod[rdmPort] ?? []).map(Identity.hex), id: \.self) { Text($0).tag($0) }
                }
                Picker("PID", selection: $pid) {
                    ForEach(ManagerRDM.pids.sorted { $0.key < $1.key }, id: \.key) { Text(String(format: "0x%04X  %@", $0.key, $0.value)).tag($0.key) }
                }
                TextField("Data for SET", text: $data, prompt: Text("text for DEVICE_LABEL, else hex"))
                HStack {
                    Button("Read fixture list") { manager.requestToD(device.tuid, ep: rdmPort) }.disabled(manager.busy)
                    Button("GET") { sendRDM(set: false) }.disabled(uid.isEmpty || manager.busy)
                    Button("SET") { sendRDM(set: true) }.disabled(uid.isEmpty || manager.busy)
                }
            }
            Section("Last result") {
                Text(manager.result.isEmpty ? "—" : manager.result).font(.callout.monospaced()).textSelection(.enabled)
                if !device.rdm.isEmpty {
                    DisclosureGroup("RDM responses (\(device.rdm.count))") {
                        ForEach(device.rdm.reversed(), id: \.self) { Text($0).font(.caption.monospaced()).textSelection(.enabled) }
                    }
                }
            }
        }
        .formStyle(.grouped)
    }

    private func sendRDM(set: Bool) {
        guard let dest = mgrBytes(hex: uid) else { return }
        let pd = !set ? [] : (pid == 0x0082 ? Array(data.utf8.prefix(32)) : mgrBytes(hex: data) ?? [])
        manager.rdm(device.tuid, ep: rdmPort, dest: dest, set: set, pid: pid, pd: pd)
    }
}
