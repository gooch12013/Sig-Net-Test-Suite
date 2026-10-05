import SigNet
import SwiftUI

/// Debug: the one place protocol codes, hex and packets appear.
/// Packets is the traffic log for this device; Raw commands sends any parameter or RDM PID.
struct ManagerDebugView: View {
    @ObservedObject var manager: Manager
    let device: ManagerDevice
    @State private var mode = "packets"

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            ModeKeys(options: [("packets", "Packets"), ("raw", "Raw commands")], selection: $mode)
            if mode == "raw" { ManagerRawCommands(manager: manager, device: device) } else { ManagerPackets(manager: manager, device: device) }
        }
    }
}

private struct ManagerPackets: View {
    @ObservedObject var manager: Manager
    let device: ManagerDevice
    @State private var everything = false

    private var entries: [ManagerLogEntry] {
        manager.log.reversed().filter { everything || $0.sender.hasPrefix(device.id) || $0.uri.contains(device.id) }
    }

    var body: some View {
        ModulePanel("Packets") {
            Toggle("All devices", isOn: $everything).font(.system(size: 11.5)).foregroundStyle(Color.inkDim)
            Button("Clear") { manager.clearLog() }.buttonStyle(.softKey)
        } content: {
            if entries.isEmpty { Text("No packets yet.").font(.system(size: 12)).foregroundStyle(Color.silk) }
            LazyVStack(alignment: .leading, spacing: 2) {
                ForEach(entries.prefix(300)) { e in
                    DisclosureGroup {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(e.tlvs).foregroundStyle(Color.ink)
                            Text("\(e.peer)  \(e.sender)  \(e.mode)  \(e.lane)").foregroundStyle(Color.silk)
                            Text(e.hex).foregroundStyle(Color.silk).lineLimit(nil)
                        }
                        .font(.system(size: 11, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(.vertical, 4)
                    } label: {
                        HStack(spacing: 10) {
                            Text(e.time.formatted(date: .omitted, time: .standard)).foregroundStyle(Color.silk)
                            Image(systemName: e.tx ? "arrow.up.right" : "arrow.down.left")
                                .foregroundStyle(e.tx ? Color.lampLatch : Color.inkDim)
                                .accessibilityLabel(e.tx ? "Sent" : "Received")
                            Text(e.uri.split(separator: "/").dropFirst(3).joined(separator: "/")).foregroundStyle(Color.ink)
                            Text(e.tlvs).foregroundStyle(Color.silk).lineLimit(1)
                            Spacer()
                            if !e.tx {
                                Lamp(color: e.auth == "OK" ? .lampLatch : (e.auth.hasPrefix("FAIL") || e.auth.hasPrefix("REPLAY") || e.auth.hasPrefix("MAL")) ? .lampFault : nil, size: 6)
                                Text(e.auth).foregroundStyle(Color.silk)
                            }
                        }
                        .font(.system(size: 11.5, design: .monospaced))
                    }
                    .padding(.vertical, 3)
                    Divider().overlay(Color.black.opacity(0.4))
                }
            }
        }
    }
}

/// Any parameter on any endpoint, any RDM PID to any fixture. Nothing is filtered here.
private struct ManagerRawCommands: View {
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
    private var dangerous: Bool { tid == 0x0401 || tid == 0x060A || (0x0502...0x0505).contains(tid) || (0x0581...0x0584).contains(tid) }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            ModulePanel("Parameter") {
                field("Endpoint") {
                    Picker("Endpoint", selection: $ep) {
                        ForEach(endpoints, id: \.self) { e in Text(e == 0 ? "Root (0)" : e == 0xFFFF ? "All (65535)" : "Port \(e)").tag(e) }
                    }.labelsHidden()
                }
                field("Parameter") {
                    Picker("Parameter", selection: $tid) {
                        ForEach(families, id: \.self) { fam in
                            Section(fam) { ForEach(ManagerTID.all.filter { $0.family == fam }) { t in Text("\(t.hex)  \(t.name)").tag(t.tid) } }
                        }
                    }.labelsHidden()
                }
                if let info {
                    field("Layout") { Text(info.layout).foregroundStyle(Color.inkDim) }
                }
                field("Value") {
                    TextField("labels: text · numbers: decimal or 0x · IPv4: dotted · else hex", text: $value)
                }
                HStack(spacing: 8) {
                    Spacer().frame(width: ReadoutRow.labelWidth)
                    Button("Get") { manager.get(device.tuid, ep: ep, tids: [tid]) }.buttonStyle(.softKey)
                        .disabled(!(info?.get ?? false) || manager.busy)
                    Button("Set") {
                        guard let v = ManagerTID.parse(tid, value) else { return }
                        manager.set(device.tuid, ep: ep, tlvs: [ManagerTLV(tid: tid, value: v)])
                    }
                    .buttonStyle(SoftKeyStyle(lamp: dangerous ? .lampFault : nil))
                    .disabled(!(info?.set ?? false) || manager.busy || ManagerTID.parse(tid, value) == nil)
                    if dangerous {
                        Text("Can wipe, reboot or re-address the device").font(.system(size: 11)).foregroundStyle(Color.lampFault)
                    }
                }
            }
            ModulePanel("RDM") {
                field("Port") {
                    Picker("Port", selection: $rdmPort) { ForEach(endpoints.filter { $0 != 0 && $0 != 0xFFFF }, id: \.self) { Text("Port \($0)").tag($0) } }.labelsHidden()
                }
                field("Fixture") {
                    Picker("Fixture", selection: $uid) {
                        Text("—").tag("")
                        ForEach((device.tod[rdmPort] ?? []).map(Identity.hex), id: \.self) { Text($0).tag($0) }
                    }.labelsHidden()
                }
                field("PID") {
                    Picker("PID", selection: $pid) {
                        ForEach(ManagerRDM.pids.sorted { $0.key < $1.key }, id: \.key) { Text(String(format: "%04X  %@", $0.key, $0.value)).tag($0.key) }
                    }.labelsHidden()
                }
                field("Data") { TextField("text for DEVICE_LABEL, else hex", text: $data) }
                HStack(spacing: 8) {
                    Spacer().frame(width: ReadoutRow.labelWidth)
                    Button("Read fixture list") { manager.requestToD(device.tuid, ep: rdmPort) }.buttonStyle(.softKey).disabled(manager.busy)
                    Button("Get") { sendRDM(set: false) }.buttonStyle(.softKey).disabled(uid.isEmpty || manager.busy)
                    Button("Set") { sendRDM(set: true) }.buttonStyle(.softKey).disabled(uid.isEmpty || manager.busy)
                }
            }
            ModulePanel("Last result") {
                ReadoutWindow { Text(manager.result.isEmpty ? "—" : manager.result).font(.system(size: 12, design: .monospaced)).foregroundStyle(Color.ink).textSelection(.enabled).padding(.vertical, 6) }
                if !device.rdm.isEmpty {
                    DisclosureGroup("RDM responses (\(device.rdm.count))") {
                        ForEach(device.rdm.reversed(), id: \.self) { Text($0).font(.system(size: 11, design: .monospaced)).foregroundStyle(Color.inkDim).textSelection(.enabled) }
                    }
                    .font(.system(size: 12)).foregroundStyle(Color.inkDim)
                }
            }
        }
        .font(.system(size: 12, design: .monospaced))
    }

    private func field<C: View>(_ label: String, @ViewBuilder _ content: () -> C) -> some View {
        HStack(spacing: 8) {
            Text(label).font(.system(size: 12.5, weight: .medium)).foregroundStyle(Color.inkDim).frame(width: ReadoutRow.labelWidth, alignment: .leading)
            content()
            Spacer(minLength: 0)
        }
    }

    private func sendRDM(set: Bool) {
        guard let dest = mgrBytes(hex: uid) else { return }
        let pd = !set ? [] : (pid == 0x0082 ? Array(data.utf8.prefix(32)) : mgrBytes(hex: data) ?? [])
        manager.rdm(device.tuid, ep: rdmPort, dest: dest, set: set, pid: pid, pd: pd)
    }
}
