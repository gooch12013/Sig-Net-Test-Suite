import SwiftUI

/// The device's configuration as a form: one section for the device, one per port,
/// showing the cached values with inline editing for the settable ones.
struct ManagerSettingsView: View {
    @ObservedObject var manager: Manager
    let device: ManagerDevice

    private static let rootOrder: [UInt16] = [0x0605, 0x0607, 0x0606]
    private static let networkOrder: [UInt16] = [0x0501, 0x0502, 0x0503, 0x0504, 0x0505, 0x0506, 0x0581, 0x0582, 0x0583, 0x0584, 0x0585]
    private static let portOrder: [UInt16] = [0x0901, 0x0902, 0x0905, 0x090C, 0x0907, 0x090B, 0x0908, 0x0909, 0x0906, 0x0903,
                                              0x0904, 0x090A, 0x0305, 0x0306, 0xFF03]

    /// RT_SUPPORTED_TIDS when the device has reported it; otherwise show everything.
    private var supported: Set<UInt16>? {
        guard let v = device.root(0x0601) else { return nil }
        return Set(stride(from: 0, to: v.count - 1, by: 2).map { mgrU16(v[$0...]) })
    }
    private func shown(_ order: [UInt16]) -> [UInt16] { order.filter { supported?.contains($0) ?? true } }
    private var ports: [UInt16] {
        let n = device.root(0x0602).map(mgrU16) ?? UInt16(device.params.keys.filter { $0 != 0 && $0 != 0xFFFF }.count)
        return n == 0 ? [] : Array(1...n)
    }

    var body: some View {
        Form {
            Section("Device") {
                ForEach(shown(Self.rootOrder), id: \.self) { ManagerParamRow(manager: manager, device: device, ep: 0, tid: $0) }
            }
            let network = shown(Self.networkOrder)
            if !network.isEmpty {
                Section {
                    ForEach(network, id: \.self) { ManagerParamRow(manager: manager, device: device, ep: 0, tid: $0) }
                } header: {
                    Text("Network")
                } footer: {
                    Text("Read-only here: changing the address needs the rollback procedure, so use Tools if you really mean to.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            ForEach(ports, id: \.self) { ep in
                Section {
                    ForEach(shown(Self.portOrder), id: \.self) { ManagerParamRow(manager: manager, device: device, ep: ep, tid: $0) }
                } header: {
                    Text("Port \(ep)")
                }
            }
            Section {
                HStack {
                    Button("Refresh all") {
                        manager.poll(lo: device.tuid, hi: device.tuid, level: 3, ep: 0xFFFF, to: manager.unicast ? device.ip : nil)
                    }
                    Text("Values are the last ones the device reported.").font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .formStyle(.grouped)
    }
}

/// One parameter: name, current value, and an editor when it is settable.
/// Choices apply as soon as they are picked; text and numbers need Save.
private struct ManagerParamRow: View {
    @ObservedObject var manager: Manager
    let device: ManagerDevice
    let ep: UInt16
    let tid: UInt16
    @State private var editing = false
    @State private var draft = ""
    @State private var note = ""
    @State private var failed = false

    private var current: [UInt8]? { device.params[ep]?[tid] }
    private var title: String { ManagerLabels.title(tid) }

    var body: some View {
        LabeledContent {
            HStack(spacing: 8) {
                if !note.isEmpty {
                    Text(note).font(.caption).foregroundStyle(failed ? .red : .secondary).lineLimit(2)
                }
                control
            }
        } label: {
            Text(title)
        }
    }

    @ViewBuilder private var control: some View {
        switch ManagerLabels.editor(tid) {
        case .choice(let options):
            Picker(title, selection: Binding(get: { current?.first ?? 0 }, set: { send([$0]) })) {
                ForEach(options, id: \.0) { Text($0.1).tag($0.0) }
                if let v = current?.first, !options.contains(where: { $0.0 == v }) { Text(ManagerLabels.value(tid, [v])).tag(v) }
            }
            .labelsHidden().fixedSize()
            .disabled(manager.busy || current == nil)
        case .some where editing:
            TextField(title, text: $draft, prompt: Text(ManagerTID.byTID[tid]?.layout ?? ""))
                .labelsHidden().frame(minWidth: 160, maxWidth: 260)
                .onSubmit(save)
            Button("Save", action: save).disabled(ManagerLabels.encode(tid, draft) == nil || manager.busy)
            Button("Cancel") { editing = false }
        case .some:
            Text(current.map { ManagerLabels.value(tid, $0) } ?? "—").textSelection(.enabled)
            Button("Edit") { draft = ManagerLabels.draft(tid, current); editing = true; note = "" }
                .disabled(manager.busy)
        case nil:
            Text(current.map { ManagerLabels.value(tid, $0) } ?? "—").textSelection(.enabled)
                .foregroundStyle(current == nil ? .secondary : .primary)
        }
    }

    private func save() {
        guard let v = ManagerLabels.encode(tid, draft) else { return }
        send(v)
    }

    private func send(_ v: [UInt8]) {
        guard v != current else { editing = false; return }
        note = "Saving…"
        failed = false
        manager.set(device.tuid, ep: ep, tlvs: [ManagerTLV(tid: tid, value: v)]) { r in
            failed = !r.ok
            note = r.ok ? "Saved" : (r.text.contains("refused") ? "Device refused this value" : "No confirmation")
            if r.ok { editing = false }
            DispatchQueue.main.asyncAfter(deadline: .now() + 4) { if note == "Saved" { note = "" } }
        }
    }
}
