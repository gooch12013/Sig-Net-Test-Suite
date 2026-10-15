import SigNet
import SwiftUI

/// Parameters: one module for the device, one for its network, one per port.
/// Only parameters the device says it supports are shown; each is a readout with GET and SET.
struct ManagerSettingsView: View {
    @ObservedObject var manager: Manager
    let device: ManagerDevice
    @State private var editing = false

    private static let rootOrder: [UInt16] = [0x0605, 0x0607, 0x0606]
    private static let networkOrder: [UInt16] = [0x0501, 0x0502, 0x0503, 0x0504, 0x0505, 0x0506, 0x0581, 0x0582, 0x0583, 0x0584, 0x0585]
    private static let portOrder: [UInt16] = [0x0901, 0x0902, 0x0905, 0x090C, 0x0907, 0x090B, 0x0908, 0x0909, 0x0906, 0x0903,
                                              0x0904, 0x090A, 0x0305, 0x0306, 0xFF03]
    /// On the Info tab already (Device and Health), the supported list itself, and RDM discovery (the RDM tab sends it):
    /// not repeated under Other parameters.
    private static let elsewhere: [UInt16] = [0x0601, 0x0602, 0x0603, 0x0604, 0x0608, 0x0609, 0x060B, 0xFF01, 0x0303]

    /// What the device reports it supports; everything when it hasn't said yet.
    private var supported: Set<UInt16>? {
        guard let v = device.root(0x0601) else { return nil }
        return Set(stride(from: 0, to: v.count - 1, by: 2).map { mgrU16(v[$0...]) })
    }
    private func shown(_ order: [UInt16]) -> [UInt16] { order.filter { supported?.contains($0) ?? true } }
    /// Supported parameters no list above names, manufacturer ones included: root (or unknown) ones, or data-port ones.
    private func others(port: Bool) -> [UInt16] {
        guard let supported else { return [] }
        let listed = Set(Self.rootOrder + Self.networkOrder + Self.portOrder + Self.elsewhere)
        return supported.filter { tid in
            guard !listed.contains(tid) else { return false }
            guard let t = ManagerTID.byTID[tid] else { return !port && tid >= 0x8000 } // unknown standard TIDs aren't parameters
            return (t.get || t.set) && (t.scope == "D") == port
        }.sorted()
    }
    private var ports: [UInt16] {
        let n = device.root(0x0602).map(mgrU16) ?? UInt16(device.params.keys.filter { $0 != 0 && $0 != 0xFFFF }.count)
        return n == 0 ? [] : Array(1...n)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            ModulePanel("Device") {
                Button("Refresh all") {
                    manager.poll(lo: device.tuid, hi: device.tuid, level: 3, ep: 0xFFFF, to: manager.unicast ? device.ip : nil)
                }
                .buttonStyle(.softKey).disabled(!manager.running)
            } content: {
                ForEach(shown(Self.rootOrder), id: \.self) { parameterRow(manager, device, ep: 0, tid: $0) }
            }
            let network = shown(Self.networkOrder)
            if !network.isEmpty {
                ModulePanel("Network") {
                    Text("Read only here").font(.system(size: 11)).foregroundStyle(Color.silk)
                        .help("Changing the address needs the rollback procedure; use Debug if you really mean to")
                } content: {
                    ForEach(network, id: \.self) { parameterRow(manager, device, ep: 0, tid: $0) }
                }
            }
            let more = others(port: false)
            if !more.isEmpty {
                ModulePanel("Other parameters") {
                    Text(ManufacturerTIDs.problem ?? "Reported by the device").font(.system(size: 11))
                        .foregroundStyle(ManufacturerTIDs.problem == nil ? Color.silk : Color.red)
                    Button("Edit") { editing = true }.buttonStyle(.softKey)
                        .help("Names and SET ranges for manufacturer parameters")
                } content: {
                    ForEach(more, id: \.self) { parameterRow(manager, device, ep: 0, tid: $0) }
                }
            }
            ForEach(ports, id: \.self) { ep in
                ModulePanel("Port \(ep)") {
                    if let u = device.params[ep]?[0x0901] {
                        Text("Universe \(ManagerLabels.value(0x0901, u))").font(.system(size: 11, design: .monospaced)).foregroundStyle(Color.silk)
                    }
                } content: {
                    ForEach(shown(Self.portOrder) + others(port: true), id: \.self) { parameterRow(manager, device, ep: ep, tid: $0) }
                }
            }
        }
        .sheet(isPresented: $editing) {
            ManufacturerTIDsEditor { manager.objectWillChange.send() }
        }
    }
}
