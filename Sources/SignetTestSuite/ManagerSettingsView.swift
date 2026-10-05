import SigNet
import SwiftUI

/// Parameters: one module for the device, one for its network, one per port.
/// Only parameters the device says it supports are shown; each is a readout with GET and SET.
struct ManagerSettingsView: View {
    @ObservedObject var manager: Manager
    let device: ManagerDevice

    private static let rootOrder: [UInt16] = [0x0605, 0x0607, 0x0606]
    private static let networkOrder: [UInt16] = [0x0501, 0x0502, 0x0503, 0x0504, 0x0505, 0x0506, 0x0581, 0x0582, 0x0583, 0x0584, 0x0585]
    private static let portOrder: [UInt16] = [0x0901, 0x0902, 0x0905, 0x090C, 0x0907, 0x090B, 0x0908, 0x0909, 0x0906, 0x0903,
                                              0x0904, 0x090A, 0x0305, 0x0306, 0xFF03]

    /// What the device reports it supports; everything when it hasn't said yet.
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
            ForEach(ports, id: \.self) { ep in
                ModulePanel("Port \(ep)") {
                    if let u = device.params[ep]?[0x0901] {
                        Text("Universe \(ManagerLabels.value(0x0901, u))").font(.system(size: 11, design: .monospaced)).foregroundStyle(Color.silk)
                    }
                } content: {
                    ForEach(shown(Self.portOrder), id: \.self) { parameterRow(manager, device, ep: ep, tid: $0) }
                }
            }
        }
    }
}
