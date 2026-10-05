import CSignet
import SigNet
import SwiftUI

/// Receive Debug: the one place on this tab with counters, drop reasons, packet hex and the library log.
struct ReceiveDebugView: View {
    @ObservedObject var rx: Receiver
    @State private var mode = "counters"

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                ModeKeys(options: [("counters", "Counters"), ("rejected", "Rejected packets"), ("log", "Log")], selection: $mode)
                Spacer()
                Toggle("Auto refresh", isOn: $rx.autoDiagnostics).font(.system(size: 11.5)).foregroundStyle(Color.inkDim)
                Button("Refresh") { rx.refreshDiagnostics() }.buttonStyle(.softKey).disabled(!rx.running)
            }
            switch mode {
            case "rejected": rejected
            case "log": ReceiveLog(rx: rx)
            default: counters
            }
        }
    }

    private var counters: some View {
        let c = rx.counters
        var drops = withUnsafeBytes(of: c.drops) { Array($0.bindMemory(to: UInt64.self)) }
        drops.append(c.coap_duplicates)
        let rows: [(String, UInt64)] = [
            ("Packets accepted", c.accepted), ("Beacons heard", c.beacons), ("Packets dropped", c.drops_total),
            ("Rejected packets recorded", c.rejections_recorded), ("Too many sources to merge", c.merge_saturations),
            ("Flood packets dropped", c.dos_packets_dropped), ("Preview frames dropped", c.preview_frames_dropped),
            ("Frame-rate buffer overflows", c.tap_frames_dropped), ("Frame-rate buffer stale", c.tap_frames_stale),
            ("Send failures", c.send_failures), ("Receive failures", c.transport_recv_failures),
            ("Packets truncated on receive", c.transport_recv_truncated), ("Runtime poll failures", c.runtime_poll_failures),
            ("Runtime faulted", UInt64(c.runtime_faulted)), ("Runtime jobs dropped", c.poll_jobs_dropped),
            ("Log lines dropped", c.log_records_dropped), ("Log delivery failures", c.log_delivery_failures),
            ("Log muted", UInt64(max(0, c.log_muted))), ("RDM frames rejected", c.rdm_frames_rejected),
            ("RDM changes blocked", c.rdm_sets_blocked), ("Offboard save failures", c.offboard_persist_failures),
            ("Offboard pending at boot", UInt64(c.booted_offboard_pending)),
        ]
        return HStack(alignment: .top, spacing: 12) {
            ModulePanel("Counters") {
                counterList(rows, alarm: { name, _ in name == "Packets dropped" || name == "Runtime faulted" })
                Divider().overlay(Color.black.opacity(0.4))
                HStack(spacing: 8) {
                    Text("This receiver’s ID").font(.system(size: 12, weight: .medium)).foregroundStyle(Color.inkDim)
                    Spacer()
                    Text(Identity.hex(rx.tuid)).font(.system(size: 12, design: .monospaced)).foregroundStyle(Color.ink).textSelection(.enabled)
                }
            }
            ModulePanel("Drops by reason") {
                counterList(drops.indices.dropFirst().map { (dropName(UInt8($0)).capitalizedFirst, drops[$0]) }, alarm: { _, _ in true })
            }
        }
    }

    private func counterList(_ rows: [(String, UInt64)], alarm: @escaping (String, UInt64) -> Bool) -> some View {
        VStack(spacing: 2) {
            ForEach(rows, id: \.0) { name, value in
                HStack(spacing: 8) {
                    Text(name).font(.system(size: 12)).foregroundStyle(Color.inkDim)
                    Spacer(minLength: 12)
                    Text("\(value)")
                        .font(.system(size: 12, weight: value > 0 ? .semibold : .regular, design: .monospaced)).monospacedDigit()
                        .foregroundStyle(value > 0 && alarm(name, value) ? Color.lampFault : value > 0 ? Color.ink : Color.silk)
                }
                .accessibilityElement(children: .combine)
            }
        }
        .frame(maxWidth: .infinity)
    }

    private var rejected: some View {
        ModulePanel("Rejected packets") {
            Text("\(rx.rejections.count)").font(.system(size: 11, design: .monospaced)).foregroundStyle(Color.silk)
        } content: {
            if rx.rejections.isEmpty {
                Text(rx.running ? "No packets rejected." : "Start receiving to record rejected packets.")
                    .font(.system(size: 12)).foregroundStyle(Color.silk)
            }
            LazyVStack(alignment: .leading, spacing: 2) {
                ForEach(Array(rx.rejections.enumerated().reversed()), id: \.offset) { _, r in
                    let header = withUnsafeBytes(of: r.header) { Identity.hex(Array($0.prefix(Int(r.header_len)))) }
                    HStack(alignment: .firstTextBaseline, spacing: 12) {
                        Lamp(color: .lampFault, size: 6)
                        Text("−\(max(0, (rx.nowNs - r.monotonic_ns) / 1_000_000)) ms").foregroundStyle(Color.silk).frame(width: 90, alignment: .trailing)
                        Text(dropName(r.drop_reason).capitalizedFirst).foregroundStyle(Color.ink).frame(width: 130, alignment: .leading)
                        Text("\(r.datagram_len) B").foregroundStyle(Color.inkDim).frame(width: 60, alignment: .trailing)
                        Text(header).foregroundStyle(Color.silk).textSelection(.enabled)
                    }
                    .font(.system(size: 11.5, design: .monospaced)).monospacedDigit()
                    .padding(.vertical, 3)
                    Divider().overlay(Color.black.opacity(0.4))
                }
            }
        }
    }
}

private struct ReceiveLog: View {
    @ObservedObject var rx: Receiver

    var body: some View {
        ModulePanel("Library log") {
            ModeKeys(options: Receiver.levelNames.indices.map { ($0, Receiver.levelNames[$0].capitalized) }, selection: $rx.logLevel)
            Button("Clear") { rx.clearLog() }.buttonStyle(.softKey)
        } content: {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 1) {
                        if rx.log.isEmpty {
                            Text(rx.running ? "No log lines at this level yet." : "Start receiving to see the library log.").foregroundStyle(Color.silk)
                        }
                        ForEach(Array(rx.log.enumerated()), id: \.offset) { i, line in
                            Text(line).foregroundStyle(Color.inkDim).textSelection(.enabled).id(i)
                        }
                    }
                    .font(.system(size: 11, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8)
                }
                .frame(height: 420)
                .background(RoundedRectangle(cornerRadius: 4, style: .continuous).fill(Color.readoutWindow))
                .onChange(of: rx.log.count) { n in proxy.scrollTo(n - 1, anchor: .bottom) }
            }
        }
    }
}

private let dropNames = [
    "none", "malformed", "unsupported mode", "mode mismatch", "bad version", "bad code", "bad URI",
    "routing scope", "routing TUID", "replay session", "replay seq", "auth failed", "payload invalid",
    "table saturated", "internal", "CoAP duplicate",
]

private func dropName(_ reason: UInt8) -> String {
    dropNames.indices.contains(Int(reason)) ? dropNames[Int(reason)] : "reason \(reason)"
}

private extension String {
    var capitalizedFirst: String { prefix(1).uppercased() + dropFirst() }
}
