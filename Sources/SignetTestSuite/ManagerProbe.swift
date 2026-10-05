import Foundation

/// `SignetTestSuite --probe --node <TUID> --ip <addr> [--interface <addr>] [--passphrase <p>] [--scope <s>]`
/// Runs the Manager tab's own code paths against a real Node and prints one line
/// per discovery shape, TID GET, SET round-trip and RDM operation.
/// Never sends RT_OFFBOARD, RT_REBOOT or NW_* SETs; every SET is restored.
extension Manager {
    static func probe(_ args: [String]) -> Int32 {
        func arg(_ name: String) -> String? { args.firstIndex(of: name).flatMap { $0 + 1 < args.count ? args[$0 + 1] : nil } }
        guard let nodeHex = arg("--node")?.uppercased(), let node = mgrBytes(hex: nodeHex), node.count == 6, let ip = arg("--ip") else {
            print("usage: --probe --node <12 hex TUID> --ip <node IPv4> [--interface <local IPv4>] [--passphrase <p>] [--scope <s>] [--rdm-uid <12 hex>]")
            return 2
        }
        let s = SecuritySettings()
        if let p = arg("--passphrase") { s.mode = .secure; s.passphrase = p } else { s.mode = .open }
        s.scope = arg("--scope") ?? "local"
        guard s.ready else { print("passphrase rejected: \(s.passphraseProblem ?? "")"); return 2 }

        // Own TUID: sharing the GUI Manager's TUID would collide on session/seq and get one of them dropped as replay.
        let m = Manager(settings: s, tuid: Identity.tuid("probe"))
        m.heartbeat = false
        m.unicast = true
        m.interface = arg("--interface") ?? ""
        m.start()
        guard m.running else { print("manager start failed: \(m.status)"); return 1 }
        defer { m.stop() }
        print("Manager \(Identity.hex(m.tuid)) · \(s.mode.rawValue) · scope \(s.scopeOrDefault) · iface \(m.interface.isEmpty ? "default" : m.interface)")
        print("Node \(nodeHex) @ \(ip)\n")

        // Replies from the node logged since `mark`, as "auth · TIDs".
        func replies(since mark: Int) -> [String] {
            m.log.suffix(from: min(mark, m.log.count)).filter { !$0.tx && $0.sender.uppercased().hasPrefix(nodeHex) }
                .map { "\($0.uri.split(separator: "/").suffix(3).joined(separator: "/")) auth=\($0.auth) [\($0.tlvs)]" }
        }

        // 1. Discovery: let the start-up FULL poll land, then every shape × query level.
        spin(2) { m.devices[nodeHex] != nil }
        print("== Discovery")
        print("start-up poll: " + (m.devices[nodeHex].map { "found · model \"\($0.model)\" · label \"\($0.label)\" · ip \($0.ip) · auth \($0.auth)" } ?? "NOT FOUND"))
        let lo = node.prefix(5) + [0x00], hi = node.prefix(5) + [0xFF]
        let shapes: [(String, [UInt8], [UInt8], String?)] = [
            ("broadcast", [0, 0, 0, 0, 0, 0], [UInt8](repeating: 0xFF, count: 6), nil),
            ("range", Array(lo), Array(hi), nil),
            ("targeted multicast", node, node, nil),
            ("targeted unicast", node, node, ip),
        ]
        for (name, l, h, to) in shapes {
            for level: UInt8 in 0...3 {
                let mark = m.log.count
                m.poll(lo: l, hi: h, level: level, ep: 0xFFFF, to: to)
                RunLoop.main.run(until: Date().addingTimeInterval(name.hasPrefix("targeted") ? 0.8 : 1.8))
                let r = replies(since: mark)
                print("\(name) QL\(level): \(r.isEmpty ? "NO REPLY" : "\(r.count) packet(s)")")
                r.forEach { print("    \($0)") }
            }
        }

        // 2. GET every catalogue TID on its endpoints, one TID per request.
        print("\n== GET (one TID per request)")
        for t in ManagerTID.all where t.get {
            let eps: [UInt16] = t.scope == "R" ? [0] : t.scope == "D" ? [1, 2] : [0, 1, 2]
            for ep in eps {
                let r = wait { m.get(node, ep: ep, tids: [t.tid], done: $0) }
                let tlvs = r?.tlvs.filter { $0.tid == t.tid } ?? [] // some TIDs (DG_SECURITY_EVENT) answer with several TLVs
                let line = tlvs.isEmpty ? "– \(r?.text ?? "no result")"
                    : tlvs.map { "\(ManagerTID.describe(t.tid, $0.value))  (\($0.value.count) B: \(mgrHex($0.value)))" }.joined(separator: " | ")
                print("\(t.hex) \(t.name) ep\(ep): \(line)")
            }
        }

        // 3. SET round-trips, each restored. EP 1 drives the fixture, so direction/config there are rewritten unchanged.
        print("\n== SET round-trips")
        func value(_ tid: UInt16, _ ep: UInt16) -> [UInt8]? {
            wait { m.get(node, ep: ep, tids: [tid], done: $0) }?.tlvs.first { $0.tid == tid }?.value
        }
        func roundTrip(_ tid: UInt16, ep: UInt16, test: ([UInt8]) -> [UInt8]) {
            let name = "\(String(format: "0x%04X", tid)) \(ManagerTID.name(tid)) ep\(ep)"
            guard let orig = value(tid, ep) else { return print("\(name): skipped, GET of the original value failed") }
            let cc0 = m.devices[nodeHex]?.changeCount
            let new = test(orig)
            let mark = m.log.count
            let set = wait { m.set(node, ep: ep, tlvs: [ManagerTLV(tid: tid, value: new)], done: $0) }
            if set?.ok != true { // raw packets for whoever debugs it
                m.log.suffix(from: min(mark, m.log.count)).forEach {
                    print("    \($0.tx ? "TX" : "RX") \($0.time.timeIntervalSince1970) \($0.uri) [\($0.tlvs)] hex=\($0.hex)")
                }
            }
            let readBack = value(tid, ep)
            let cc1 = m.devices[nodeHex]?.changeCount
            let restore = wait { m.set(node, ep: ep, tlvs: [ManagerTLV(tid: tid, value: orig)], done: $0) }
            let final = value(tid, ep)
            print("\(name): \(mgrHex(orig)) → SET \(mgrHex(new)): \(set?.ok == true ? "confirmed" : "FAILED (\(set?.text ?? "no result"))")"
                + " · read back \(readBack.map(mgrHex) ?? "–")\(readBack == new ? " ✓" : " ✗")"
                + " · CHANGE_COUNT \(cc0.map(String.init) ?? "?")→\(cc1.map(String.init) ?? "?")"
                + " · restore \(restore?.ok == true ? "confirmed" : "FAILED (\(restore?.text ?? "no result"))")"
                + " · final \(final.map(mgrHex) ?? "–")\(final == orig ? " ✓" : " ✗ NOT RESTORED")")
        }
        roundTrip(0x0605, ep: 0) { _ in [0] + Array("Probe label".utf8) }
        roundTrip(0x0607, ep: 0) { $0 == [1] ? [0] : [1] }
        roundTrip(0x0901, ep: 1) { _ in mgrBE16(7) }
        roundTrip(0x0901, ep: 2) { _ in mgrBE16(8) }
        roundTrip(0x0902, ep: 1) { _ in [0] + Array("Probe EP1".utf8) }
        roundTrip(0x0902, ep: 2) { _ in [0] + Array("Probe EP2".utf8) }
        roundTrip(0x0905, ep: 1) { $0 }                       // unchanged: port A feeds the fixture
        roundTrip(0x0905, ep: 2) { [($0.first ?? 0) ^ 0x04] }  // toggle the RDM-enable bit
        roundTrip(0x0305, ep: 1) { $0 }
        roundTrip(0x0305, ep: 2) { [($0.first ?? 0) ^ 0x01] }  // toggle background discovery
        roundTrip(0x090C, ep: 1) { _ in [2] }                   // EP_IDENTIFY full
        roundTrip(0x090C, ep: 2) { _ in [1] }                   // EP_IDENTIFY subtle
        roundTrip(0x0908, ep: 1) { $0 }                         // EP_FAILOVER rewritten unchanged
        roundTrip(0x0908, ep: 1) { _ in [1, 0, 0] }             // mode 1: a Node may skip it
        roundTrip(0x090B, ep: 1) { $0 }                         // EP_PROTOCOL rewritten unchanged
        roundTrip(0x090B, ep: 1) { _ in [1] }                   // Art-Net: a Node may skip it
        roundTrip(0x0909, ep: 1) { $0 }                         // EP_DMX_TIMING rewritten unchanged

        // 3b. Mixed transactions (§10.4.2 path 1): one bad TLV must reject the whole packet,
        // silently, nothing applied, CHANGE_COUNT unchanged. Each test restores EP_LABEL.
        print("\n== Mixed transactions (§10.4.2)")
        func mixed(_ name: String, _ other: ManagerTLV, reject: Bool) {
            let label = [0] + Array("probe-mix".utf8)
            guard let before = value(0x0902, 1) else { return print("\(name): skipped, GET EP_LABEL failed") }
            let cc0 = m.devices[nodeHex]?.changeCount
            let mark = m.log.count
            let r = wait { m.set(node, ep: 1, tlvs: [ManagerTLV(tid: 0x0902, value: label), other], done: $0) }
            let after = value(0x0902, 1)
            let cc1 = m.devices[nodeHex]?.changeCount
            let echoed = r?.ok == true && r!.tlvs.contains(ManagerTLV(tid: 0x0902, value: label)) && r!.tlvs.contains(other)
            let pass = reject
                ? r?.ok != true && after == before && cc1 == cc0
                : echoed && after == label && cc1 == cc0.map { $0 &+ 1 }
            print("\(pass ? "PASS" : "FAIL") \(name): \(r?.text ?? "no result") · EP_LABEL \(after.map(mgrHex) ?? "–")"
                + " · CHANGE_COUNT \(cc0.map(String.init) ?? "?")→\(cc1.map(String.init) ?? "?")")
            if !pass {
                m.log.suffix(from: min(mark, m.log.count)).forEach {
                    print("    \($0.tx ? "TX" : "RX") \($0.uri) [\($0.tlvs)] hex=\($0.hex)")
                }
            }
            if after != before {
                let restore = wait { m.set(node, ep: 1, tlvs: [ManagerTLV(tid: 0x0902, value: before)], done: $0) }
                print("    EP_LABEL restored: \(restore?.ok == true && value(0x0902, 1) == before ? "✓" : "✗ \(restore?.text ?? "")")")
            }
        }
        mixed("label + EP_FAILOVER 010000 → reject", ManagerTLV(tid: 0x0908, value: [1, 0, 0]), reject: true)
        mixed("label + EP_PROTOCOL 01 → reject", ManagerTLV(tid: 0x090B, value: [1]), reject: true)
        mixed("label + EP_DMX_TIMING 0100 → reject", ManagerTLV(tid: 0x0909, value: [1, 0]), reject: true)
        mixed("label + EP_FAILOVER 000000 → apply both (control)", ManagerTLV(tid: 0x0908, value: [0, 0, 0]), reject: false)

        // 4. RDM through EP 1.
        print("\n== RDM (ep1)")
        let fixture = mgrBytes(hex: arg("--rdm-uid") ?? "21A43DA458B0") ?? []
        func flow(_ when: String) {
            for ep: UInt16 in [1, 2] { print("RDM_FLOW_CONTROL ep\(ep) \(when): \(value(0x0306, ep).map(mgrHex) ?? "– no reply")") }
        }
        flow("before")
        m.flushToD(node, ep: 1)
        print("TOD_CONTROL 1 (flush + discovery): sent (no reply expected, §10.5)")
        RunLoop.main.run(until: Date().addingTimeInterval(3)) // let the node rediscover the line
        let tod = wait { m.requestToD(node, ep: 1, done: $0) }
        let uids = m.devices[nodeHex]?.tod[1] ?? []
        print("TOD_CONTROL 0 (send ToD): \(tod?.ok == true ? "ok" : tod?.text ?? "no result") · UIDs \(uids.map(Identity.hex))")
        func rdm(_ label: String, set: Bool = false, pid: UInt16, pd: [UInt8] = []) {
            let r = wait { m.rdm(node, ep: 1, dest: fixture, set: set, pid: pid, pd: pd, done: $0) }
            guard let r, r.ok else { return print("\(label): FAILED \(r?.text ?? "no result")") }
            print("\(label): \(ManagerRDM.describe(r.frame)) · checksum \(ManagerRDM.valid(r.frame) ? "ok" : "BAD") · \(r.frame.count) B")
        }
        rdm("GET DEVICE_INFO", pid: 0x0060)
        rdm("GET DEVICE_LABEL", pid: 0x0082)
        rdm("GET SOFTWARE_VERSION_LABEL", pid: 0x00C0)
        rdm("GET SLOT_INFO", pid: 0x0120)
        for slot: UInt16 in 0...10 { rdm("GET SLOT_DESCRIPTION \(slot)", pid: 0x0121, pd: mgrBE16(slot)) }
        rdm("SET IDENTIFY_DEVICE 1", set: true, pid: 0x1000, pd: [1])
        rdm("SET IDENTIFY_DEVICE 0", set: true, pid: 0x1000, pd: [0])
        flow("after")

        // 5. Anything the Manager flagged.
        print("\n== Flags")
        if let a = m.devices[nodeHex]?.anomaly, !a.isEmpty { print("device anomaly: \(a)") }
        let odd = m.log.filter { !$0.tx && ($0.auth.contains("FAIL") || $0.auth.contains("REPLAY") || $0.auth.contains("MALFORMED") || $0.auth.contains("BAD")) }
        odd.forEach { print("\($0.peer) \($0.uri) auth=\($0.auth) \($0.tlvs) hex=\($0.hex)") }
        if odd.isEmpty && (m.devices[nodeHex]?.anomaly ?? "").isEmpty { print("none") }
        print("final CHANGE_COUNT \(m.devices[nodeHex]?.changeCount.map(String.init) ?? "?") · state \(m.devices[nodeHex]?.state ?? "?")")
        return 0
    }

    private static func spin(_ secs: Double, until ok: () -> Bool) {
        let end = Date().addingTimeInterval(secs)
        while Date() < end, !ok() { RunLoop.main.run(until: Date().addingTimeInterval(0.05)) }
    }

    private static func wait(_ op: (@escaping (ManagerResult) -> Void) -> Void) -> ManagerResult? {
        var r: ManagerResult?
        op { r = $0 }
        spin(8) { r != nil }
        return r
    }
}
