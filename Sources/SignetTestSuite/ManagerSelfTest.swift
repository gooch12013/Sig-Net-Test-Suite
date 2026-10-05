import CryptoKit
import Foundation

extension Manager {
    /// Codec known-answers (manager-wire.md §9) + a live interop run against the
    /// in-process FakeDevice (library Node). Prints "  manager: <reason>" on failure.
    static func selfTest(settings s: SecuritySettings) -> Bool {
        func fail(_ why: String) -> Bool { print("  manager: \(why)"); return false }
        if let why = knownAnswers() { return fail(why) }

        let dev = FakeDevice(settings: s)
        dev.start()
        guard dev.running else { return fail("FakeDevice did not start: \(dev.status)") }
        defer { dev.stop() }
        let m = Manager(settings: s, tuid: Identity.tuid("selftest-manager")) // never share a lane with a running GUI Manager
        m.heartbeat = false
        m.start()
        guard m.running else { return fail("start: \(m.status)") }
        defer { m.stop() }
        let id = Identity.hex(dev.tuid)

        // Discovery: the initial FULL poll must surface the device with its model name.
        spin(4) { m.devices[id]?.model == dev.modelName }
        guard let d = m.devices[id] else { return fail("poll: device \(id) never replied") }
        guard d.model == dev.modelName else { return fail("poll: model \"\(d.model)\" ≠ \"\(dev.modelName)\"") }
        guard d.label != "" else { return fail("poll: FULL reply carried no RT_DEVICE_LABEL") }

        // GET model name + label.
        guard let g = wait({ m.get(dev.tuid, ep: 0, tids: [0x060B, 0x0605], done: $0) }), g.ok else {
            return fail("GET: \(m.result)")
        }
        guard g.tlvs.first(where: { $0.tid == 0x060B })?.value == [0] + Array(dev.modelName.utf8) else { return fail("GET model: \(g.text)") }

        // SET label → echo + SET_REPLY, CHANGE_COUNT +1, then GET returns it.
        let before = m.devices[id]?.changeCount
        let label = "Mgr test \(UInt16.random(in: 0...0xFFFF))"
        let value = [0] + Array(label.utf8)
        guard let st = wait({ m.set(dev.tuid, ep: 0, tlvs: [ManagerTLV(tid: 0x0605, value: value)], done: $0) }), st.ok,
              st.tlvs.contains(where: { $0.tid == 0x0003 }) else { return fail("SET label: \(m.result)") }
        if let before, m.devices[id]?.changeCount != before &+ 1 {
            return fail("SET label: CHANGE_COUNT \(before) → \(m.devices[id]?.changeCount.map(String.init) ?? "nil"), expected +1")
        }
        guard let g2 = wait({ m.get(dev.tuid, ep: 0, tids: [0x0605], done: $0) }), g2.tlvs.first?.value == value else {
            return fail("GET after SET: \(m.result)")
        }

        // Out-of-range SET (RT_IDENTIFY 9): silence, retry, then the GET probe classifies it as refused.
        guard let bad = wait({ m.set(dev.tuid, ep: 0, tlvs: [ManagerTLV(tid: 0x0607, value: [9])], done: $0) }), !bad.ok,
              bad.text.contains("refused") else { return fail("invalid SET: \(m.result)") }

        // RDM: ToD on EP 1, then GET DEVICE_INFO to the first UID.
        guard let tod = wait({ m.requestToD(dev.tuid, ep: 1, done: $0) }), tod.ok, let uid = m.devices[id]?.tod[1]?.first else {
            return fail("ToD: \(m.result)")
        }
        guard let r = wait({ m.rdm(dev.tuid, ep: 1, dest: uid, set: false, pid: 0x0060, done: $0) }), r.ok,
              ManagerRDM.valid(r.frame), mgrU16(r.frame[21...]) == 0x0060, r.frame[23] == 19 else {
            return fail("RDM DEVICE_INFO: \(m.result)")
        }

        // Negative (Secure only): wrong passphrase → Node stays silent, and the
        // wrong-key Manager flags the real Node's replies as auth FAIL.
        if s.mode == .secure {
            let bad = SecuritySettings()
            bad.mode = .secure
            bad.passphrase = "Wrong-Pass-42"
            let intruder = Manager(settings: bad, tuid: [0x7F, 0xF0, 0xC0, 0xDE, 0x00, 0x01])
            intruder.heartbeat = false
            intruder.start()
            guard intruder.running else { return fail("wrong-key manager: \(intruder.status)") }
            defer { intruder.stop() }
            guard let n = wait({ intruder.get(dev.tuid, ep: 0, tids: [0x0605], done: $0) }), !n.ok else {
                return fail("wrong passphrase: Node answered a GET signed with the wrong Km_local")
            }
            _ = wait { m.get(dev.tuid, ep: 0, tids: [0x0605], done: $0) } // real reply, seen by both
            guard intruder.log.contains(where: { !$0.tx && $0.uri.contains("/node/\(id)/") && $0.auth == "FAIL" }) else {
                return fail("wrong passphrase: Node reply was not flagged auth FAIL")
            }
            guard intruder.devices[id]?.anomaly.contains("FAIL") == true else { return fail("wrong passphrase: no anomaly raised for \(id)") }
        }
        return true
    }

    private static func spin(_ secs: Double, until ok: () -> Bool) {
        let end = Date().addingTimeInterval(secs)
        while Date() < end, !ok() { RunLoop.main.run(until: Date().addingTimeInterval(0.05)) }
    }

    private static func wait(_ op: (@escaping (ManagerResult) -> Void) -> Void) -> ManagerResult? {
        var r: ManagerResult?
        op { r = $0 }
        spin(6) { r != nil }
        return r
    }

    /// Byte-exact packets from manager-wire.md §9 (accepted by the library's own RX pipeline).
    private static func knownAnswers() -> String? {
        let kat = SecuritySettings()
        kat.mode = .secure
        kat.passphrase = "SigNetT3stVector1!" // Annex G
        guard var k0 = try? kat.rootKey() else { return "KAT: K0 derivation failed" }
        guard mgrHex(k0).hasPrefix("06577c60"), mgrHex(k0).hasSuffix("48d3e3") else { return "KAT: K0 \(mgrHex(k0))" }
        var keys = ManagerKeys(k0: &k0)
        guard k0.allSatisfy({ $0 == 0 }) else { return "KAT: K0 buffer not wiped" }
        let node: [UInt8] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]
        let kml = keys.kmLocal(node).withUnsafeBytes { mgrHex($0) }
        guard kml == "8f41d6df9a5ac9d8f8c7c0580a0c5fb90026154dd2dca6469cc3929ec5bb4889" else { return "KAT: Km_local \(kml)" }

        func packet(_ mid: UInt16, _ path: [String], mode: UInt8, seq: UInt32, _ tlv: ManagerTLV) -> ManagerPacket {
            var p = ManagerPacket()
            p.mid = mid
            p.segs = ["sig-net", "v1", "local"] + path
            p.mode = mode
            p.tuid = [0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01]
            if mode == 0 { p.session = 5; p.seq = seq }
            p.payload = ManagerTLV.encode([tlv])
            return p
        }
        let pollValue = [0xAA, 0xBB, 0xCC, 0, 0, 1] + [0, 0, 0, 0] + [UInt8](repeating: 0, count: 6)
            + [UInt8](repeating: 0xFF, count: 6) + [0xFF, 0xFF, 0x00]
        var poll = packet(0x1234, ["poll"], mode: 0, seq: 1, ManagerTLV(tid: 0x0001, value: pollValue))
        poll.sign(keys.kmGlobal)
        var get = packet(0x1235, ["manager", "123456789ABC", "0"], mode: 0, seq: 2, ManagerTLV(tid: 0x0605))
        get.sign(keys.kmLocal(node))
        let open = packet(0x1236, ["manager", "123456789ABC", "0"], mode: 1, seq: 0, ManagerTLV(tid: 0x0605))
        let vectors = [
            ("9a poll", poll, "50021234b77369672d6e6574027631056c6f63616c04706f6c6ce1070400d813aabbcc0000010000d2130000d41300000005d41300000001dd131332c0c4315922c1da83848d378536905bbc4e30bb48d785665317da21e3876b76ff00010019aabbcc00000100000000000000000000ffffffffffffffff00"),
            ("9b GET", get, "50021235b77369672d6e6574027631056c6f63616c076d616e616765720c3132333435363738394142430130e1070400d813aabbcc0000010000d2130000d41300000005d41300000002dd13137ff14675a05e808270295af4b5f2baed1d06a1feae6e93272ec7e1b48e24436fff06050000"),
            ("9c Open GET", open, "50021236b77369672d6e6574027631056c6f63616c076d616e616765720c3132333435363738394142430130e1070401d813aabbcc0000010000d2130000d41300000000d41300000000d013ff06050000"),
        ]
        for (name, p, hex) in vectors {
            let wire = mgrHex(p.encode())
            guard wire == hex else { return "KAT \(name): encoded \(wire)" }
            guard let back = try? ManagerPacket.decode(p.encode()), mgrHex(back.encode()) == hex, back.uri == p.uri else {
                return "KAT \(name): decode/re-encode mismatch"
            }
        }
        guard mgrHex(poll.auth) == "32c0c4315922c1da83848d378536905bbc4e30bb48d785665317da21e3876b76" else { return "KAT 9a HMAC" }
        guard poll.verify(keys.kmGlobal), !poll.verify(keys.kc) else { return "KAT 9a verify" }
        var tampered = poll
        tampered.payload[28] ^= 1
        guard !tampered.verify(keys.kmGlobal) else { return "KAT: tampered payload still verified" }
        // Decoder strictness: no Auth option is malformed even in Open Mode (library requires it).
        guard (try? ManagerPacket.decode(Array(open.encode().dropLast(7)) + [0xFF, 0x06, 0x05, 0x00, 0x00])) == nil else {
            return "KAT: packet without Sig-Net-Auth was accepted"
        }
        return nil
    }
}
