import Foundation
import SigNet

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
            bad.interface = s.interface
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
}
