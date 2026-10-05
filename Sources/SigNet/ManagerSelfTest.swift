import Crypto
import Foundation

extension ManagerEngine {
    /// Two Managers on the network: B must discover A from A's start-up announce (§10.2.5), verified with Kc
    /// in Secure Mode. Exercises UDPSocket, the codec and HMAC end to end. nil = pass.
    public static func loopTest(settings s: SecurityConfig) -> String? {
        let b = ManagerEngine(settings: s, tuid: [0x7F, 0xF0, 0xC0, 0xDE, 0x00, 0x02])
        b.heartbeat = false
        b.start()
        guard b.running else { return "start B: \(b.status)" }
        defer { b.stop() }
        let a = ManagerEngine(settings: s, tuid: [0x7F, 0xF0, 0xC0, 0xDE, 0x00, 0x03])
        a.heartbeat = false
        a.start()
        guard a.running else { return "start A: \(a.status)" }
        defer { a.stop() }
        let id = Identity.hex(a.tuid), auth = s.mode == .secure ? "OK" : "Open (unauthenticated)"
        spin(3) { b.devices[id] != nil }
        guard let d = b.devices[id] else { return "B never heard A's announce" }
        guard d.auth == auth, d.state.hasPrefix("Online"), d.anomaly.isEmpty else { return "A seen as \(d.state), auth \(d.auth) \(d.anomaly)" }
        return nil
    }

    public static func spin(_ secs: Double, until ok: () -> Bool) {
        let end = Date().addingTimeInterval(secs)
        while Date() < end, !ok() { RunLoop.main.run(until: Date().addingTimeInterval(0.05)) }
    }

    public static func wait(_ op: (@escaping (ManagerResult) -> Void) -> Void, timeout: Double = 8) -> ManagerResult? {
        var r: ManagerResult?
        op { r = $0 }
        spin(timeout) { r != nil }
        return r
    }

    /// Byte-exact packets from manager-wire.md §9 (accepted by the library's own RX pipeline), plus the
    /// PF §7.2.3 passphrase rules. nil = pass.
    public static func knownAnswers() -> String? {
        let rules = SecurityConfig()
        for (p, ok) in [("Sig-Net-Test-9", true), ("SigNetT3stVector1!", true), ("Short-1a", false), ("lowercase-only1", true),
                        ("lowercaseonly", false), ("Paaass-word-9", false), ("Pass-abcd-word", false), ("Pass-4321-word", false),
                        ("Pass-abd-word9", true), (String(repeating: "Ab1-", count: 17), false)] {
            rules.passphrase = p
            guard (rules.passphraseProblem == nil) == ok else { return "passphrase \"\(p)\": \(rules.passphraseProblem ?? "accepted")" }
        }
        let kat = SecurityConfig()
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
