import Foundation

/// `--selftest` for both front-ends (sig-net and the app). `--offline` keeps to the known-answer and
/// emulator checks, for hosts without multicast loopback. Prints one line per check; returns the exit status.
public enum SelfTest {
    public static func run(_ args: [String]) -> Int32 {
        var failed = false
        func report(_ label: String, _ why: String?) {
            print("\(why == nil ? "PASS" : "FAIL") \(label)\(why.map { ": \($0)" } ?? "")")
            failed = failed || why != nil
        }
        report("timecode counter", Timecode.selfTest() ? nil : "wrong frame label")
        report("rdm firmware upload (emulator)", FirmwareUpdate.selfTestFTC() ? nil : "see above")
        report("manager spec vectors", ManagerEngine.knownAnswers())
        report("sender spec vectors", TransmitterEngine.knownAnswers())
        report("receiver spec vectors and parse path", ReceiverEngine.knownAnswers())
        report("device rdm", DeviceEngine.rdmSelfTest())
        if args.contains("--offline") { return failed ? 1 : 0 }
        let interface = args.firstIndex(of: "--interface").flatMap { args.dropFirst($0 + 1).first } ?? ""
        for mode in SecurityMode.allCases {
            let s = SecurityConfig()
            s.mode = mode
            s.passphrase = "Sig-Net-Test-9"
            s.interface = interface
            let tag = mode.rawValue.lowercased()
            report("manager loop \(tag)", ManagerEngine.loopTest(settings: s))
            report("sender loop \(tag)", TransmitterEngine.loopTest(settings: s))
            report("device \(tag)", DeviceEngine.selfTest(settings: s))
            report("manager+device \(tag)", ManagerEngine.deviceLoopTest(settings: s))
            for (label, why) in loopback(s) { report("loopback \(label) \(tag)", why) }
        }
        return failed ? 1 : 0
    }

    // MARK: - Sender -> Receiver loopback

    /// Each check uses its own universes (101+) and stops everything before returning. Self-test roles never
    /// share a TUID with a running GUI.
    static func loopback(_ s: SecurityConfig) -> [(String, String?)] {
        var rows = [("multi-universe 101-103", multiUniverse(s)), ("priority 150 beats 100", priority(s)),
                    ("sync", sync(s)), ("timecode stream 7 @25", timecode(s)), ("preview 120", preview(s))]
        if s.mode == .secure { rows += mismatch(s.interface) } // mode-independent: run once
        return rows
    }

    private static func spin(_ secs: Double, until ok: () -> Bool = { false }) -> Bool {
        ManagerEngine.spin(secs, until: ok)
        return ok()
    }

    private static func pair(_ s: SecurityConfig, role: String = "selftest-sender", _ universes: String,
                             rx rxSetup: (ReceiverEngine) -> Void = { _ in }, tx txSetup: (TransmitterEngine) -> Void)
        -> (ReceiverEngine, TransmitterEngine, String?) {
        let rx = ReceiverEngine(settings: s, tuid: [0x7F, 0xF0, 0, 0, 0, 3]), tx = TransmitterEngine(settings: s, role: role)
        rx.universesText = universes
        rx.selected = Int(universes.prefix { $0.isNumber })!
        rxSetup(rx)
        txSetup(tx)
        rx.start()
        tx.start()
        return (rx, tx, !rx.running ? "rx: \(rx.status)" : !tx.running ? "tx: \(tx.status)" : nil)
    }

    private static func multiUniverse(_ s: SecurityConfig) -> String? {
        let (rx, tx, problem) = pair(s, "101-103") { $0.universe = 101; $0.count = 3 }
        defer { tx.stop(); rx.stop() }
        if let problem { return problem }
        let want: [UInt8] = [11, 22, 33]
        for i in 0..<3 { tx.selected = i; tx.setAll(want[i]) }
        var got = [UInt8]()
        for i in 0..<3 {
            rx.selected = 101 + i
            _ = spin(1.5) { rx.frame != nil && rx.levels.allSatisfy { $0 == want[i] } }
            got.append(rx.frame == nil ? 0 : rx.levels[0])
        }
        return got == want ? nil : "want \(want) got \(got) (0 = no frame)"
    }

    /// Per slot the highest priority wins, HTP among equals. The high-priority sender sends the LOWER level so a
    /// priority-blind HTP merge fails; dropping it to 90 must flip the output, proving the loser is heard.
    private static func priority(_ s: SecurityConfig) -> String? {
        let low = TransmitterEngine(settings: s, role: "selftest-sender2") // merge keys sources by Sender-ID
        let (rx, high, problem) = pair(s, "110") { $0.universe = 110; $0.sendPriority = true; $0.priorities[0] = 150 }
        low.universe = 110
        low.sendPriority = true
        low.priorities[0] = 100
        low.start()
        defer { low.stop(); high.stop(); rx.stop() }
        if let problem { return problem }
        if !low.running { return "tx2: \(low.status)" }
        high.setAll(60)
        low.setAll(200)
        let first = spin(1.5) { rx.frame != nil && rx.levels.allSatisfy { $0 == 60 } }
        let firstLevel = rx.levels[0]
        high.priorities[0] = 90
        let flipped = spin(1.5) { rx.levels.allSatisfy { $0 == 200 } }
        return first && flipped ? nil : "150/60 vs 100/200 gave \(firstLevel) (want 60); after 150->90 gave \(rx.levels[0]) (want 200)"
    }

    private static func sync(_ s: SecurityConfig) -> String? {
        let (rx, tx, problem) = pair(s, "111") { $0.universe = 111; $0.sync = true }
        defer { tx.stop(); rx.stop() }
        if let problem { return problem }
        tx.setAll(99)
        return spin(2.5) { rx.frame != nil && rx.levels.allSatisfy { $0 == 99 } } ? nil
            : "want 99, got \(rx.frame == nil ? "no frame" : "\(rx.levels[0])")"
    }

    private static func timecode(_ s: SecurityConfig) -> String? {
        let (rx, tx, problem) = pair(s, "112", rx: { $0.timecodeText = "7" }) { $0.universe = 112; $0.tcStream = 7; $0.tcRate = 0x01 }
        defer { tx.stop(); rx.stop() }
        if let problem { return problem }
        tx.startTimecode()
        func frames(_ v: [UInt8]) -> Int { ((Int(v[0]) * 60 + Int(v[1])) * 60 + Int(v[2])) * 25 + Int(v[3]) }
        guard spin(1.5, until: { rx.timecodes[7] != nil }), let a = rx.timecodes[7] else { return "nothing on stream 7 within 1.5 s" }
        _ = spin(0.4)
        let b = rx.timecodes[7]!
        return b.value[4] == 0x01 && !b.lost && frames(b.value) > frames(a.value) ? nil
            : "rate 0x\(String(b.value[4], radix: 16)) lost \(b.lost) frames \(frames(a.value)) -> \(frames(b.value))"
    }

    private static func preview(_ s: SecurityConfig) -> String? {
        let (rx, tx, problem) = pair(s, "120", rx: { $0.previewText = "120" }) { $0.universe = 120; $0.preview = true }
        defer { tx.stop(); rx.stop() }
        if let problem { return problem }
        let want = (0..<512).map { UInt8(truncatingIfNeeded: $0 * 7) }
        tx.levels = want
        if spin(1.5, until: { rx.previews[120]?.levels == want }) { return nil }
        return "want \(Array(want.prefix(4))), " + (rx.previews[120].map { "first bytes \(Array($0.levels.prefix(4)))" } ?? "no preview frame")
    }

    /// A Secure Receiver must drop an Open Sender (mode mismatch) and a Secure one with another passphrase (auth failure).
    private static func mismatch(_ interface: String) -> [(String, String?)] {
        func settings(_ mode: SecurityMode, _ pass: String) -> SecurityConfig {
            let s = SecurityConfig()
            (s.mode, s.passphrase, s.interface) = (mode, pass, interface)
            return s
        }
        let rxS = settings(.secure, "Sig-Net-Test-9")
        let cases: [(String, SecurityConfig, DropReason)] = [
            ("secure rx rejects open tx", settings(.open, ""), .modeMismatch),
            ("secure rx rejects wrong passphrase", settings(.secure, "Wrong-Pass-77x"), .authFailed),
        ]
        return cases.map { label, txS, reason in
            let rx = ReceiverEngine(settings: rxS, tuid: [0x7F, 0xF0, 0, 0, 0, 3]), tx = TransmitterEngine(settings: txS, role: "selftest-sender")
            rx.universesText = "130"
            tx.universe = 130
            rx.start()
            tx.start()
            defer { tx.stop(); rx.stop() }
            if !rx.running { return (label, "rx: \(rx.status)") }
            if !tx.running { return (label, "tx: \(tx.status)") }
            tx.setAll(201)
            var published = false
            _ = spin(1.5) { published = published || rx.frame != nil; return false } // a frame must never appear
            let drops = rx.counters.drops[reason.rawValue], recorded = rx.rejections.contains { $0.reason == reason }
            return (label, !published && drops > 0 && recorded ? nil
                : "frame published \(published), drops[\(reason.name)] \(drops), flight-recorder entry \(recorded), accepted \(rx.counters.accepted)")
        }
    }
}
