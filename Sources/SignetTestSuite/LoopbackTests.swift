import CSignet
import Foundation
import SigNet

/// End-to-end Transmitter -> Receiver loopback checks for --selftest. Each check
/// uses its own universes (101+) and stops everything before returning.
enum LoopbackTests {
    typealias Row = (String, Bool, String)

    static func run(settings s: SecuritySettings) -> [Row] {
        var rows = [multiUniverse(s), priority(s), sync(s), timecode(s), preview(s)]
        if s.mode == .secure { rows += mismatch() } // mode-independent: run once
        return rows
    }

    /// Drives the main RunLoop (Receiver/Transmitter timers live there) until `ok` or timeout.
    @discardableResult
    private static func spin(_ secs: Double, until ok: () -> Bool = { false }) -> Bool {
        let deadline = Date().addingTimeInterval(secs)
        while Date() < deadline {
            RunLoop.main.run(until: Date().addingTimeInterval(0.05))
            if ok() { return true }
        }
        return ok()
    }

    private static func pair(_ s: SecuritySettings, rx rxSetup: (Receiver) -> Void, tx txSetup: (Transmitter) -> Void)
        -> (Receiver, Transmitter, String?) {
        let rx = Receiver(settings: s), tx = Transmitter(settings: s)
        rxSetup(rx)
        txSetup(tx)
        rx.start()
        tx.start()
        let problem = !rx.running ? "rx: \(rx.status)" : !tx.running ? "tx: \(tx.status)" : nil
        return (rx, tx, problem)
    }

    private static func multiUniverse(_ s: SecuritySettings) -> Row {
        let label = "loopback multi-universe 101-103"
        let (rx, tx, problem) = pair(s, rx: { $0.universesText = "101-103"; $0.selected = 101 },
                                     tx: { $0.universe = 101; $0.count = 3 })
        defer { tx.stop(); rx.stop() }
        if let problem { return (label, false, problem) }
        let want: [UInt8] = [11, 22, 33]
        for i in 0..<3 { tx.selected = i; tx.setAll(want[i]) }
        var got = [UInt8]()
        for i in 0..<3 {
            rx.selected = 101 + i
            spin(1.5) { rx.frame != nil && rx.levels.allSatisfy { $0 == want[i] } }
            got.append(rx.frame == nil ? 0 : rx.levels[0])
        }
        return (label, got == want, "want \(want) got \(got) (0 = no frame)")
    }

    /// Merge rule: per slot the highest priority wins, HTP
    /// among equal priorities. The high-priority sender sends the LOWER level so
    /// a priority-blind HTP merge would fail.
    private static func priority(_ s: SecuritySettings) -> Row {
        let label = "loopback priority 150 beats 100"
        // The merge keys sources by TUID+endpoint, so the second sender needs its own role.
        let low = Transmitter(settings: s, role: "sender2")

        let (rx, high, problem) = pair(s, rx: { $0.universesText = "110"; $0.selected = 110 },
                                       tx: { $0.universe = 110; $0.sendPriority = true; $0.priorities[0] = 150 })
        low.universe = 110
        low.sendPriority = true
        low.priorities[0] = 100
        low.start()
        defer { low.stop(); high.stop(); rx.stop() }
        if let problem { return (label, false, problem) }
        if !low.running { return (label, false, "tx2: \(low.status)") }
        high.setAll(60)
        low.setAll(200)
        // source_count counts only senders that win a slot, so prove the loser is
        // heard by dropping the winner to 90 and watching the output flip to 200.
        let first = spin(1.5) { rx.frame != nil && rx.levels.allSatisfy { $0 == 60 } }
        let firstLevel = rx.levels[0]
        high.priorities[0] = 90
        let flipped = spin(1.5) { rx.levels.allSatisfy { $0 == 200 } }
        return (label, first && flipped, "150/60 vs 100/200 gave \(firstLevel) (want 60); after 150->90 gave \(rx.levels[0]) (want 200)")
    }

    private static func sync(_ s: SecuritySettings) -> Row {
        let label = "loopback sync"
        let (rx, tx, problem) = pair(s, rx: { $0.universesText = "111"; $0.selected = 111 },
                                     tx: { $0.universe = 111; $0.sync = true })
        defer { tx.stop(); rx.stop() }
        if let problem { return (label, false, problem) }
        tx.setAll(99)
        let ok = spin(2.5) { rx.frame != nil && rx.levels.allSatisfy { $0 == 99 } }
        return (label, ok, "want 99, got \(rx.frame == nil ? "no frame" : "\(rx.levels[0])") · \(tx.status)")
    }

    private static func timecode(_ s: SecuritySettings) -> Row {
        let label = "loopback timecode stream 7 @25"
        let (rx, tx, problem) = pair(s, rx: { $0.universesText = "112"; $0.timecodeText = "7" },
                                     tx: { $0.universe = 112; $0.tcStream = 7; $0.tcRate = 0x01 })
        defer { tx.stop(); rx.stop() }
        if let problem { return (label, false, problem) }
        tx.startTimecode()
        func frames(_ v: (UInt8, UInt8, UInt8, UInt8, UInt8)) -> Int { ((Int(v.0) * 60 + Int(v.1)) * 60 + Int(v.2)) * 25 + Int(v.3) }
        guard spin(1.5, until: { rx.timecodes[7] != nil }), let a = rx.timecodes[7] else {
            return (label, false, "nothing on stream 7 within 1.5 s (tx \(tx.tcDisplay))")
        }
        spin(0.4)
        let b = rx.timecodes[7]!
        let ok = b.value.4 == 0x01 && b.lost == 0 && frames(b.value) > frames(a.value)
        return (label, ok, "rate 0x\(String(b.value.4, radix: 16)) lost \(b.lost) frames \(frames(a.value)) -> \(frames(b.value))")
    }

    private static func preview(_ s: SecuritySettings) -> Row {
        let label = "loopback preview 120"
        let (rx, tx, problem) = pair(s, rx: { $0.universesText = "120"; $0.previewText = "120" },
                                     tx: { $0.universe = 120; $0.preview = true })
        defer { tx.stop(); rx.stop() }
        if let problem { return (label, false, problem) }
        let want = (0..<512).map { UInt8(truncatingIfNeeded: $0 * 7) }
        tx.levels = want
        let ok = spin(1.5) { rx.previews[120]?.levels == want }
        let got = rx.previews[120].map { "first bytes \(Array($0.levels.prefix(4)))" } ?? "no preview frame"
        return (label, ok, ok ? "" : "want \(Array(want.prefix(4))), \(got)")
    }

    /// Secure Rx vs Open Tx (mode mismatch) and vs Secure Tx with another passphrase (auth failure).
    private static func mismatch() -> [Row] {
        func settings(_ mode: SecurityMode, _ pass: String) -> SecuritySettings {
            let s = SecuritySettings()
            s.mode = mode
            s.passphrase = pass
            return s
        }
        let rxS = settings(.secure, "Sig-Net-Test-9")
        let cases: [(String, SecuritySettings, Int)] = [
            ("loopback secure rx rejects open tx", settings(.open, ""), Int(SIGNET_RX_DROP_MODE_MISMATCH.rawValue)),
            ("loopback secure rx rejects wrong passphrase", settings(.secure, "Wrong-Pass-77x"), Int(SIGNET_RX_DROP_AUTH_FAILED.rawValue)),
        ]
        return cases.map { label, txS, reason in
            let rx = Receiver(settings: rxS), tx = Transmitter(settings: txS)
            rx.universesText = "130"
            rx.selected = 130
            tx.universe = 130
            rx.start()
            tx.start()
            defer { tx.stop(); rx.stop() }
            if !rx.running { return (label, false, "rx: \(rx.status)") }
            if !tx.running { return (label, false, "tx: \(tx.status)") }
            tx.setAll(201)
            func drops() -> UInt64 { withUnsafeBytes(of: rx.counters.drops) { $0.bindMemory(to: UInt64.self)[reason] } }
            var published = false
            spin(1.5) {
                published = published || rx.frame != nil
                return false // watch the whole window: a frame must never appear
            }
            let recorded = rx.rejections.contains { Int($0.drop_reason) == reason }
            return (label, !published && drops() > 0 && recorded,
                    "frame published \(published), drops[\(reason)] \(drops()), flight-recorder entry \(recorded), accepted \(rx.counters.accepted)")
        }
    }
}
