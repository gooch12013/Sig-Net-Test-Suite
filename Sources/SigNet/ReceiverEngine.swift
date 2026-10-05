import Crypto
import Foundation

public struct UniverseFrame {
    public var slotCount: Int
    public var sourceCount: Int
    public var publishedNs: Int64
}

public struct PreviewFrame {
    public var frame: UniverseFrame
    public var levels: [UInt8]
}

public struct TimecodeFrame {
    /// Hours, minutes, seconds, frames, rate type (PF §11.2.5).
    public var value: [UInt8]
    public var lost = false
    var seenNs: Int64
}

/// Why a packet was dropped, in PF §8.6 processing order.
public enum DropReason: Int, CaseIterable {
    case malformed, unsupportedMode, modeMismatch, badVersion, badCode, badURI, routingScope,
         replaySession, replaySeq, authFailed, payloadInvalid
    public var name: String {
        ["malformed", "unsupported mode", "mode mismatch", "bad version", "bad code", "bad URI", "routing scope",
         "replay session", "replay seq", "auth failed", "payload invalid"][rawValue]
    }
}

public struct ReceiverCounters {
    public var accepted: UInt64 = 0
    public var beacons: UInt64 = 0
    public var drops = [UInt64](repeating: 0, count: DropReason.allCases.count)
    public var dropsTotal: UInt64 { drops.reduce(0, +) }
    public var rejectionsRecorded: UInt64 = 0
    public var mergeSaturations: UInt64 = 0
    public var floodDropped: UInt64 = 0
}

public struct Rejection {
    public let monotonicNs: Int64
    public let reason: DropReason
    public let length: Int
    public let header: [UInt8]
}

/// A data-plane-only Sig-Net Node (no discovery, management or persistence) consuming a list
/// of universes, preview universes and timecode streams, written from PF §8.6, §9.2, §10.6–10.8.
/// Packets are processed as they arrive; the UI-facing properties update on a 20 Hz tick.
/// Plain class; the app's ObservableObject subclass turns `willChange()` into objectWillChange.
/// ponytail: everything runs on the main queue, like ManagerEngine; move parse/HMAC off main if
/// one host ever has to take hundreds of universes.
open class ReceiverEngine {
    public static let levelNames = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "CRITICAL", "OFF"]

    public let settings: SecurityConfig
    public let tuid: [UInt8]
    public var universesText = "1" { willSet { willChange() } }
    public var previewText = "" { willSet { willChange() } }
    public var timecodeText = "1" { willSet { willChange() } }
    public var sourcesPerUniverse = 4 { willSet { willChange() } }
    public var selected = 1 { willSet { willChange() } didSet { tapCount = 0; windowStart = Self.monotonicNs() } }
    public var logLevel = 2 { willSet { willChange() } }
    public var autoDiagnostics = true { willSet { willChange() } }
    public private(set) var running = false { willSet { willChange() } }
    public private(set) var status = "Stopped" { willSet { willChange() } }

    public private(set) var levels = [UInt8](repeating: 0, count: 512) { willSet { willChange() } }
    public private(set) var frame: UniverseFrame? { willSet { willChange() } }
    public private(set) var fps = 0.0 { willSet { willChange() } }
    public private(set) var nowNs: Int64 = 0 { willSet { willChange() } }
    public private(set) var timecodes: [UInt16: TimecodeFrame] = [:] { willSet { willChange() } }
    public private(set) var previews: [UInt16: PreviewFrame] = [:] { willSet { willChange() } }
    public private(set) var counters = ReceiverCounters() { willSet { willChange() } }
    public private(set) var rejections: [Rejection] = [] { willSet { willChange() } }
    public private(set) var log: [String] = [] { willSet { willChange() } }
    public private(set) var universes: [UInt16] = []
    public private(set) var previewUniverses: [UInt16] = []
    public private(set) var timecodeStreams: [UInt16] = []

    /// Called before any property above changes.
    open func willChange() {}

    private struct Source {
        var levels: [UInt8] = []
        var priority = [UInt8](repeating: 100, count: 512) // PF §10.6: 100 until TID_PRIORITY arrives
        var held: [UInt8]?
        var seenNs: Int64 = 0
    }

    private struct Universe {
        var sources: [[UInt8]: Source] = [:] // keyed by the 8-byte Sender-ID (PF §10.6)
        var out = [UInt8](repeating: 0, count: 512)
        var winners = Set<[UInt8]>()
        var frame: UniverseFrame?
        var syncFrom: [UInt8]? // SYNC_ACTIVE with this Sender-ID (PF §10.7.2)
        var syncNs: Int64 = 0
    }

    private var socket: UDPSocket?
    private var timer: Timer?
    private var ks: SymmetricKey?
    private var secure = false
    private var scope = "local"
    private var state: [UInt16: Universe] = [:]
    private var previewState: [UInt16: PreviewFrame] = [:]
    private var tcState: [UInt16: TimecodeFrame] = [:]
    private var sessions: [[UInt8]: UInt32] = [:] // per TUID
    private var lanes: [[UInt8]: (session: UInt32, seq: UInt32)] = [:] // per Sender-ID
    private var c = ReceiverCounters()
    private var recent: [Rejection] = []
    private var budget = 0
    private var tapCount = 0
    private var windowStart: Int64 = 0

    public init(settings: SecurityConfig, tuid: [UInt8] = Identity.tuid("receiver")) {
        self.settings = settings
        self.tuid = tuid
    }

    public static func monotonicNs() -> Int64 { Int64(DispatchTime.now().uptimeNanoseconds) }

    // MARK: - Lifecycle

    public func start() {
        guard !running else { return }
        do {
            try prepare()
            let s = try UDPSocket(interface: settings.interface)
            socket = s
            var groups = Set(universes.map(SigNetKeys.levelGroup))
            groups.insert(SigNetKeys.timeGroup) // sync and timecode
            if !previewUniverses.isEmpty { groups.insert(SigNetKeys.previewGroup) }
            for g in groups.sorted() { try s.join(g) }
            s.receive(on: .main) { [weak self] bytes, ip in self?.handle(bytes, from: ip) }
            note(2, "rx", "joined \(groups.sorted().joined(separator: " "))")
        } catch {
            stop()
            status = "\(error)"
            return
        }
        running = true
        settings.deviceStarted()
        status = "Receiving \(universes.count) universe(s) · \(settings.mode.rawValue) Mode · scope \(scope)"
        note(2, "rx", "started tuid=\(Identity.hex(tuid)) mode=\(settings.mode.rawValue) scope=\(scope)")
        timer = Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { [weak self] _ in self?.tick() }
    }

    /// Parses the lists, derives Ks and clears all receive state.
    func prepare() throws {
        universes = try Self.parseList(universesText, max: 63999, what: "universe")
        previewUniverses = try Self.parseList(previewText, max: 63999, what: "preview universe")
        timecodeStreams = try Self.parseList(timecodeText, max: 255, what: "timecode stream")
        guard !universes.isEmpty else { throw SigNetError("Enter at least one universe") }
        if !universes.contains(UInt16(clamping: selected)) { selected = Int(universes[0]) }
        secure = settings.mode == .secure
        scope = settings.scopeOrDefault
        ks = nil
        if secure {
            var k0 = try settings.rootKey()
            ks = SigNetKeys.sender(k0: k0) // PF §7.3.2: K0 is not kept
            wipe(&k0)
        }
        state = Dictionary(uniqueKeysWithValues: universes.map { ($0, Universe()) })
        previewState = [:]
        tcState = [:]
        sessions = [:]
        lanes = [:]
        c = ReceiverCounters()
        recent = []
        budget = Self.floodBudget
        nowNs = Self.monotonicNs()
        tapCount = 0
        windowStart = nowNs
    }

    public func stop() {
        timer?.invalidate()
        timer = nil
        socket?.close()
        socket = nil
        ks = nil
        if running {
            status = "Stopped"
            settings.deviceStopped()
            note(2, "rx", "stopped")
        }
        running = false
        frame = nil
        fps = 0
    }

    public func clearLog() { log.removeAll() }

    /// Switches the timecode list to every stream heard since Start.
    public func scanTimecode() {
        guard running else { return }
        timecodeStreams = tcState.keys.sorted()
        timecodes = tcState
    }

    public func refreshDiagnostics() {
        counters = c
        rejections = recent
    }

    // MARK: - Packet path (PF §8.6)

    /// ponytail: packets per 50 ms tick before the rest are dropped unprocessed (PF §8.6 step 9 DoS note).
    static let floodBudget = 4000

    func handle(_ b: [UInt8], from ip: String) {
        budget -= 1
        guard budget >= 0 else { c.floodDropped += 1; return }
        let now = Self.monotonicNs()
        func drop(_ r: DropReason, _ why: String = "") {
            c.drops[r.rawValue] += 1
            c.rejectionsRecorded += 1
            recent.append(Rejection(monotonicNs: now, reason: r, length: b.count, header: Array(b.prefix(24))))
            if recent.count > 32 { recent.removeFirst() }
            note(1, "rx", "drop reason=\(r.name) len=\(b.count) from=\(ip)\(why.isEmpty ? "" : " " + why)")
        }
        if b.count >= 4, b[0] >> 6 != 1 { return drop(.badVersion) }
        if b.count >= 4, b[1] != 0x02 { return drop(.badCode) }
        let p: ManagerPacket
        do { p = try ManagerPacket.decode(b) } catch {
            let why = "\(error)"
            return drop(why.hasPrefix("security mode") ? .unsupportedMode : .malformed, why) // ManagerCodec's wording
        }
        if p.mode == 0xFF { c.beacons += 1; return } // offboarded beacon: presence only (PF §8.6 1b)
        if (p.mode == 0) != secure { return drop(.modeMismatch, "mode=\(p.mode)") } // PF §8.6 1c/1d

        let s = p.segs
        guard s.count >= 4, s[0] == "sig-net", s[1] == "v1" else { return drop(.badURI, p.uri) }
        guard s[2] == scope else { return drop(.routingScope, p.uri) }
        func index(_ max: Int) -> UInt16? { // decimal, no leading zeros (PF §8.2)
            guard s.count == 5, let v = UInt16(s[4]), String(v) == s[4], (1...max).contains(Int(v)) else { return nil }
            return v
        }
        let n: UInt16
        switch s[3] {
        case "level", "preview":
            guard let u = index(63999) else { return drop(.badURI, p.uri) }
            // Folded groups carry other universes: not ours, not an error (PF §9.2.3).
            guard s[3] == "level" ? state[u] != nil : previewUniverses.contains(u) else { return }
            n = u
        case "timecode":
            guard let t = index(255) else { return drop(.badURI, p.uri) }
            n = t
        case "sync":
            guard s.count == 4 else { return drop(.badURI, p.uri) }
            n = 0
        default: return // poll, node, manager…: not for a data-plane Node
        }

        let sender = p.tuid + mgrBE16(p.ep)
        if secure { // PF §8.6 steps 8–9; Open Mode skips them (1d)
            if let last = sessions[p.tuid], p.session < last { return drop(.replaySession, "session=\(p.session) stored=\(last)") }
            if let l = lanes[sender], p.session == l.session, p.seq <= l.seq { return drop(.replaySeq, "seq=\(p.seq) stored=\(l.seq)") }
            guard let ks, p.verify(ks) else { return drop(.authFailed, p.uri) }
        }
        guard let tlvs = ManagerTLV.decode(p.payload) else { return drop(.payloadInvalid, "TLV overruns payload") }
        if let why = Self.invalid(s[3], tlvs) { return drop(.payloadInvalid, why) }
        if secure { // PF §8.6 step 10: commit only after the HMAC verifies
            sessions[p.tuid] = max(sessions[p.tuid] ?? 0, p.session)
            lanes[sender] = (p.session, p.seq)
        }
        c.accepted += 1
        note(0, "rx", "accept \(p.uri) sender=\(Identity.hex(p.tuid)):\(p.ep) seq=\(p.seq)")

        switch s[3] {
        case "level": level(n, sender, tlvs, now)
        case "preview":
            guard let v = tlvs.last(where: { $0.tid == 0x0103 })?.value else { return }
            previewState[n] = PreviewFrame(frame: UniverseFrame(slotCount: v.count, sourceCount: 1, publishedNs: now),
                                           levels: v + [UInt8](repeating: 0, count: 512 - v.count))
        case "timecode":
            guard let v = tlvs.last(where: { $0.tid == 0x0202 })?.value else { return }
            if tcState[n]?.lost == true { note(2, "timecode", "resumed stream=\(n)") }
            tcState[n] = TimecodeFrame(value: v, seenNs: now)
        default: sync(sender, now)
        }
    }

    /// nil when every TID this receiver uses has a legal length and value (PF §10.1.3, §11.2).
    /// Unknown TIDs are skipped, so later revisions can add TLVs to these URIs.
    static func invalid(_ resource: String, _ tlvs: [ManagerTLV]) -> String? {
        for t in tlvs {
            switch (resource, t.tid) {
            case ("level", 0x0101), ("preview", 0x0103):
                if !(1...512).contains(t.value.count) { return "TID 0x\(String(t.tid, radix: 16)) length \(t.value.count)" }
            case ("level", 0x0102):
                if !(1...512).contains(t.value.count) || t.value.contains(where: { $0 > 200 }) { return "TID_PRIORITY length \(t.value.count) or value > 200" }
            case ("timecode", 0x0202):
                let v = t.value
                guard v.count == 5, v[4] <= 0x0A, v[0] < 24, v[1] < 60, v[2] < 60,
                      Int(v[3]) < [24, 25, 30, 30, 48, 50, 60, 60, 100, 120, 120][Int(v[4])] else { return "TID_TIMECODE \(mgrHex(v))" }
            case ("sync", 0x0201):
                if !t.value.isEmpty { return "TID_SYNC length \(t.value.count)" }
            default: continue
            }
        }
        return nil
    }

    private func level(_ n: UInt16, _ sender: [UInt8], _ tlvs: [ManagerTLV], _ now: Int64) {
        var u = state[n]!
        defer { state[n] = u }
        if u.sources[sender] == nil {
            guard u.sources.count < sourcesPerUniverse else {
                c.mergeSaturations += 1
                return note(3, "merge", "source limit universe=\(n) sender=\(Self.id(sender))")
            }
            note(2, "merge", "new source universe=\(n) sender=\(Self.id(sender))")
        }
        var src = u.sources[sender] ?? Source()
        var held = false
        for t in tlvs { // TID_PRIORITY comes first in the packet (PF §10.6)
            switch t.tid {
            case 0x0102:
                // ponytail: §10.6 sets unaddressed slots to 0 (not driven), §11.2.2 to 100; we take §10.6.
                src.priority = t.value.count == 1 ? [UInt8](repeating: t.value[0], count: 512)
                    : t.value + [UInt8](repeating: 0, count: 512 - t.value.count)
            case 0x0101:
                if u.syncFrom == sender { src.held = t.value; held = true } else { src.levels = t.value }
            default: continue
            }
        }
        src.seenNs = now
        u.sources[sender] = src
        if !held { publish(&u, n, now) }
    }

    /// PF §10.6 / ETC 0xDD per-slot merge: highest priority wins, HTP between equal priorities;
    /// priority 0 means "not driven".
    private func publish(_ u: inout Universe, _ n: UInt16, _ now: Int64) {
        var out = [UInt8](repeating: 0, count: 512), best = [UInt8](repeating: 0, count: 512), slots = 0
        for s in u.sources.values {
            slots = max(slots, s.levels.count)
            for (i, v) in s.levels.enumerated() where s.priority[i] > 0 {
                if s.priority[i] > best[i] || s.priority[i] == best[i] && v > out[i] { best[i] = s.priority[i]; out[i] = v }
            }
        }
        u.winners = Set(u.sources.filter { _, s in s.levels.indices.contains { s.priority[$0] > 0 && s.priority[$0] == best[$0] && s.levels[$0] == out[$0] } }.keys)
        u.out = out
        u.frame = UniverseFrame(slotCount: slots, sourceCount: u.winners.count, publishedNs: now)
        if n == UInt16(clamping: selected) { tapCount += 1 }
    }

    /// PF §10.7.2: a sync from the Sender driving a universe makes it SYNC_ACTIVE and releases held levels.
    private func sync(_ sender: [UInt8], _ now: Int64) {
        for n in state.keys {
            var u = state[n]!
            guard u.syncFrom == sender || u.winners.contains(sender) else { continue }
            if u.syncFrom == nil { note(2, "sync", "active universe=\(n) sender=\(Self.id(sender))") }
            u.syncFrom = sender
            u.syncNs = now
            if let h = u.sources[sender]?.held {
                u.sources[sender]!.levels = h
                u.sources[sender]!.held = nil
                publish(&u, n, now)
            }
            state[n] = u
        }
    }

    private static func id(_ sender: [UInt8]) -> String { Identity.hex(Array(sender.prefix(6))) + ":\(mgrU16(sender.suffix(2)))" }

    // MARK: - Timers and UI

    func tick() {
        let now = Self.monotonicNs()
        budget = Self.floodBudget
        for n in state.keys {
            var u = state[n]!
            let lost = u.sources.filter { now - $0.value.seenNs > 3_000_000_000 }.keys // <universe_lost_timeout> 3 s
            for k in lost { u.sources[k] = nil; note(2, "merge", "source lost universe=\(n) sender=\(Self.id(k))") }
            if let from = u.syncFrom, now - u.syncNs > 250_000_000 { // <sync_lost_timeout> 250 ms (PF §10.7.3)
                note(2, "sync", "timeout universe=\(n)")
                u.syncFrom = nil
                if let h = u.sources[from]?.held { u.sources[from]!.levels = h; u.sources[from]!.held = nil; publish(&u, n, now) }
            }
            if !lost.isEmpty {
                if u.sources.isEmpty { u.frame?.sourceCount = 0; u.winners = [] } // hold the last look
                else { publish(&u, n, now) }
            }
            state[n] = u
        }
        for (s, tc) in tcState where !tc.lost && now - tc.seenNs > 1_000_000_000 { // <timecode_lost_timeout> 1 s
            tcState[s]!.lost = true
            note(3, "timecode", "lost stream=\(s)")
        }

        nowNs = now
        if let u = state[UInt16(clamping: selected)], let f = u.frame {
            levels = u.out
            frame = f
        } else {
            frame = nil
        }
        if now - windowStart >= 1_000_000_000 {
            fps = Double(tapCount) * 1e9 / Double(now - windowStart)
            tapCount = 0
            windowStart = now
        }
        timecodes = tcState.filter { timecodeStreams.contains($0.key) }
        previews = previewState
        if autoDiagnostics { refreshDiagnostics() }
    }

    private func note(_ level: Int, _ component: String, _ message: String) {
        guard level >= logLevel else { return }
        log.append(String(format: "%.3f ", Double(Self.monotonicNs()) / 1e9) + Self.levelNames[level] + " \(component): \(message)")
        if log.count > 500 { log.removeFirst(log.count - 500) }
    }

    /// Frames per second for a PF §11.2.5 rate type.
    public static func timecodeFPS(_ rate: UInt8) -> Double {
        rate <= 0x0A ? [24, 25, 29.97, 30, 48, 50, 59.94, 60, 100, 119.88, 120][Int(rate)] : 0
    }

    /// "1-4, 10" -> [1, 2, 3, 4, 10]; unique, sorted, each in 1...max.
    public static func parseList(_ text: String, max: UInt16, what: String) throws -> [UInt16] {
        var out = Set<UInt16>()
        for item in text.split(separator: ",") where !item.allSatisfy(\.isWhitespace) {
            let ends = item.split(separator: "-", omittingEmptySubsequences: false)
                .map { UInt16($0.trimmingCharacters(in: .whitespaces)) }
            guard (1...2).contains(ends.count), let lo = ends.first!, let hi = ends.last!, 1 <= lo, lo <= hi, hi <= max
            else { throw SigNetError("Bad \(what) “\(item.trimmingCharacters(in: .whitespaces))” (1–\(max))") }
            out.formUnion(lo...hi)
        }
        return out.sorted()
    }
}

// MARK: - Self test

extension ReceiverEngine {
    /// Appendix G vector plus hand-built packets through the parse path: levels, merge, sync,
    /// timecode and every drop reason a sender can provoke. nil = pass.
    public static func knownAnswers() -> String? {
        let kat = SecurityConfig()
        kat.mode = .secure
        kat.passphrase = "SigNetT3stVector1!" // Appendix G
        guard var k0 = try? kat.rootKey() else { return "K0 derivation failed" }
        let ks = SigNetKeys.sender(k0: k0)
        wipe(&k0)
        guard ks.withUnsafeBytes({ mgrHex($0) }) == "23ffd543990f2253c884af7fc6c47255aa1606a4f2f30e082381bb17c9a6c242" else { return "KAT: Ks" }
        guard (try? parseList("1-4, 10,3", max: 63999, what: "")) == [1, 2, 3, 4, 10], (try? parseList("0", max: 63999, what: "")) == nil,
              (try? parseList("5-2", max: 63999, what: "")) == nil else { return "universe list parser" }
        guard SigNetKeys.levelGroup(1) == "239.254.0.1", SigNetKeys.levelGroup(109) == "239.254.0.109",
              SigNetKeys.levelGroup(110) == "239.254.0.1", SigNetKeys.levelGroup(63999) == "239.254.0.16" else { return "folding" }

        let tx: [UInt8] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC], tx2: [UInt8] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBD]
        func packet(_ path: [String], _ tlvs: [ManagerTLV], tuid: [UInt8] = tx, ep: UInt16 = 1, mode: UInt8 = 0,
                    session: UInt32 = 5, seq: UInt32, scope: String = "local") -> ManagerPacket {
            var p = ManagerPacket()
            p.mid = UInt16(truncatingIfNeeded: seq)
            p.segs = ["sig-net", "v1", scope] + path
            p.mode = mode
            p.tuid = tuid
            p.ep = ep
            p.payload = ManagerTLV.encode(tlvs)
            if mode == 0 { p.session = session; p.seq = seq; p.sign(ks) }
            return p
        }
        func lvl(_ v: [UInt8]) -> ManagerTLV { ManagerTLV(tid: 0x0101, value: v) }
        func pri(_ v: [UInt8]) -> ManagerTLV { ManagerTLV(tid: 0x0102, value: v) }

        let vector = packet(["level", "1"], [lvl([0xFF, 0x80, 0x00])], seq: 0xA2)
        guard mgrHex(vector.auth) == "c7126005fb474564dc7ce4c122e3e60d4b13dedeb8c6ad1e8daa51e5c66a8225" else { return "KAT: HMAC tag \(mgrHex(vector.auth))" }

        let rx = ReceiverEngine(settings: kat, tuid: [0x7F, 0xF0, 0, 0, 0, 1])
        rx.universesText = "1-2"
        rx.timecodeText = "7"
        guard (try? rx.prepare()) != nil else { return "prepare" }
        // want: nil = accepted, .some(nil) = silently ignored, else that drop reason.
        func feed(_ label: String, _ p: ManagerPacket, _ want: DropReason??) -> String? { feed(label, p.encode(), want) }
        func feed(_ label: String, _ b: [UInt8], _ want: DropReason??) -> String? {
            let before = rx.c
            rx.handle(b, from: "selftest")
            rx.tick()
            let got = rx.c.accepted > before.accepted ? "accepted" : rx.c.dropsTotal > before.dropsTotal ? rx.recent.last!.reason.name : "ignored"
            let wanted = want.map { $0?.name ?? "ignored" } ?? "accepted"
            return got == wanted ? nil : "\(label): want \(wanted), got \(got)"
        }
        func levels(_ want: [UInt8], sources: Int) -> String? {
            guard let f = rx.frame else { return "no frame" }
            return Array(rx.levels.prefix(want.count)) == want && f.sourceCount == sources ? nil
                : "levels \(Array(rx.levels.prefix(want.count))) sources \(f.sourceCount), want \(want) / \(sources)"
        }
        var forged = packet(["level", "1"], [lvl([1])], seq: 0xA3)
        forged.auth[0] ^= 1
        var version = vector.encode()
        version[0] = 0x90
        let sync = ManagerTLV(tid: 0x0201)
        let steps: [() -> String?] = [
            { feed("vector", vector, nil) }, { levels([0xFF, 0x80, 0x00], sources: 1) },
            { feed("replayed packet", vector, .replaySeq) },
            { feed("bad HMAC", forged, .authFailed) },
            { feed("old session", packet(["level", "1"], [lvl([1])], session: 4, seq: 0xFFFF), .replaySession) },
            { feed("open packet", packet(["level", "1"], [lvl([1])], mode: 1, seq: 0), .modeMismatch) },
            { feed("other scope", packet(["level", "1"], [lvl([1])], seq: 0xA4, scope: "hall-b"), .routingScope) },
            { feed("CoAP version", version, .badVersion) },
            { feed("leading zero", packet(["level", "01"], [lvl([1])], seq: 0xA5), .badURI) },
            { feed("priority 201", packet(["level", "1"], [pri([201]), lvl([1])], seq: 0xA6), .payloadInvalid) },
            { feed("unsubscribed universe", packet(["level", "3"], [lvl([1])], seq: 0xA7), .some(nil)) },
            { levels([0xFF, 0x80, 0x00], sources: 1) }, // nothing dropped reached the output
            // Merge on universe 2: priority beats level, HTP among equals.
            { rx.selected = 2; return feed("tx 150", packet(["level", "2"], [pri([150]), lvl([10, 10])], seq: 0xA8), nil) },
            { feed("tx2 100", packet(["level", "2"], [lvl([200, 200, 200])], tuid: tx2, seq: 1), nil) },
            { levels([10, 10, 200], sources: 2) },
            { feed("tx 100", packet(["level", "2"], [pri([100]), lvl([10, 10])], seq: 0xA9), nil) },
            { levels([200, 200, 200], sources: 1) },
            // Sync (PF §10.7.2): the driving sender's sync makes universe 1 hold levels until the next sync.
            { rx.selected = 1; return feed("sync", packet(["sync"], [sync], seq: 0xAA), nil) },
            { feed("held level", packet(["level", "1"], [lvl([1, 2, 3])], seq: 0xAB), nil) },
            { levels([0xFF, 0x80, 0x00], sources: 1) },
            { feed("sync", packet(["sync"], [sync], seq: 0xAC), nil) },
            { levels([1, 2, 3], sources: 1) },
            { feed("timecode", packet(["timecode", "7"], [ManagerTLV(tid: 0x0202, value: [1, 2, 3, 24, 0x01])], ep: 9, seq: 1), nil) },
            { rx.timecodes[7]?.value == [1, 2, 3, 24, 1] ? nil : "timecode \(rx.timecodes[7]?.value ?? [])" },
            { feed("timecode frame 25 @25", packet(["timecode", "7"], [ManagerTLV(tid: 0x0202, value: [1, 2, 3, 25, 0x01])], ep: 9, seq: 2), .payloadInvalid) },
        ]
        for step in steps { if let why = step() { return why } }

        // An Open-Mode receiver takes Open packets and refuses signed ones.
        let orx = ReceiverEngine(settings: SecurityConfig(), tuid: [0x7F, 0xF0, 0, 0, 0, 2])
        guard (try? orx.prepare()) != nil else { return "prepare open" }
        orx.handle(packet(["level", "1"], [lvl([42])], mode: 1, seq: 0).encode(), from: "selftest")
        orx.handle(vector.encode(), from: "selftest")
        orx.tick()
        guard orx.levels[0] == 42, orx.c.accepted == 1, orx.c.drops[DropReason.modeMismatch.rawValue] == 1 else { return "open receiver" }
        return nil
    }
}
