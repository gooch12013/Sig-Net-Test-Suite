import Crypto
import Foundation

/// One standalone Sig-Net Sender (PF §10.6–§10.8) transmitting `count` consecutive universes from
/// `universe`, all on Sender endpoint 1 so one TID_SYNC covers them (§10.7.2 matches the Sender-ID).
/// Timecode uses its own lane, endpoint 2 (§8.6.2). Announces itself and its universes on /node/{tuid}/0
/// (§10.2.5, §11.2.6) but answers no polls (§9.2.2: pure Senders don't subscribe).
/// Main-thread API; every packet goes out on one serial queue. The app's ObservableObject subclass turns
/// `willChange()` into objectWillChange.
open class TransmitterEngine {
    public enum Pattern: String, CaseIterable, Identifiable {
        case off = "Off", chase = "Chase", ramp = "Ramp", random = "Random"
        public var id: Self { self }
    }

    /// PF §11.2.5 rate codes 0x00–0x0A, in code order.
    public static let timecodeRates = ["24", "25", "29.97 DF", "30", "48", "50", "59.94 DF", "60", "100", "119.88 DF", "120"]
    static let millifps: [UInt64] = [24000, 25000, 29970, 30000, 48000, 50000, 59940, 60000, 100_000, 119_880, 120_000]

    public let settings: SecurityConfig
    public var universe = 1 { willSet { willChange() } } // first (primary) universe
    public var count = 1 { willSet { willChange() } didSet { selected = min(selected, count - 1) } }
    public var maxFps = 44 { willSet { willChange() } }
    /// Offset of the universe the fader bank edits; 0 = primary.
    public var selected = 0 { willSet { willChange() } didSet { if selected != oldValue { levels = bank[selected] } } }
    /// Levels of the selected universe.
    public var levels = [UInt8](repeating: 0, count: 512) { willSet { willChange() } didSet { bank[selected] = levels; push(selected) } }
    public var master: Double = 255 { willSet { willChange() } didSet { pushAll() } }
    public var sendPriority = false { willSet { willChange() } didSet { pushAll() } }
    public var priorities = [Int](repeating: 100, count: 16) { willSet { willChange() } didSet { pushAll() } }
    public var sync = false { willSet { willChange() } didSet { let on = sync; q.async { self.syncOn = on } } }
    public var preview = false { willSet { willChange() } }
    public var pattern = Pattern.off { willSet { willChange() } }
    public var patternSpeed = 8.0 { willSet { willChange() } } // steps per second
    public var tcStream = 1 { willSet { willChange() } }
    public var tcRate: UInt8 = 0x01 { willSet { willChange() } }
    public private(set) var tcRunning = false { willSet { willChange() } }
    public private(set) var tcDisplay = "00:00:00:00" { willSet { willChange() } }
    public private(set) var syncFps: UInt16 = 0 { willSet { willChange() } }
    public private(set) var running = false { willSet { willChange() } }
    public private(set) var status = "Stopped" { willSet { willChange() } }
    public private(set) var sendFailures: UInt64 = 0 { willSet { willChange() } }

    /// Called before any property above changes.
    open func willChange() {}

    public let tuid: [UInt8]
    private var bank = [[UInt8]](repeating: [UInt8](repeating: 0, count: 512), count: 16)
    private var tickTimer: Timer?
    private var ticks = 0
    private var patternPhase = 0.0

    // Everything below is touched only on q.
    private let q = DispatchQueue(label: "signet.sender")
    private struct Stream { var level: [UInt8] = [], priority: [UInt8] = [], dirty = true, repeats = 0, last: UInt64 = 0 }
    private var socket: UDPSocket?
    private var scope = "local", first = 1, secure = false
    private var ks: SymmetricKey?, kc: SymmetricKey?
    private var session: UInt32 = 0
    private var lanes: [UInt16: UInt32] = [:] // Sender endpoint → last Seq-Num (§8.3)
    private var mid = UInt16.random(in: 1...0xFFFF)
    private var streams: [Stream] = []
    private var pacer: DispatchSourceTimer?
    private var syncOn = false
    private var nextAnnounce: UInt64 = 0, announced = false
    private var failures: UInt64 = 0
    private var dead = false // Session ID exhausted: no more packets (§8.3)
    // Timecode generator.
    private var tcTimer: DispatchSourceTimer?
    private var tcBase = 0 // frames counted before the current run
    private var tcStart: UInt64 = 0 // uptime ns at the current run's start
    private var tcLast = -1
    private var tcFrozen: (stream: UInt16, value: [UInt8])?, tcSentAt: UInt64 = 0

    /// `role` picks the persisted TUID; distinct roles are distinct merge sources.
    public init(settings: SecurityConfig, role: String = "sender-v2") {
        self.settings = settings
        tuid = Identity.tuid(role)
    }

    public func start() {
        guard !running else { return }
        do {
            try create()
        } catch {
            stop()
            status = "\(error)"
            return
        }
        running = true
        settings.deviceStarted()
        let range = count == 1 ? "universe \(universe)" : "universes \(universe)–\(universe + count - 1)"
        status = "Transmitting \(range) · \(settings.mode.rawValue) Mode · scope \(settings.scopeOrDefault)"
        tickTimer = Timer(timeInterval: 1.0 / 30, repeats: true) { [weak self] _ in self?.tick() }
        RunLoop.main.add(tickTimer!, forMode: .common) // keep ticking while a fader is dragged
    }

    private func create() throws {
        let secure = settings.mode == .secure
        var k0 = try settings.rootKey()
        defer { wipe(&k0) }
        let session = secure ? try SigNetKeys.nextSession(tuid) : 0
        let socket = try UDPSocket(interface: settings.interface, port: 0) // ephemeral: never steals 5683 unicast
        // §10.7.1 leaves >= 5 ms between a frame's last TID_LEVEL and its TID_SYNC.
        syncFps = UInt16(clamping: min(maxFps, 200))
        let fps = max(1, maxFps), on = sync
        let first = universe, scope = settings.scopeOrDefault
        let streams = (0..<count).map { output($0) }
        let ks = secure ? SigNetKeys.sender(k0: k0) : nil, kc = secure ? SigNetKeys.citizen(k0: k0) : nil
        q.sync {
            (self.socket, self.secure, self.session, self.ks, self.kc) = (socket, secure, session, ks, kc)
            (self.first, self.scope, syncOn, lanes, failures, dead, announced) = (first, scope, on, [:], 0, false, false)
            self.streams = streams.map { Stream(level: $0.level, priority: $0.priority) }
            nextAnnounce = DispatchTime.now().uptimeNanoseconds + UInt64.random(in: 0...1_000_000_000) // <poll_backoff_max>
            let t = DispatchSource.makeTimerSource(queue: q)
            t.schedule(deadline: .now(), repeating: .nanoseconds(1_000_000_000 / fps), leeway: .microseconds(500))
            t.setEventHandler { [weak self] in self?.pace() }
            pacer = t
            t.resume()
        }
    }

    public func stop() {
        stopTimecode()
        tickTimer?.invalidate()
        tickTimer = nil
        q.sync {
            pacer?.cancel()
            pacer = nil
            if announced { announceUniverses(join: false) } // graceful Leave (§11.2.6)
            socket?.close()
            socket = nil
            ks = nil
            kc = nil
            streams = []
            tcFrozen = nil
        }
        if running {
            status = "Stopped"
            settings.deviceStopped()
        }
        running = false
        sendFailures = 0
    }

    /// Sets every channel of the selected universe.
    public func setAll(_ value: UInt8) {
        levels = [UInt8](repeating: value, count: levels.count)
    }

    private func output(_ i: Int) -> (level: [UInt8], priority: [UInt8]) {
        (bank[i].map { UInt8((Double($0) * master / 255).rounded()) },
         sendPriority ? [UInt8(clamping: priorities[i])] : []) // empty = no TID_PRIORITY
    }

    private func push(_ i: Int) {
        guard running, i < count else { return }
        let out = output(i)
        q.async { [self] in
            guard i < streams.count, streams[i].level != out.level || streams[i].priority != out.priority else { return }
            streams[i].level = out.level
            streams[i].priority = out.priority
            streams[i].dirty = true
        }
    }

    private func pushAll() { (0..<count).forEach(push) }

    /// Level of `channel` (1–512) in universe `u`; nil when this sender doesn't send `u`.
    public func level(universe u: Int, channel: Int) -> UInt8? {
        let i = u - universe
        guard (0..<count).contains(i), (1...512).contains(channel) else { return nil }
        return bank[i][channel - 1]
    }

    /// Sets `channel` (1–512) in universe `u`; false when this sender doesn't send `u`.
    @discardableResult public func setLevel(universe u: Int, channel: Int, to value: UInt8) -> Bool {
        let i = u - universe
        guard (0..<count).contains(i), (1...512).contains(channel) else { return false }
        if i == selected { levels[channel - 1] = value; return true }
        willChange()
        bank[i][channel - 1] = value
        push(i)
        return true
    }

    /// 30 Hz main-thread tick: test pattern, preview at 10 Hz, stats at 1 Hz.
    private func tick() {
        guard running else { return }
        ticks += 1
        if pattern != .off {
            let before = Int(patternPhase)
            patternPhase += patternSpeed / 30
            let step = Int(patternPhase)
            if step != before {
                switch pattern {
                case .off: break
                case .chase: levels = (0..<512).map { $0 == step % 512 ? 255 : 0 }
                case .ramp: levels = [UInt8](repeating: UInt8(truncatingIfNeeded: step * 8), count: 512) // 32-step sawtooth
                case .random: levels = (0..<512).map { _ in .random(in: 0...255) }
                }
            }
        }
        if preview, ticks % 3 == 0 {
            let u = universe + selected, out = output(selected).level
            q.async { [self] in send(["preview", "\(u)"], ep: 1, [ManagerTLV(tid: 0x0103, value: out)], key: ks, to: SigNetKeys.previewGroup) }
        }
        if ticks % 30 == 0 {
            let n = q.sync { failures }
            if n != sendFailures { sendFailures = n }
        }
    }

    // MARK: - Output (q only)

    /// One pacer period (§10.6.3): a changed universe goes out now, then 3 identical repeats at the frame
    /// rate, then a 1 Hz keep-alive. A sync follows any frame that sent levels, >= 5 ms later (§10.7.1).
    private func pace() {
        let now = DispatchTime.now().uptimeNanoseconds
        var sent = false
        for i in streams.indices {
            if streams[i].dirty { streams[i].dirty = false; streams[i].repeats = 3 }
            else if streams[i].repeats > 0 { streams[i].repeats -= 1 }
            else if now - streams[i].last < 900_000_000 { continue } // a period early, so never under 1 Hz
            streams[i].last = now
            sent = true
            let s = streams[i]
            // §10.6: TID_PRIORITY before TID_LEVEL.
            let tlvs = (s.priority.isEmpty ? [] : [ManagerTLV(tid: 0x0102, value: s.priority)]) + [ManagerTLV(tid: 0x0101, value: s.level)]
            send(["level", "\(first + i)"], ep: 1, tlvs, key: ks, to: SigNetKeys.levelGroup(first + i))
        }
        if sent, syncOn {
            q.asyncAfter(deadline: .now() + .milliseconds(5)) { [self] in
                send(["sync"], ep: 1, [ManagerTLV(tid: 0x0201)], key: ks, to: SigNetKeys.timeGroup)
            }
        }
        if tcTimer == nil, let f = tcFrozen, now - tcSentAt >= 1_000_000_000 { sendTimecode(f.stream, f.value) } // §10.8.1 paused keep-alive
        if now >= nextAnnounce {
            if !announced { announce() }
            announced = true
            announceUniverses(join: true)
            nextAnnounce = now + 5_000_000_000 // <universe_announce_interval>
        }
    }

    /// §10.2.5 on-boot notification, signed with Kc.
    private func announce() {
        let tlvs = [
            ManagerTLV(tid: 0x0002, value: tuid + mgrBE32(ManagerEngine.soem) + [0, 0]), // TID_POLL_REPLY, CHANGE_COUNT 0
            ManagerTLV(tid: 0x0603, value: [1]), // protocol version
            ManagerTLV(tid: 0x0609, value: mgrBE32(0x82)), // Sender + Open Mode supported
            ManagerTLV(tid: 0x0602, value: mgrBE16(2)), // endpoints 1 (levels) and 2 (timecode)
            ManagerTLV(tid: 0x0606, value: [0]), // default multicast folding
        ]
        send(["node", Identity.hex(tuid), "0"], ep: 0, tlvs, key: kc, to: SigNetKeys.nodeGroup)
    }

    /// §11.2.6 TID_UNIVERSE for every universe, packed in one packet; IP 0.0.0.0 = default folding.
    private func announceUniverses(join: Bool) {
        let tlvs = streams.indices.map { ManagerTLV(tid: 0x0203, value: mgrBE16(UInt16(first + $0)) + [join ? 1 : 2, 0, 0, 0, 0] + mgrBE16(1)) }
        send(["node", Identity.hex(tuid), "0"], ep: 0, tlvs, key: kc, to: SigNetKeys.nodeGroup)
    }

    private func send(_ path: [String], ep: UInt16, _ tlvs: [ManagerTLV], key: SymmetricKey?, to group: String) {
        guard let socket, !dead else { return }
        var seq: UInt32 = 0
        if secure {
            if lanes[ep, default: 0] >= 0xFFFF_FFFE { // §8.3 wrap: new session, every lane restarts at 1
                do { session = try SigNetKeys.nextSession(tuid) } catch {
                    dead = true
                    DispatchQueue.main.async { self.status = "\(error)" }
                    return
                }
                lanes = [:]
            }
            seq = lanes[ep, default: 0] + 1
            lanes[ep] = seq
        }
        let p = Self.packet(scope: scope, path, tuid: tuid, ep: ep, session: session, seq: seq, mid: mid, tlvs, key: key)
        mid = mid == 0xFFFF ? 1 : mid + 1 // never 0: MsgID 0 bypasses the Open-Mode duplicate filter
        do { try socket.send(p.encode(), to: group) } catch { failures += 1 }
    }

    /// A Sender packet (§8.3–§8.5): mode 0x00 signed with `key`, or Open Mode (0x01, session/seq 0) when nil.
    static func packet(scope: String, _ path: [String], tuid: [UInt8], ep: UInt16, session: UInt32, seq: UInt32,
                       mid: UInt16, _ tlvs: [ManagerTLV], key: SymmetricKey?) -> ManagerPacket {
        var p = ManagerPacket()
        p.mid = mid
        p.segs = ["sig-net", "v1", scope] + path
        p.mode = key == nil ? 0x01 : 0x00
        p.tuid = tuid
        p.ep = ep
        if key != nil { (p.session, p.seq) = (session, seq) }
        p.payload = ManagerTLV.encode(tlvs)
        if let key { p.sign(key) }
        return p
    }

    // MARK: - Timecode generator

    private func sendTimecode(_ stream: UInt16, _ tc: [UInt8]) {
        send(["timecode", "\(stream)"], ep: 2, [ManagerTLV(tid: 0x0202, value: tc)], key: ks, to: SigNetKeys.timeGroup)
        tcFrozen = (stream, tc)
        tcSentAt = DispatchTime.now().uptimeNanoseconds
    }

    public func startTimecode() {
        guard running, !tcRunning else { return }
        tcRunning = true
        let stream = UInt16(clamping: tcStream), rate = tcRate
        let millifps = Self.millifps[Int(min(rate, 0x0A))]
        q.async { [self] in
            tcStart = DispatchTime.now().uptimeNanoseconds
            tcLast = -1
            let timer = DispatchSource.makeTimerSource(queue: q)
            // Frame index comes from elapsed time, so timer jitter never accumulates.
            timer.schedule(deadline: .now(), repeating: .nanoseconds(Int(1_000_000_000_000 / millifps)), leeway: .microseconds(500))
            timer.setEventHandler { [self] in
                let n = tcBase + Int((DispatchTime.now().uptimeNanoseconds - tcStart) * millifps / 1_000_000_000_000)
                guard n != tcLast else { return }
                tcLast = n
                let tc = Timecode.value(frame: n, rate: rate)
                sendTimecode(stream, tc)
                let text = Self.format(tc)
                DispatchQueue.main.async { self.tcDisplay = text }
            }
            tcTimer = timer
            timer.resume()
        }
    }

    public func stopTimecode() {
        tcRunning = false
        q.async { [self] in
            tcTimer?.cancel()
            tcTimer = nil
            if tcLast >= 0 { tcBase = tcLast + 1 }
            tcLast = -1
        }
    }

    public func resetTimecode() {
        q.async { [self] in
            tcBase = 0
            tcStart = DispatchTime.now().uptimeNanoseconds
            tcLast = -1
            if tcTimer == nil, let f = tcFrozen { tcFrozen = (f.stream, [0, 0, 0, 0, f.value[4]]) } // keep-alive the reset value
        }
        tcDisplay = "00:00:00:00"
    }

    private static func format(_ tc: [UInt8]) -> String {
        String(format: "%02d:%02d:%02d", tc[0], tc[1], tc[2]) + ([0x02, 0x06, 0x09].contains(tc[4]) ? ";" : ":") + String(format: "%02d", tc[3])
    }
}

// MARK: - Self test (sig-net --selftest)

extension TransmitterEngine {
    /// PF Annex G vectors (Ks, Kc, the /level/1 HMAC input and tag), codec round trip and §9.2.3 folding. nil = pass.
    public static func knownAnswers() -> String? {
        let s = SecurityConfig()
        s.mode = .secure
        s.passphrase = "SigNetT3stVector1!"
        guard var k0 = try? s.rootKey() else { return "K0 derivation failed" }
        let ks = SigNetKeys.sender(k0: k0), kc = SigNetKeys.citizen(k0: k0)
        wipe(&k0)
        let hex = { (k: SymmetricKey) in k.withUnsafeBytes { mgrHex($0) } }
        guard hex(ks) == "23ffd543990f2253c884af7fc6c47255aa1606a4f2f30e082381bb17c9a6c242" else { return "Ks \(hex(ks))" }
        guard hex(kc) == "eac261f8782065387816c0c9ea72aa8083565eb871a3392363a5b31611a26f81" else { return "Kc \(hex(kc))" }
        let node: [UInt8] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]
        let p = packet(scope: "local", ["level", "1"], tuid: node, ep: 1, session: 5, seq: 0xA2, mid: 7,
                       [ManagerTLV(tid: 0x0101, value: [0xFF, 0x80, 0x00])], key: ks)
        guard mgrHex(p.macInput) == "2f7369672d6e65742f76312f6c6f63616c2f6c6576656c2f3100123456789abc0001000000000005000000a201010003ff8000"
        else { return "HMAC input \(mgrHex(p.macInput))" }
        guard mgrHex(p.auth) == "c7126005fb474564dc7ce4c122e3e60d4b13dedeb8c6ad1e8daa51e5c66a8225" else { return "HMAC tag \(mgrHex(p.auth))" }
        guard let back = try? ManagerPacket.decode(p.encode()), back.verify(ks), !back.verify(kc), back.uri == "/sig-net/v1/local/level/1",
              back.ep == 1, back.session == 5, back.seq == 0xA2 else { return "signed level packet did not round-trip" }
        let open = packet(scope: "local", ["sync"], tuid: node, ep: 1, session: 5, seq: 9, mid: 8, [ManagerTLV(tid: 0x0201)], key: nil)
        guard let o = try? ManagerPacket.decode(open.encode()), o.mode == 1, o.auth.isEmpty, o.session == 0, o.seq == 0,
              ManagerTLV.decode(o.payload) == [ManagerTLV(tid: 0x0201)] else { return "open sync packet did not round-trip" }
        for (u, last) in [(1, 1), (109, 109), (110, 1), (219, 1), (63999, 16)] where SigNetKeys.levelGroup(u) != "239.254.0.\(last)" {
            return "universe \(u) → \(SigNetKeys.levelGroup(u))"
        }
        return nil
    }

    /// A live Sender on universes 201–202 heard by a plain socket: every packet decodes and (Secure) verifies with the
    /// right key, seq rises per lane, TID_PRIORITY precedes TID_LEVEL, sync, timecode and the announces appear. nil = pass.
    public static func loopTest(settings s: SecurityConfig) -> String? {
        var k0 = (try? s.rootKey()) ?? []
        let ks = SigNetKeys.sender(k0: k0), kc = SigNetKeys.citizen(k0: k0)
        wipe(&k0)
        let secure = s.mode == .secure
        let tx = TransmitterEngine(settings: s, role: "selftest-sender")
        guard let rx = try? UDPSocket(interface: s.interface) else { return "listen socket" }
        defer { rx.close() }
        for g in [SigNetKeys.levelGroup(201), SigNetKeys.levelGroup(202), SigNetKeys.timeGroup, SigNetKeys.nodeGroup] {
            do { try rx.join(g) } catch { return "\(error)" }
        }
        var got: [ManagerPacket] = [], problem: String?
        rx.receive(on: .main) { bytes, _ in
            guard let p = try? ManagerPacket.decode(bytes), p.tuid == tx.tuid else { return }
            if secure ? !p.verify(p.segs.count > 3 && p.segs[3] == "node" ? kc : ks) : p.mode != 1 { problem = problem ?? "bad auth on \(p.uri)" }
            got.append(p)
        }
        tx.universe = 201
        tx.count = 2
        tx.sendPriority = true
        tx.priorities[0] = 150
        tx.sync = true
        tx.start()
        guard tx.running else { return "start: \(tx.status)" }
        tx.setAll(42)
        tx.startTimecode()
        ManagerEngine.spin(1.6) { false } // the on-boot announce waits up to 1 s
        tx.stop()
        ManagerEngine.spin(0.3) { false }
        if let problem { return problem }
        var seqs: [UInt16: UInt32] = [:]
        for p in got where secure {
            guard p.seq > seqs[p.ep, default: 0] else { return "seq \(p.seq) not rising on endpoint \(p.ep)" }
            seqs[p.ep] = p.seq
        }
        let tlvs = { (uri: String) in got.filter { $0.uri.hasSuffix(uri) }.compactMap { ManagerTLV.decode($0.payload) } }
        guard tlvs("/level/201").contains(where: { $0.map(\.tid) == [0x0102, 0x0101] && $0[0].value == [150] && $0[1].value.allSatisfy { $0 == 42 } })
        else { return "no priority 150 + level 42 frame on 201" }
        guard tlvs("/level/202").contains(where: { $0.map(\.tid) == [0x0102, 0x0101] && $0[0].value == [100] }) else { return "no frame on 202" }
        guard !tlvs("/sync").isEmpty else { return "no sync" }
        guard got.contains(where: { $0.uri.hasSuffix("/timecode/1") && $0.ep == 2 && $0.payload.count == 9 }) else { return "no timecode on endpoint 2" }
        let node = tlvs("/node/\(Identity.hex(tx.tuid))/0").flatMap { $0 }
        guard node.first?.tid == 0x0002, node.contains(where: { $0.tid == 0x0609 && $0.value == mgrBE32(0x82) }) else { return "no on-boot announce" }
        for cmd: UInt8 in [1, 2] where !node.contains(where: { $0.tid == 0x0203 && $0.value == mgrBE16(202) + [cmd, 0, 0, 0, 0, 0, 1] }) {
            return "no TID_UNIVERSE \(cmd == 1 ? "join" : "leave") for 202"
        }
        return nil
    }
}
