import Crypto
import Foundation

/// A complete, discoverable Sig-Net Node (PF V1.10): a fake fixture with N virtual endpoints, each
/// consuming a universe and hosting a virtual RDM responder (DeviceRDM). Managers discover it
/// (§10.2), GET/SET its parameters (§10.4, proprietary TIDs included) and tunnel RDM to it (§10.5).
/// Built on the Manager's codec: the Node is its counterpart on the same wire.
/// Plain class; the app's ObservableObject subclass turns `willChange()` into objectWillChange.
/// ponytail: everything runs on the main queue (socket reads delivered on main), no locking and no
/// §8.6 step 9 CPU budget; move RX off main if a flood ever matters.
open class DeviceEngine {
    public struct Live { public var levels = [UInt8](repeating: 0, count: 32), slots = 0, sources = 0 }

    /// Proprietary TIDs (PF §10.1.1 manufacturer range 0x8000-0xFF00), answered at the root for
    /// Managers sending Mfg-Code 0x7FF0: a 1-byte level and a 1-32 byte UTF-8 note.
    public static let tidTestLevel: UInt16 = 0x8001, tidTestNote: UInt16 = 0x8002
    static let esta: UInt16 = 0x7FF0 // ESTA prototyping ID: our Mfg-Code and TUID prefix

    public let settings: SecurityConfig
    public let tuid: [UInt8]
    // Configurable while stopped.
    public var modelName = "Sig-Net Test Fixture" { willSet { willChange() } }
    public var label = "Test Fixture" { willSet { willChange() } }
    public var firmwareLabel = "v1.0.0" { willSet { willChange() } }
    public var endpointCount = 2 { willSet { willChange() } }
    public var universes = Array(1...8) { willSet { willChange() } } // endpoint n consumes universes[n - 1]
    public var freshPowerOn = false { willSet { willChange() } }
    public var acceptNetwork = false { willSet { willChange() } }

    public private(set) var running = false { willSet { willChange() } }
    public private(set) var status = "Stopped" { willSet { willChange() } }
    public private(set) var log: [String] = [] { willSet { willChange() } }
    public private(set) var identifying: [Bool] = [] { willSet { willChange() } }
    public private(set) var live: [Live] = [] { willSet { willChange() } }
    public private(set) var changeCount: UInt16 = 0 { willSet { willChange() } }

    /// Called before any property above changes.
    open func willChange() {}

    private var socket: UDPSocket?
    private var timer: Timer?
    private var keys: ManagerKeys?
    private var kmLocal: SymmetricKey?
    private var ks: SymmetricKey?
    private var secure = false, scope = "local", n = 0
    private var session: UInt32 = 0
    private var seqs: [UInt16: UInt32] = [:] // TX lane (reply endpoint) → last seq
    private var mid = UInt16.random(in: 1...0xFFFF)
    private var params: [UInt32: [UInt8]] = [:] // (tid << 16 | endpoint) → stored value
    private var responders: [DeviceRDMResponder] = []
    private var fresh = Freshness()
    private var events: [UInt16: (count: UInt32, ip: [UInt8], sent: Date)] = [:]
    private var bootedAt = Date(), powerOn = Date(), lastPoll = Date(), lastLost = Date(), lastBeacon = Date()
    private var lost = false, offboarded = false
    private var replyGen = 0 // §10.2.3 reply supersession: delayed replies of an older generation are dropped
    private var sources: [[String: (levels: [UInt8], seen: Date)]] = [] // per data EP, by Sender-ID
    private var merged: [[UInt8]] = []                                  // per data EP, held on stream loss
    private var epStatus: [UInt32] = [], statusSent: [Date] = [], statusDirty: [Bool] = []
    private var groups: Set<String> = []
    private var network: (old: [UInt32: [UInt8]], deadline: Date)?
    private let launched = Date()

    public init(settings: SecurityConfig, tuid: [UInt8] = Identity.tuid("device")) {
        self.settings = settings
        self.tuid = tuid
    }

    // MARK: - Lifecycle

    public func start() {
        guard !running else { return }
        do { try boot() } catch {
            stop()
            status = "\(error)"
            return
        }
        running = true
        settings.deviceStarted()
        status = "Running · \(n) endpoints · \(settings.mode.rawValue) Mode · scope \(scope)" + (secure ? " · session \(session)" : "")
        append("Started, TUID \(Identity.hex(tuid))")
        timer = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { [weak self] _ in self?.tick() }
        after(Double.random(in: 0...1)) { $0.transmit("node", lane: 0, $0.presence(), to: "239.254.255.253") } // §10.2.5
    }

    public func stop() {
        timer?.invalidate()
        timer = nil
        socket?.close()
        socket = nil
        keys = nil
        kmLocal = nil
        ks = nil
        network = nil
        replyGen += 1
        if running {
            status = "Stopped"
            append("Stopped")
            settings.deviceStopped()
        }
        running = false
        offboarded = false
        identifying = identifying.map { _ in false }
    }

    private func boot() throws {
        guard settings.ready else { throw SigNetError(settings.passphraseProblem ?? "Settings not ready") }
        secure = settings.mode == .secure
        scope = settings.scopeOrDefault
        n = min(8, max(1, endpointCount))
        if secure {
            var k0 = try settings.rootKey()
            ks = SigNetKeys.sender(k0: k0)
            var k = ManagerKeys(k0: &k0) // wipes k0
            kmLocal = k.kmLocal(tuid)
            keys = k
            try bumpSession()
        }
        seqs = [:]
        fresh = Freshness()
        events = [:]
        lost = false
        offboarded = false
        let d = UserDefaults.standard
        changeCount = UInt16(clamping: d.integer(forKey: stateKey + ".cc"))
        // Factory defaults, then the persisted store (NVR stand-in); the panel's label and universes win (front-panel edits).
        params = [Self.key(0x0607, 0): [0], Self.key(Self.tidTestLevel, 0): [0x80], Self.key(Self.tidTestNote, 0): Array("hello".utf8),
                  Self.key(0x0502, 0): [1], Self.key(0x0503, 0): [0, 0, 0, 0], Self.key(0x0504, 0): [0, 0, 0, 0], Self.key(0x0505, 0): [0, 0, 0, 0],
                  Self.key(0x0581, 0): [1], Self.key(0x0582, 0): [UInt8](repeating: 0, count: 16), Self.key(0x0583, 0): [64],
                  Self.key(0x0584, 0): [UInt8](repeating: 0, count: 16)]
        for e in 1...UInt16(n) {
            for (tid, v) in [(0x0305, [3]), (0x0902, [0]), (0x0903, [0, 0, 0, 0]), (0x0905, [5])] as [(UInt16, [UInt8])] { params[Self.key(tid, e)] = v }
        }
        for (k, v) in d.dictionary(forKey: stateKey + ".params") as? [String: Data] ?? [:] {
            if let key = UInt32(k), key >> 16 != 0x0607 { params[key] = [UInt8](v) }
        }
        params[Self.key(0x0605, 0)] = [0] + Array(label.utf8.prefix(64))
        for e in 1...n { params[Self.key(0x0901, UInt16(e))] = mgrBE16(UInt16(clamping: universes[e - 1])) }

        responders = (1...n).map { DeviceRDMResponder(uid: uid(for: $0), label: "\(modelName) \($0)", softwareLabel: firmwareLabel) }
        identifying = Array(repeating: false, count: n)
        live = Array(repeating: Live(), count: n)
        sources = Array(repeating: [:], count: n)
        merged = Array(repeating: [], count: n)
        epStatus = Array(repeating: 0, count: n)
        statusSent = Array(repeating: .distantPast, count: n)
        statusDirty = Array(repeating: false, count: n)

        let s = try UDPSocket(interface: settings.interface)
        socket = s // closed by stop() if a join throws
        groups = []
        try regroup()
        s.receive(on: .main) { [weak self] bytes, ip in self?.receive(bytes, from: ip) }
        bootedAt = Date()
        powerOn = freshPowerOn ? bootedAt : bootedAt.addingTimeInterval(-300) // app start is not a physical power-on (§7.7.1)
        lastPoll = bootedAt
    }

    private var stateKey: String { "device.\(Identity.hex(tuid))" }

    /// §8.3: load, +1, persist, and only then send. Open Mode is exempt.
    private func bumpSession() throws {
        let key = stateKey + ".session", d = UserDefaults.standard
        let stored = UInt32(clamping: d.integer(forKey: key))
        guard stored < 0xFFFF_FFFE else { throw SigNetError("Session ID exhausted: offboard and rekey") }
        session = stored + 1
        d.set(Int(session), forKey: key)
        guard d.synchronize() else { throw SigNetError("Could not persist Session ID") }
        seqs = [:]
    }

    private func persist() {
        let d = UserDefaults.standard
        d.set(Int(changeCount), forKey: stateKey + ".cc")
        d.set(Dictionary(uniqueKeysWithValues: params.map { (String($0.key), Data($0.value)) }), forKey: stateKey + ".params")
    }

    /// PF §6.7: an RDM responder's UID is its TUID. Endpoint 1 uses it as is;
    /// further endpoints count up the Device ID so each responder is distinct.
    private func uid(for endpoint: Int) -> [UInt8] {
        let id = mgrU32(tuid[2...]) &+ UInt32(endpoint - 1)
        return Array(tuid[..<2]) + mgrBE32(id)
    }

    /// Joins the admin groups (§9.2.2) and each consuming endpoint's level group (§9.2.3 folding or EP override).
    private func regroup() throws {
        var want: Set<String> = ["239.254.255.252", "239.254.255.251"]
        for e in 1...UInt16(n) where consumes(e) {
            let o = params[Self.key(0x0903, e)] ?? [0, 0, 0, 0], u = Int(mgrU16(params[Self.key(0x0901, e)] ?? [0, 0]))
            if o != [0, 0, 0, 0] { want.insert(o.map(String.init).joined(separator: ".")) }
            else if u > 0 { want.insert(SigNetKeys.levelGroup(UInt16(u))) }
        }
        for g in groups.subtracting(want) { try socket?.leave(g) }
        for g in want.subtracting(groups) { try socket?.join(g) }
        groups = want
    }

    private func consumes(_ e: UInt16) -> Bool { (params[Self.key(0x0905, e)]?.first ?? 0) & 3 == 1 }

    private func after(_ secs: Double, _ body: @escaping (DeviceEngine) -> Void) {
        DispatchQueue.main.asyncAfter(deadline: .now() + secs) { [weak self] in
            if let self, self.socket != nil { body(self) }
        }
    }

    // MARK: - Tick: levels, status, Lost Mode, beacons, IP rollback

    private func tick() {
        let now = Date()
        var view = live
        for i in 0..<n {
            let before = sources[i].count
            sources[i] = sources[i].filter { now.timeIntervalSince($0.value.seen) < 3 } // <universe_lost_timeout>
            if before > 0, sources[i].isEmpty { append("EP\(i + 1) stream lost: holding last state (no EP_FAILOVER)") }
            if !sources[i].isEmpty {
                let len = sources[i].values.map(\.levels.count).max()!
                merged[i] = (0..<len).map { s in sources[i].values.map { s < $0.levels.count ? $0.levels[s] : 0 }.max()! } // HTP, all at priority 100
            }
            view[i] = Live(levels: Array((merged[i] + [UInt8](repeating: 0, count: 32)).prefix(32)), slots: merged[i].count, sources: sources[i].count)
            let st: UInt32 = sources[i].isEmpty ? 0 : sources[i].count > 1 ? 0x19 : 0x09
            if st != epStatus[i] { epStatus[i] = st; statusDirty[i] = true }
            if statusDirty[i], now.timeIntervalSince(statusSent[i]) >= 1, !offboarded { // §10.4.4 defer and coalesce
                statusDirty[i] = false
                statusSent[i] = now
                notify(UInt16(i + 1), [ManagerTLV(tid: 0x0907, value: mgrBE32(epStatus[i]))])
            }
        }
        live = view
        if offboarded {
            if now.timeIntervalSince(lastBeacon) >= 5 { beacon() } // <beacon_min_interval>
            return
        }
        if !lost, now.timeIntervalSince(lastPoll) > 9 { // 3 × <poll_time> (§10.2.6)
            lost = true
            lastLost = .distantPast
            append("No Manager poll for 3 poll cycles: Lost Mode")
        }
        if lost, now.timeIntervalSince(lastLost) >= 3 {
            lastLost = now
            transmit("node_lost", lane: 0, presence(), to: "239.254.255.254")
        }
        if let net = network, now > net.deadline {
            network = nil
            for (k, v) in net.old { params[k] = v }
            changeCount &+= 1
            persist()
            append("network revert (rollback window expired): previous settings restored")
            notify(0, net.old.keys.sorted().map { ManagerTLV(tid: UInt16($0 >> 16), value: params[$0]!) })
        }
    }

    // MARK: - RX (§8.6)

    private func receive(_ bytes: [UInt8], from ip: String) {
        guard !offboarded else { return } // §10.2.1: an offboarded Device discards everything
        guard let p = try? ManagerPacket.decode(bytes), p.tuid != tuid else { return }
        switch p.mode { // step 1: no downgrade, no beacons
        case 0x00 where secure, 0x01 where !secure: break
        default: return
        }
        let s = p.segs
        guard s.count >= 4, s[0] == "sig-net", s[1] == "v1", s[2] == scope else { return } // steps 5, 6a
        if s[3] == "level" { return level(p, s, ip) }
        guard let uri = try? ManagerURI(s), uri.kind == "poll" || uri.kind == "manager" && uri.tuid == tuid else { return } // 6b
        guard authentic(p, uri.kind == "poll" ? keys?.kmGlobal : kmLocal, ip), let tlvs = ManagerTLV.decode(p.payload) else { return }
        if uri.kind == "poll" { poll(tlvs) } else { command(p, uri.ep, tlvs, ip) }
    }

    /// Steps 7-10: freshness, HMAC, commit. Open Mode skips all three (step 1d).
    private func authentic(_ p: ManagerPacket, _ key: SymmetricKey?, _ ip: String) -> Bool {
        guard secure else { return true }
        guard let key else { return false }
        if let code = fresh.problem(p) {
            event(0x0002, ip)
            event(code, ip)
            return false
        }
        guard p.verify(key) else { event(0x0001, ip); return false }
        guard fresh.commit(p) else { event(0x0005, ip); return false }
        return true
    }

    /// §10.9: count, remember the source, multicast at most once per second per code.
    private func event(_ code: UInt16, _ ip: String) {
        let now = Date()
        var e = events[code] ?? (0, [], .distantPast)
        e.count &+= 1
        let v4 = ip.split(separator: ".").compactMap { UInt8($0) }
        e.ip = v4.count == 4 ? v4 : []
        let send = now.timeIntervalSince(e.sent) >= 1
        if send { e.sent = now }
        events[code] = e
        append(String(format: "security event 0x%04X #%d from %@", code, e.count, ip))
        if send { transmit("node", lane: 0, [securityTLV(code)], to: "239.254.255.253") }
    }

    private func securityTLV(_ code: UInt16) -> ManagerTLV {
        let e = events[code] ?? (0, [], .distantPast)
        return ManagerTLV(tid: 0xFF01, value: mgrBE16(code) + mgrBE32(e.count) + (e.ip.isEmpty ? [0] : [1] + e.ip))
    }

    // MARK: - Discovery (§10.2)

    private func poll(_ tlvs: [ManagerTLV]) {
        guard let v = tlvs.first(where: { $0.tid == 0x0001 })?.value, v.count == 25 else { return }
        let lo = Array(v[10..<16]), hi = Array(v[16..<22]), ep = mgrU16(v[22...]), ql = v[24]
        guard !hi.lexicographicallyPrecedes(lo), ql <= 3 else { return } // §10.1.3: invalid → drop
        lastPoll = Date() // any valid poll proves the management network is up (§10.2.6)
        if lost { lost = false; append("Manager poll heard: leaving Lost Mode") }
        guard !tuid.lexicographicallyPrecedes(lo), !hi.lexicographicallyPrecedes(tuid) else { return }
        // ponytail: UDPSocket can't tell unicast from multicast, so any targeted poll verifies an IP change (§10.4.7).
        if lo == hi, network != nil { network = nil; append("network commit (rollback verified by targeted poll)") }
        let eps = endpoints(ep)
        guard !eps.isEmpty else { return }
        replyGen += 1
        let gen = replyGen, delay = lo == hi ? 0 : Double.random(in: 0...1) // <poll_backoff_max>
        for (i, e) in eps.enumerated() { // <endpoint_spacing_delay> between endpoints
            after(delay + Double(i) * 0.002) { me in
                guard gen == me.replyGen else { return }
                let tids = Self.supported.filter { Self.table[$0].map { $0.poll <= ql && (e == 0 ? $0.root : $0.data) } ?? false }
                me.send(e, tids.flatMap { me.values($0, e) }, lead: [me.pollReply()])
            }
        }
    }

    private func endpoints(_ ep: UInt16) -> [UInt16] { ep == 0xFFFF ? Array(0...UInt16(n)) : ep <= n ? [ep] : [] }

    private func pollReply(cc: UInt16? = nil) -> ManagerTLV {
        ManagerTLV(tid: 0x0002, value: tuid + mgrBE32(UInt32(Self.esta) << 16 | UInt32(DeviceRDMResponder.modelID)) + mgrBE16(cc ?? changeCount))
    }

    /// On-boot and Lost-Mode payload, in the §10.2.5 / §10.2.6 order (no OTW support).
    private func presence() -> [ManagerTLV] {
        [pollReply()] + [0x0603, 0x0609, 0x0602, 0x0606].flatMap { values($0, 0) }
    }

    private func beacon() { // §10.2.1
        lastBeacon = Date()
        transmit("node_beacon", lane: 0, [pollReply(cc: 0)] + [0x0605, 0x0609, 0x0602].flatMap { values($0, 0) }, to: "239.254.255.255")
    }

    // MARK: - Parameters (§11)

    private struct Param {
        let root: Bool, data: Bool
        let get: Bool, set: Bool, persistent: Bool
        let poll: UInt8 // QUERY_LEVEL category; 9 = never in poll replies
        var ok: ([UInt8]) -> Bool = { _ in false }
    }

    private static func label(_ v: [UInt8]) -> Bool { (1...65).contains(v.count) && v[0] == 0 } // encoding 0x00 ASCII
    private static func one(_ max: UInt8) -> ([UInt8]) -> Bool { { $0.count == 1 && $0[0] <= max } }
    private static func len(_ n: Int) -> ([UInt8]) -> Bool { { $0.count == n } }

    /// Every TID this Node answers on the Command URI, with §11.9 poll category and §11 limits.
    private static let table: [UInt16: Param] = {
        func r(_ poll: UInt8, set: Bool = false, nv: Bool = false, get: Bool = true, _ ok: @escaping ([UInt8]) -> Bool = { _ in false }) -> Param {
            Param(root: true, data: false, get: get, set: set, persistent: nv, poll: poll, ok: ok)
        }
        func d(_ poll: UInt8, set: Bool = false, nv: Bool = false, _ ok: @escaping ([UInt8]) -> Bool = { _ in false }) -> Param {
            Param(root: false, data: true, get: true, set: set, persistent: nv, poll: poll, ok: ok)
        }
        return [
            0x0601: r(2), 0x0602: r(0), 0x0603: r(2), 0x0604: r(2),
            0x0605: r(1, set: true, nv: true, label),
            0x0606: r(0, set: true, nv: true) { $0 == [0] }, // SET: only 0 = reset every EP override
            0x0607: r(1, set: true, one(4)),
            0x0608: r(1), 0x0609: r(2), 0x060B: r(2),
            0x0401: r(9, set: true, get: false) { $0 == Array("WIPE".utf8) },
            0x0502: r(2, set: true, nv: true, one(1)), 0x0503: r(2, set: true, nv: true, len(4)),
            0x0504: r(2, set: true, nv: true, len(4)), 0x0505: r(2, set: true, nv: true, len(4)),
            0x0581: r(2, set: true, nv: true, one(2)), 0x0582: r(2, set: true, nv: true, len(16)),
            0x0583: r(2, set: true, nv: true, one(128)), 0x0584: r(2, set: true, nv: true, len(16)),
            0xFF01: r(3),
            tidTestLevel: r(9, set: true, nv: true, len(1)),
            tidTestNote: r(9, set: true, nv: true) { (1...32).contains($0.count) },
            0x0305: d(1, set: true, nv: true, one(3)), 0x0306: d(1),
            0x0901: d(1, set: true, nv: true) { $0.count == 2 && mgrU16($0) <= 63999 }, // 0 = unpatched
            0x0902: d(1, set: true, nv: true, label),
            0x0903: d(1, set: true, nv: true) { v in // 0.0.0.0 clears; never one of the admin groups 239.254.255.x
                v.count == 4 && (v == [0, 0, 0, 0] || (224...239).contains(v[0]) && v[..<3] != [239, 254, 255])
            },
            0x0904: d(1),
            0x0905: d(1, set: true, nv: true) { $0.count == 1 && [0, 1, 4, 5].contains($0[0]) }, // consumer or off, RDM on/off
            0x0907: d(1), 0xFF03: d(9),
        ]
    }()

    /// RT_SUPPORTED_TIDS: the table plus discovery, level input and the RDM family.
    private static let supported: [UInt16] = ([0x0001, 0x0002, 0x0003, 0x0101, 0x0301, 0x0302, 0x0303, 0x0304] + table.keys).sorted()

    private static func key(_ tid: UInt16, _ ep: UInt16) -> UInt32 { UInt32(tid) << 16 | UInt32(ep) }

    /// Current value(s) of a TID on an endpoint: DG_SECURITY_EVENT gives one TLV per event code.
    private func values(_ tid: UInt16, _ ep: UInt16) -> [ManagerTLV] {
        let v: [UInt8]?
        switch tid {
        case 0x0601: v = Self.supported.flatMap(mgrBE16)
        case 0x0602: v = mgrBE16(UInt16(n))
        case 0x0603: v = [1]
        case 0x0604: v = mgrBE32(DeviceRDMResponder.softwareID) + Array(firmwareLabel.utf8.prefix(64))
        case 0x0606: v = [(1...UInt16(n)).contains { params[Self.key(0x0903, $0)] != [0, 0, 0, 0] } ? 1 : 0]
        case 0x0608: v = mgrBE32(secure ? 0 : 0x08)
        case 0x0609: v = mgrBE32(0x81) // Node, Open Mode supported
        case 0x060B: v = [0] + Array(modelName.utf8.prefix(64))
        case 0xFF01: return (1...UInt16(8)).map(securityTLV)
        case 0x0306: v = [8, 8] // virtual responder answers at once: the FIFO never fills
        case 0x0904: v = mgrBE32(0x15) // consume LEVEL, consume RDM, virtual
        case 0x0907: v = mgrBE32(epStatus[Int(ep) - 1])
        case 0xFF03: v = merged[Int(ep) - 1].isEmpty ? [0] : merged[Int(ep) - 1]
        default: v = params[Self.key(tid, ep)]
        }
        return v.map { [ManagerTLV(tid: tid, value: $0)] } ?? []
    }

    // MARK: - Commands (§10.4, §10.5)

    private func command(_ p: ManagerPacket, _ ep: UInt16, _ all: [ManagerTLV], _ ip: String) {
        let eps = endpoints(ep)
        func refuse(_ why: String) { append("command refused (silent, §10.4.2): \(why)") }
        guard !eps.isEmpty else { return refuse("no endpoint \(ep)") }
        // §10.1.2: proprietary TIDs only under our own Mfg-Code; §10.3.1: discovery/RDM-reply/data TIDs don't belong here.
        let tlvs = all.filter { (!(0x8000...0xFF00).contains($0.tid) || p.mfg == Self.esta) && ![0x0001, 0x0002, 0x0003, 0x0302, 0x0304].contains($0.tid) }
        let sets = tlvs.filter { !$0.value.isEmpty }
        if !sets.isEmpty, Date().timeIntervalSince(bootedAt) < 2 { return refuse("§8.6.4 bootstrap window (2 s after start)") }

        var writes: [(ep: UInt16, tlv: ManagerTLV)] = [], rdm: [(ep: UInt16, tlv: ManagerTLV)] = []
        let data = eps.filter { $0 > 0 }
        for t in sets {
            let v = t.value
            switch t.tid {
            case 0x0301: // root has no Root_Firmware_Support: RDM there is ignored (§6.8.1)
                guard (26...257).contains(v.count) else { return refuse("RDM frame length \(v.count)") }
                guard v[20] != 0x10, !(1...3).contains(mgrU16(v[21...])) else { return refuse("RDM discovery is never tunnelled (§10.5.5)") }
                rdm += data.map { ($0, t) }
            case 0x0303:
                guard v.count == 1, v[0] <= 1, !data.isEmpty else { return refuse("RDM_TOD_CONTROL \(mgrHex(v)) ep \(ep)") }
                rdm += data.map { ($0, t) }
            default:
                guard let d = Self.table[t.tid], d.set else {
                    if ManagerTID.byTID[t.tid] != nil { return refuse("\(ManagerTID.name(t.tid)) is not settable here") }
                    continue // unknown TID: skipped by length (§10.1)
                }
                let targets = eps.filter { $0 == 0 ? d.root : d.data }
                guard !targets.isEmpty else { return refuse("\(ManagerTID.name(t.tid)) on the wrong endpoint class") }
                guard d.ok(v) else { return refuse("\(ManagerTID.name(t.tid)) = \(mgrHex(v)) out of range") }
                writes += targets.map { ($0, t) }
            }
        }
        if writes.contains(where: { $0.tlv.tid == 0x0401 }), Date().timeIntervalSince(powerOn) > 300 {
            event(0x0008, ip)
            return refuse("RT_OFFBOARD after <offboard_lockout> (300 s from power-on)")
        }
        let nw = writes.map(\.tlv).filter { (0x0502...0x0505).contains($0.tid) || (0x0581...0x0584).contains($0.tid) }
        if !nw.isEmpty, let why = networkProblem(nw) { return refuse(why) }

        // Valid: apply atomically, then reply per endpoint (§10.4.2).
        replyGen += 1
        var nv = 0, extra: [UInt16: [UInt16]] = [:], regroupNeeded = false
        for (e, t) in writes where t.tid != 0x0401 {
            let k = Self.key(t.tid, e)
            if t.tid == 0x0606 { // §9.2.5: back to default folding everywhere
                for i in 1...UInt16(n) where params[Self.key(0x0903, i)] != [0, 0, 0, 0] {
                    params[Self.key(0x0903, i)] = [0, 0, 0, 0]
                    extra[i, default: []].append(0x0903)
                    nv += 1
                    regroupNeeded = true
                }
                continue
            }
            let changed = params[k] != t.value
            params[k] = t.value
            append("SET \(ManagerTID.name(t.tid)) ep\(e) = \(mgrHex(t.value))\(changed ? "" : " (unchanged)")")
            guard changed else { continue }
            if Self.table[t.tid]!.persistent { nv += 1 }
            if [0x0901, 0x0903, 0x0905].contains(t.tid) { regroupNeeded = true }
            // §9.2.4: a new universe drops the EP override unless the same packet sets one.
            if t.tid == 0x0901, !writes.contains(where: { $0.ep == e && $0.tlv.tid == 0x0903 }), params[Self.key(0x0903, e)] != [0, 0, 0, 0] {
                params[Self.key(0x0903, e)] = [0, 0, 0, 0]
                extra[e, default: []].append(0x0903)
            }
            if t.tid == 0x0607 { append("RT_IDENTIFY \(t.value[0])") }
        }
        if nv > 0 {
            changeCount &+= 1
            persist()
        }
        if regroupNeeded { do { try regroup() } catch { append("multicast regroup: \(error)") } }
        for (i, e) in eps.enumerated() {
            var out: [ManagerTLV] = []
            var confirms = false
            for t in tlvs {
                if t.value.isEmpty {
                    if let d = Self.table[t.tid], d.get, e == 0 ? d.root : d.data { out += values(t.tid, e) }
                } else if writes.contains(where: { $0.ep == e && $0.tlv == t }) {
                    out.append(t) // echo the request bytes
                    confirms = true
                }
            }
            out += (extra[e] ?? []).flatMap { values($0, e) }
            if confirms || extra[e] != nil { out.append(ManagerTLV(tid: 0x0003, value: [0] + mgrBE16(changeCount))) }
            if !out.isEmpty {
                if i == 0 { send(e, out) } else { after(Double(i) * 0.002) { $0.send(e, out) } } // <endpoint_spacing_delay>
            }
        }
        if nv > 0 { mirror() }
        if !nw.isEmpty { // the reply above went out on the old settings first (§10.4.7)
            network = (pendingOld, Date().addingTimeInterval(60))
            append("network apply \(nw.map { "\(ManagerTID.name($0.tid))=\(mgrHex($0.value))" }.joined(separator: " ")) (logged only, host untouched); 60 s rollback timer")
        }
        if writes.contains(where: { $0.tlv.tid == 0x0401 }) { return offboard() }
        for (e, t) in rdm { t.tid == 0x0301 ? rdmCommand(e, t.value) : tod(e, t.value[0]) }
    }

    /// §10.4.7 + §11.5: one family, mode always present, static needs address (+mask/prefix), DHCP/SLAAC none.
    private func networkProblem(_ nw: [ManagerTLV]) -> String? {
        guard network == nil else { return "an IP transaction is already in flight" }
        let v4 = nw.contains { $0.tid < 0x0580 }
        guard nw.allSatisfy({ ($0.tid < 0x0580) == v4 }) else { return "IPv4 and IPv6 settings in one packet" }
        let mode = nw.first { $0.tid == (v4 ? 0x0502 : 0x0581) }
        guard let mode else { return "network change without its MODE TID" }
        let tids = Set(nw.map(\.tid)), addresses: Set<UInt16> = v4 ? [0x0503, 0x0504, 0x0505] : [0x0582, 0x0583, 0x0584]
        if mode.value[0] == 0 {
            guard tids.isSuperset(of: v4 ? [0x0503, 0x0504] : [0x0582, 0x0583]) else { return "static IP without address and mask/prefix" }
        } else if !tids.isDisjoint(with: addresses) {
            return "address TIDs with a dynamic mode"
        }
        // The previous values are what a revert restores.
        let old = nw.reduce(into: [UInt32: [UInt8]]()) { $0[Self.key($1.tid, 0)] = params[Self.key($1.tid, 0)] }
        let text = nw.map { "\(ManagerTID.name($0.tid))=\(mgrHex($0.value))" }.joined(separator: " ")
        guard acceptNetwork else { return "network propose \(text) → refuse (Accept network changes is off)" }
        append("network propose \(text) → accept")
        pendingOld = old
        return nil
    }

    private var pendingOld: [UInt32: [UInt8]] = [:]

    /// Manager edits flow back into the panel so the UI (and the next start) follow them.
    private func mirror() {
        label = String(decoding: (params[Self.key(0x0605, 0)] ?? [0]).dropFirst(), as: UTF8.self)
        for e in 1...n { universes[e - 1] = Int(mgrU16(params[Self.key(0x0901, UInt16(e))] ?? [0, 0])) }
    }

    /// §7.7: reply first (done), then wipe keys, reset CHANGE_COUNT and beacon. Session ID persists unchanged.
    private func offboard() {
        offboarded = true
        keys = nil
        kmLocal = nil
        lost = false
        changeCount = 0
        persist()
        append("OFFBOARDED: keys wiped, now beaconing. Stop and start the device to onboard it again.")
        beacon()
    }

    /// Same path as a Manager SET (persists, bumps CHANGE_COUNT, publishes).
    @discardableResult public func applyLabel() -> Bool {
        let v = [0] + Array(label.utf8)
        guard running, !offboarded, v.count <= 65 else {
            append("set_label \"\(label)\": refused\(v.count > 65 ? " (over 64 bytes)" : "")")
            return false
        }
        let k = Self.key(0x0605, 0)
        if params[k] != v {
            params[k] = v
            changeCount &+= 1 // §10.4.4: local UI changes count too
            persist()
        }
        notify(0, [ManagerTLV(tid: 0x0605, value: v)])
        append("set_label \"\(label)\": OK")
        return true
    }

    public func clearLog() { log.removeAll() }

    /// Proactive notification of the current label, CHANGE_COUNT unchanged.
    public func notifyLabelChange() {
        guard running, !offboarded else { return }
        notify(0, values(0x0605, 0))
        append("notify_change TID_RT_DEVICE_LABEL: OK")
    }

    /// §10.4.4: changed TLVs + trailing SET_REPLY to /node/{tuid}/{ep}.
    private func notify(_ ep: UInt16, _ tlvs: [ManagerTLV]) {
        send(ep, tlvs + [ManagerTLV(tid: 0x0003, value: [0] + mgrBE16(changeCount))])
    }

    // MARK: - RDM (§10.5)

    private func rdmCommand(_ ep: UInt16, _ frame: [UInt8]) {
        let i = Int(ep) - 1
        append("RDM ep\(ep) ← \(DeviceRDMResponder.describe(frame))")
        guard (params[Self.key(0x0905, ep)]?.first ?? 0) & 4 != 0 else { return append("RDM ep\(ep): RDM disabled by EP_DIRECTION") }
        let pid = mgrU16(frame[21...])
        // §10.5.3: SETs of E1.37-2 / E1.33 network PIDs at a virtual endpoint get NR_WRITE_PROTECT.
        if DeviceRDMResponder.valid(frame), frame[20] == 0x30, Array(frame[3..<9]) == responders[i].uid,
           (0x0700...0x070D).contains(pid) || (0x0800...0x0803).contains(pid) {
            append(String(format: "RDM ep%d blocked network SET PID 0x%04X", ep, pid))
            return rdmReply(ep, DeviceRDMResponder.nack(frame, from: responders[i].uid, reason: 0x0004))
        }
        guard let reply = responders[i].handle(frame) else { return append("RDM ep\(ep) no response (not ours)") }
        rdmReply(ep, reply)
        if let note = responders[i].notification(after: reply) { // §10.5.2: proactive, after 0..<rdm_backoff_max>
            after(Double.random(in: 0...0.25)) { $0.rdmReply(ep, note) }
        }
        identifying = responders.map(\.identify)
    }

    private func rdmReply(_ ep: UInt16, _ frame: [UInt8]) {
        append("RDM ep\(ep) → \(DeviceRDMResponder.describe(frame))")
        send(ep, [ManagerTLV(tid: 0x0302, value: frame)] + values(0x0306, ep)) // FLOW_CONTROL rides along (§11.3.6)
    }

    /// Virtual endpoint: discovery always finds just our responder, so both commands report it.
    private func tod(_ ep: UInt16, _ command: UInt8) {
        guard (params[Self.key(0x0905, ep)]?.first ?? 0) & 4 != 0 else { return append("RDM ep\(ep) ToD: RDM disabled") }
        let uid = responders[Int(ep) - 1].uid
        append("RDM ep\(ep) ToD \(command == 0 ? "send" : "flush") → \(Identity.hex(uid))")
        send(ep, [ManagerTLV(tid: 0x0304, value: [1, 1] + uid)])
    }

    // MARK: - Level input (§10.6)

    private func level(_ p: ManagerPacket, _ s: [String], _ ip: String) {
        guard s.count == 5, let u = UInt16(s[4]), s[4] == String(u), (1...63999).contains(u) else { return }
        let eps = (1...UInt16(n)).filter { consumes($0) && mgrU16(params[Self.key(0x0901, $0)] ?? [0, 0]) == u }
        guard !eps.isEmpty, authentic(p, ks, ip), let tlvs = ManagerTLV.decode(p.payload),
              let levels = tlvs.first(where: { $0.tid == 0x0101 })?.value, (1...512).contains(levels.count) else { return }
        for e in eps { sources[Int(e) - 1][p.senderID] = (levels, Date()) }
    }

    // MARK: - TX

    /// Splits at TLV boundaries so no payload passes 1200 B (§10.2.4); `lead` starts every fragment.
    private func send(_ ep: UInt16, _ tlvs: [ManagerTLV], lead: [ManagerTLV] = []) {
        var chunk = lead
        for t in tlvs {
            if ManagerTLV.encode(chunk + [t]).count > 1200, chunk.count > lead.count {
                transmit("node", lane: ep, chunk, to: "239.254.255.253")
                chunk = lead
            }
            chunk.append(t)
        }
        if !chunk.isEmpty { transmit("node", lane: ep, chunk, to: "239.254.255.253") }
    }

    /// Replies are multicast always (§10.4.1), signed with Kc; the Sender-ID endpoint is the reply's endpoint (§8.6.2 lanes).
    private func transmit(_ kind: String, lane: UInt16, _ tlvs: [ManagerTLV], to group: String) {
        guard let socket else { return }
        var p = ManagerPacket()
        p.mid = mid
        mid = mid == 0xFFFF ? 1 : mid + 1
        p.segs = ["sig-net", "v1", kind == "node_beacon" ? "local" : scope, kind, Identity.hex(tuid), String(lane)]
        p.mode = offboarded ? 0xFF : secure ? 0x00 : 0x01
        p.tuid = tuid
        p.ep = lane
        p.payload = ManagerTLV.encode(tlvs)
        if !offboarded, tlvs.contains(where: { (0x8000...0xFF00).contains($0.tid) }) { p.mfg = Self.esta }
        if secure, !offboarded {
            guard let kc = keys?.kc else { return }
            if seqs[lane, default: 0] >= 0xFFFF_FFFE { // §8.3 wrap: new session, every lane back to 1
                do { try bumpSession() } catch { status = "\(error)"; return }
            }
            seqs[lane, default: 0] += 1
            (p.session, p.seq) = (session, seqs[lane]!)
            p.sign(kc)
        }
        do { try socket.send(p.encode(), to: group) } catch { append("send \(p.uri): \(error)") }
    }

    // MARK: - Log

    private func append(_ line: String) {
        log.append(String(format: "%8.2f  ", Date().timeIntervalSince(launched)) + line)
        if log.count > 500 { log.removeFirst(log.count - 500) }
    }
}

/// Node-side freshness (§8.6 steps 7-10): session per TUID, seq per 8-byte Sender-ID, RAM only,
/// ≥32 lanes with LRU eviction only after 3600 s idle.
private struct Freshness {
    private var sessions: [String: UInt32] = [:]
    private var lanes: [String: (session: UInt32, seq: UInt32, seen: Date)] = [:]

    /// nil = fresh; else the security event code (0x0006 epoch regression, 0x0007 contiguity).
    func problem(_ p: ManagerPacket) -> UInt16? {
        if let s = sessions[Identity.hex(p.tuid)], p.session < s { return 0x0006 }
        if let l = lanes[p.senderID], p.session == l.session, p.seq <= l.seq { return 0x0007 }
        return nil // unknown TUID: first-packet bootstrapping (§8.6.3)
    }

    /// false = table saturated (event 0x0005).
    mutating func commit(_ p: ManagerPacket) -> Bool {
        let now = Date()
        if lanes[p.senderID] == nil, lanes.count >= 32 {
            guard let lru = lanes.min(by: { $0.value.seen < $1.value.seen }), now.timeIntervalSince(lru.value.seen) > 3600 else { return false }
            lanes[lru.key] = nil
        }
        let t = Identity.hex(p.tuid)
        sessions[t] = max(sessions[t] ?? 0, p.session)
        lanes[p.senderID] = (p.session, p.seq, now)
        return true
    }
}

// MARK: - Self-test

extension DeviceEngine {
    /// Hand-built RDM frames, then two boots (the second must load and bump the persisted Session ID). nil = pass.
    public static func selfTest(settings: SecurityConfig) -> String? {
        if let problem = rdmSelfTest() { return "rdm: \(problem)" }
        let d = DeviceEngine(settings: settings, tuid: Identity.tuid("selftest-device"))
        var last: UInt32 = 0
        for run in 1...2 {
            d.start()
            ManagerEngine.spin(1) { false }
            defer { d.stop() }
            guard d.running else { return "boot #\(run): \(d.status)" }
            if d.secure, run == 2, d.session != last &+ 1 { return "boot #2: session \(d.session), expected \(last &+ 1)" }
            last = d.session
        }
        return nil
    }

    /// GET DEVICE_INFO → ACK, unknown PID → NACK, bad checksum → silence.
    static func rdmSelfTest() -> String? {
        let me: [UInt8] = [0x7F, 0xF0, 0x80, 0x00, 0x00, 0x01], controller: [UInt8] = [0x7F, 0xF0, 0x12, 0x34, 0x56, 0x78]
        var r = DeviceRDMResponder(uid: me, label: "x", softwareLabel: "v1")
        func request(pid: (UInt8, UInt8)) -> [UInt8] {
            let body: [UInt8] = [0xCC, 0x01, 24] + me + controller + [0x07, 0x01, 0x00, 0x00, 0x00, 0x20, pid.0, pid.1, 0x00]
            let sum = body.reduce(0) { $0 + Int($1) }
            return body + [UInt8(sum >> 8 & 0xFF), UInt8(sum & 0xFF)]
        }
        guard let info = r.handle(request(pid: (0x00, 0x60))) else { return "no reply to GET DEVICE_INFO" }
        let sum = info.prefix(43).reduce(0) { $0 + Int($1) }
        guard info.count == 45, info[2] == 43, info[23] == 19 else { return "DEVICE_INFO length \(info.count)" }
        guard info[20] == 0x21, info[16] == 0x00, info[15] == 0x07 else { return "DEVICE_INFO CC/type/TN wrong" }
        guard Array(info[3..<9]) == controller, Array(info[9..<15]) == me else { return "DEVICE_INFO UIDs not swapped" }
        guard Int(info[43]) << 8 | Int(info[44]) == sum & 0xFFFF else { return "DEVICE_INFO checksum wrong" }
        guard let nack = r.handle(request(pid: (0x12, 0x34))), nack[16] == 0x02, nack.suffix(4).prefix(2) == [0, 0]
        else { return "unknown PID not NACKed UNKNOWN_PID" }
        var bad = request(pid: (0x00, 0x60))
        bad[bad.count - 1] &+= 1
        return r.handle(bad) == nil ? nil : "answered a frame with a bad checksum"
    }
}
