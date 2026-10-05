import CryptoKit
import Darwin
import Foundation

struct ManagerDevice: Identifiable {
    let tuid: [UInt8]
    var id: String { Identity.hex(tuid) }
    var ip = ""
    var soem: UInt32 = 0
    var changeCount: UInt16?
    var lastSeen = Date()
    var state = "Online"
    var auth = ""
    var anomaly = ""
    var params: [UInt16: [UInt16: [UInt8]]] = [:] // ep → tid → last value seen
    var tod: [UInt16: [[UInt8]]] = [:]           // ep → UIDs
    var rdm: [String] = []                       // RDM responses seen (newest last)

    func root(_ tid: UInt16) -> [UInt8]? { params[0]?[tid] }
    func text(_ tid: UInt16) -> String { root(tid).map { ManagerTID.describe(tid, $0) } ?? "–" }
    var label: String { root(0x0605).map { String(decoding: $0.dropFirst(), as: UTF8.self) } ?? "" }
    var model: String { root(0x060B).map { String(decoding: $0.dropFirst(), as: UTF8.self) } ?? "" }
    var roles: String {
        guard let v = root(0x0609), v.count == 4 else { return "–" }
        let r = mgrU32(v)
        let names = [(0, "Node"), (1, "Sender"), (2, "Manager"), (3, "Visualiser"), (6, "RootFW"), (7, "Open")]
        return names.filter { r >> $0.0 & 1 == 1 }.map(\.1).joined(separator: ", ")
    }
}

struct ManagerLogEntry: Identifiable {
    let id = UUID()
    let time = Date()
    let tx: Bool
    let peer: String
    let uri: String
    let sender: String
    let mode: String
    let lane: String
    let auth: String
    let tlvs: String
    let hex: String
}

struct ManagerResult {
    var ok = false
    var text = ""
    var tlvs: [ManagerTLV] = []
    var frame: [UInt8] = []
}

/// Manager-side freshness (§8.6.1): session per TUID, seq per 8-byte Sender-ID.
/// Checked before and committed only after the HMAC verifies.
private struct ManagerFreshness {
    private var sessions: [String: UInt32] = [:]
    private var lanes: [String: (session: UInt32, seq: UInt32)] = [:]

    func problem(_ p: ManagerPacket) -> String? {
        if let s = sessions[Identity.hex(p.tuid)], p.session < s { return "REPLAY (session \(p.session) < \(s))" }
        if let l = lanes[p.senderID], p.session == l.session, p.seq <= l.seq { return "REPLAY (seq \(p.seq) ≤ \(l.seq))" }
        return nil
    }

    mutating func commit(_ p: ManagerPacket) {
        let t = Identity.hex(p.tuid)
        sessions[t] = max(sessions[t] ?? 0, p.session)
        lanes[p.senderID] = (p.session, p.seq)
    }

    mutating func forget(_ tuidHex: String) {
        sessions[tuidHex] = nil
        lanes = lanes.filter { !$0.key.hasPrefix(tuidHex) }
    }
}

/// Hand-built Sig-Net Manager: discovery, GET/SET, RDM tunnelling and a packet log.
/// ponytail: everything runs on the main queue (socket reads via a main-queue
/// DispatchSource), so there is no locking; move decode/HMAC off main if a
/// network ever floods 239.254.255.252-255.
final class Manager: ObservableObject {
    static let soem: UInt32 = 0x7FF0_0003 // ESTA prototyping ID + variant
    static let groups = ["239.254.255.252", "239.254.255.253", "239.254.255.254", "239.254.255.255"]
    static let pollGroup = "239.254.255.252", sendGroup = "239.254.255.251", nodeGroup = "239.254.255.253"

    let settings: SecuritySettings
    let tuid: [UInt8]
    @Published private(set) var running = false
    @Published private(set) var status = "Stopped"
    @Published private(set) var devices: [String: ManagerDevice] = [:]
    @Published private(set) var log: [ManagerLogEntry] = []
    @Published private(set) var result = ""
    @Published private(set) var busy = false
    @Published var heartbeat = true
    @Published var unicast = true

    private var fd: Int32 = -1
    private var source: DispatchSourceRead?
    private var timer: Timer?
    private var keys: ManagerKeys?
    private var secure = false
    private var scope = "local"
    private var session: UInt32 = 0
    private var seq: UInt32 = 0
    private var mid = UInt16.random(in: 1...0xFFFF)
    private var tn: UInt8 = 0
    private var nextPoll = Date()
    private var fresh = ManagerFreshness()
    private var repolled: [String: Date] = [:]
    private var pending: Pending?

    private struct Pending {
        enum Kind { case get, set, probe, rdm(tn: UInt8), tod }
        var id = UUID()
        let target: [UInt8]
        let ep: UInt16
        let tlvs: [ManagerTLV]
        let kind: Kind
        let timeout: TimeInterval
        var attempt = 0
        var collected: [ManagerTLV] = []
        let done: (ManagerResult) -> Void
    }

    init(settings: SecuritySettings, tuid: [UInt8] = Identity.tuid("manager")) {
        self.settings = settings
        self.tuid = tuid
    }

    // MARK: - Lifecycle

    func start() {
        guard !running, settings.ready else { return }
        secure = settings.mode == .secure
        scope = settings.scopeOrDefault
        do {
            if secure {
                var k0 = try settings.rootKey()
                keys = ManagerKeys(k0: &k0) // wipes k0
                try bumpSession()
            }
            try openSocket()
        } catch {
            stop()
            status = "\(error)"
            return
        }
        running = true
        settings.deviceStarted()
        status = "Running · \(settings.mode.rawValue) Mode · scope \(scope) · TUID \(Identity.hex(tuid))"
            + (secure ? " · session \(session)" : "")
        announce()
        poll(level: 2, ep: 0xFFFF) // initial population (§10.2.2)
        nextPoll = Date().addingTimeInterval(3)
        timer = Timer.scheduledTimer(withTimeInterval: 0.25, repeats: true) { [weak self] _ in self?.tick() }
    }

    func stop() {
        timer?.invalidate()
        timer = nil
        if let s = source { s.cancel() } else if fd >= 0 { close(fd) } // cancel handler closes fd
        source = nil
        fd = -1
        keys = nil
        if let p = pending { pending = nil; p.done(ManagerResult(text: "stopped")) }
        busy = false
        if running { settings.deviceStopped() }
        running = false
        status = "Stopped"
    }

    /// §5: load, +1, persist, and only then send. Never random, never reused.
    private func bumpSession() throws {
        let key = "manager.session.\(Identity.hex(tuid))"
        let stored = UInt32(clamping: UserDefaults.standard.integer(forKey: key))
        guard stored < 0xFFFF_FFFE else { throw ManagerError("Session ID exhausted: rekey or use a new TUID") }
        session = stored + 1
        UserDefaults.standard.set(Int(session), forKey: key)
        guard UserDefaults.standard.synchronize() else { throw ManagerError("Could not persist Session ID") }
        seq = 0
    }

    private func openSocket() throws {
        fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { throw ManagerError("socket: \(String(cString: strerror(errno)))") }
        var on: Int32 = 1, ttl: UInt8 = 32, loop: UInt8 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, 1)
        setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, 1)
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
        var nic = in_addr(s_addr: INADDR_ANY)
        let interface = settings.interface
        if !interface.isEmpty {
            guard inet_pton(AF_INET, interface, &nic) == 1 else { throw ManagerError("Interface must be an IPv4 address") }
            setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &nic, socklen_t(MemoryLayout<in_addr>.size))
        }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(5683).bigEndian
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard bound == 0 else { throw ManagerError("bind 5683: \(String(cString: strerror(errno)))") }
        for g in Self.groups {
            var mreq = ip_mreq(imr_multiaddr: in_addr(s_addr: inet_addr(g)), imr_interface: nic)
            guard setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, socklen_t(MemoryLayout<ip_mreq>.size)) == 0 else {
                throw ManagerError("join \(g): \(String(cString: strerror(errno)))")
            }
        }
        let src = DispatchSource.makeReadSource(fileDescriptor: fd, queue: .main)
        let sock = fd
        src.setEventHandler { [weak self] in self?.readable() }
        src.setCancelHandler { close(sock) }
        src.resume()
        source = src
    }

    private func tick() {
        let now = Date()
        if heartbeat, now >= nextPoll {
            poll(level: 0, ep: 0) // routine heartbeat: global, QL 0 only (§10.2.2)
            nextPoll = now.addingTimeInterval(3 + Double.random(in: 0...0.5))
        }
        for (k, d) in devices {
            let age = now.timeIntervalSince(d.lastSeen)
            if d.state == "Beacon", age > 30 { devices[k] = nil } // <beacon_timeout>
            else if heartbeat, d.state.hasPrefix("Online"), age > 3 * 3.5 { devices[k]?.state = "Lost" }
        }
    }

    func forget(_ id: String) {
        devices[id] = nil
        fresh.forget(id)
    }

    func clearLog() { log.removeAll() }

    // MARK: - TX

    /// One lane (ep 0) shared by polls and commands; seq restarts at 1 per session.
    private func nextLane() -> (UInt32, UInt32)? {
        guard secure else { return (0, 0) }
        if seq >= 0xFFFF_FFFE {
            do { try bumpSession() } catch { status = "\(error)"; return nil }
        }
        seq += 1
        return (session, seq)
    }

    @discardableResult
    private func send(_ path: [String], _ tlvs: [ManagerTLV], key: SymmetricKey?, to host: String) -> Bool {
        guard fd >= 0, let lane = nextLane() else { return false }
        var p = ManagerPacket()
        p.mid = mid
        mid = mid == 0xFFFF ? 1 : mid + 1 // never 0: MsgID 0 bypasses the Open-Mode duplicate filter
        p.segs = ["sig-net", "v1", scope] + path
        p.mode = secure ? 0x00 : 0x01
        p.tuid = tuid
        // §10.1.2: proprietary TIDs (0x8000-0xFF00) are only interpreted under the sender's ESTA ID.
        if tlvs.contains(where: { (0x8000...0xFF00).contains($0.tid) }) { p.mfg = mgrU16(tuid) }
        (p.session, p.seq) = lane
        p.payload = ManagerTLV.encode(tlvs)
        if secure, let key { p.sign(key) }
        let bytes = p.encode()
        guard p.payload.count <= 1200, bytes.count <= 1400 else {
            result = "Not sent: \(bytes.count) B packet / \(p.payload.count) B payload over the 1400/1200 B limit"
            return false
        }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(5683).bigEndian
        addr.sin_addr.s_addr = inet_addr(host)
        let n = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                sendto(fd, bytes, bytes.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        record(tx: true, peer: host, p, bytes, auth: secure ? "signed" : "none (Open)", tlvs: tlvs)
        if n < 0 { status = "sendto \(host): \(String(cString: strerror(errno)))" }
        return n >= 0
    }

    private func announce() { // §10.2.5: every Device, Managers included
        let tlvs = [
            ManagerTLV(tid: 0x0002, value: tuid + mgrBE32(Self.soem) + [0, 0]),
            ManagerTLV(tid: 0x0603, value: [1]),
            ManagerTLV(tid: 0x0609, value: mgrBE32(0x84)), // Manager + Open Mode supported
            ManagerTLV(tid: 0x0602, value: [0, 0]),
            ManagerTLV(tid: 0x0606, value: [0]),
        ]
        send(["node", Identity.hex(tuid), "0"], tlvs, key: keys?.kc, to: Self.nodeGroup)
    }

    /// TID_POLL. `to` = unicast IP for targeted polls, else multicast.
    func poll(lo: [UInt8] = [0, 0, 0, 0, 0, 0], hi: [UInt8] = [UInt8](repeating: 0xFF, count: 6),
              level: UInt8, ep: UInt16, to host: String? = nil) {
        guard running else { return }
        let v = tuid + mgrBE32(Self.soem) + lo + hi + mgrBE16(ep) + [level]
        send(["poll"], [ManagerTLV(tid: 0x0001, value: v)], key: keys?.kmGlobal, to: host ?? Self.pollGroup)
    }

    private func command(_ target: [UInt8], _ ep: UInt16, _ tlvs: [ManagerTLV], attempt: Int) {
        let host = unicast && attempt == 0 ? devices[Identity.hex(target)]?.ip ?? "" : ""
        let key = keys == nil ? nil : keys!.kmLocal(target)
        send(["manager", Identity.hex(target), String(ep)], tlvs, key: key, to: host.isEmpty ? Self.sendGroup : host)
    }

    private func begin(_ p: Pending) {
        guard running else { return p.done(ManagerResult(text: "Manager not running")) }
        guard pending == nil else { return p.done(ManagerResult(text: "Busy: one transaction at a time (reply supersession, §10.2.3)")) }
        pending = p
        busy = true
        result = "Waiting…"
        transmit()
    }

    private func transmit() {
        guard let p = pending else { return }
        command(p.target, p.ep, p.tlvs, attempt: p.attempt)
        let id = p.id
        DispatchQueue.main.asyncAfter(deadline: .now() + p.timeout) { [weak self] in self?.timedOut(id) }
    }

    /// 500 ms, one retry (new seq, multicast), then for a SET a GET probe to tell refusal from loss (semantics §2.7).
    private func timedOut(_ id: UUID) {
        guard var p = pending, p.id == id else { return }
        if p.attempt == 0 {
            p.attempt = 1
            pending = p
            return transmit()
        }
        if case .set = p.kind {
            let probe = Pending(target: p.target, ep: p.ep, tlvs: p.tlvs.map { ManagerTLV(tid: $0.tid) }, kind: .probe,
                                timeout: 0.5, attempt: 1, done: p.done)
            pending = probe
            return transmit()
        }
        let text: String
        switch p.kind {
        case .probe: text = "No confirmation, and the GET probe got no reply either: device unreachable or Km_local wrong"
        case .tod, .rdm: text = "No RDM reply after retry"
        default: text = "No reply after 500 ms + retry (unsupported TID, wrong endpoint, or unreachable)"
        }
        finish(ManagerResult(text: text))
    }

    private func finish(_ r: ManagerResult) {
        guard let p = pending else { return }
        pending = nil
        busy = false
        result = r.text
        p.done(r)
    }

    func get(_ target: [UInt8], ep: UInt16, tids: [UInt16], done: @escaping (ManagerResult) -> Void = { _ in }) {
        begin(Pending(target: target, ep: ep, tlvs: tids.map { ManagerTLV(tid: $0) }, kind: .get, timeout: 0.5, done: done))
    }

    func set(_ target: [UInt8], ep: UInt16, tlvs: [ManagerTLV], done: @escaping (ManagerResult) -> Void = { _ in }) {
        begin(Pending(target: target, ep: ep, tlvs: tlvs, kind: .set, timeout: 0.5, done: done))
    }

    /// TOD_CONTROL 0x01: flush the ToD and run full discovery. RDM TLVs are never
    /// echoed or SET_REPLY'd (§10.5), so there is nothing to wait for; request the ToD afterwards.
    func flushToD(_ target: [UInt8], ep: UInt16) {
        guard running, pending == nil else { return }
        devices[Identity.hex(target)]?.tod[ep] = []
        command(target, ep, [ManagerTLV(tid: 0x0303, value: [0x01])], attempt: 0)
    }

    func requestToD(_ target: [UInt8], ep: UInt16, done: @escaping (ManagerResult) -> Void = { _ in }) {
        devices[Identity.hex(target)]?.tod[ep] = []
        begin(Pending(target: target, ep: ep, tlvs: [ManagerTLV(tid: 0x0303, value: [0x00])], kind: .tod, timeout: 1.5, done: done))
    }

    /// GET/SET only: discovery (CC 0x10, PIDs 1-3) is never tunnelled (§10.5.5).
    func rdm(_ target: [UInt8], ep: UInt16, dest: [UInt8], set: Bool, pid: UInt16, pd: [UInt8] = [],
             upload: Bool = false, done: @escaping (ManagerResult) -> Void = { _ in }) {
        guard !(1...3).contains(pid), dest.count == 6, pd.count <= 231 else {
            return done(ManagerResult(text: "Refused locally: discovery PIDs / bad UID / PD > 231 B"))
        }
        // While a firmware upload runs, only its own requests go out: anything else could land between packets.
        guard upload || !FirmwareUpdate.active else {
            return done(ManagerResult(text: "Busy: a firmware upload is running"))
        }
        tn &+= 1
        let f = ManagerRDM.frame(dest: dest, src: tuid, tn: tn, cc: set ? 0x30 : 0x20, pid: pid, pd: pd)
        begin(Pending(target: target, ep: ep, tlvs: [ManagerTLV(tid: 0x0301, value: f)], kind: .rdm(tn: tn), timeout: 1.5, done: done))
    }

    // MARK: - RX

    private func readable() {
        var buf = [UInt8](repeating: 0, count: 2048)
        while true {
            var from = sockaddr_in()
            var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            let n = withUnsafeMutablePointer(to: &from) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(fd, &buf, buf.count, 0, $0, &len) }
            }
            guard n > 0 else { return }
            handle(Array(buf[0..<n]), from: String(cString: inet_ntoa(from.sin_addr)))
        }
    }

    private func handle(_ bytes: [UInt8], from ip: String) {
        let p: ManagerPacket
        do { p = try ManagerPacket.decode(bytes) } catch {
            return record(peer: ip, uri: "?", note: "MALFORMED: \(error)", bytes)
        }
        if p.tuid == tuid { return } // our own multicast, looped back
        let uri: ManagerURI
        do { uri = try ManagerURI(p.segs) } catch { return record(peer: ip, uri: p.uri, note: "BAD URI: \(error)", bytes) }
        guard uri.kind == "node_beacon" || uri.scope == scope else { return } // other scope: not ours
        guard let tlvs = ManagerTLV.decode(p.payload) else { return record(peer: ip, uri: p.uri, note: "BAD TLV", bytes) }

        let auth: String
        var trusted = true
        switch p.mode {
        case 0xFF:
            guard uri.kind == "node_beacon" else { return record(peer: ip, uri: p.uri, note: "mode 0xFF off a beacon URI", bytes) }
            auth = "none (beacon)"
        case 0x01:
            auth = "Open (unauthenticated)"
        default:
            guard var k = keys else {
                record(tx: false, peer: ip, p, bytes, auth: "secure, no key (Open Manager)", tlvs: tlvs)
                return
            }
            let key: SymmetricKey?
            switch uri.kind {
            case "poll": key = k.kmGlobal
            case "node", "node_lost": key = k.kc
            case "manager": key = k.kmLocal(uri.tuid!)
            default: key = nil // aux (Ks) is not ours to check
            }
            keys = k
            if let key {
                if let why = fresh.problem(p) {
                    auth = why; trusted = false
                } else if p.verify(key) {
                    fresh.commit(p); auth = "OK"
                } else {
                    auth = "FAIL"; trusted = false
                }
            } else {
                auth = "not checked"
            }
        }
        record(tx: false, peer: ip, p, bytes, auth: auth, tlvs: tlvs)
        guard let t = uri.tuid, ["node", "node_lost", "node_beacon"].contains(uri.kind) else { return }
        let id = Identity.hex(t)
        guard trusted else { // §8.6.1: alert the operator naming the TUID
            devices[id, default: ManagerDevice(tuid: t, ip: ip, state: "Unverified")].anomaly =
                "\(auth) on \(uri.kind) from \(ip) at \(Date().formatted(date: .omitted, time: .standard))"
            return
        }
        ingest(t, uri: uri, ip: ip, auth: auth, open: p.mode == 0x01, tlvs: tlvs)
    }

    private func ingest(_ t: [UInt8], uri: ManagerURI, ip: String, auth: String, open: Bool, tlvs: [ManagerTLV]) {
        let id = Identity.hex(t)
        var d = devices[id] ?? ManagerDevice(tuid: t)
        if uri.kind == "node_beacon", d.state == "Beacon", d.ip != ip, !d.ip.isEmpty, Date().timeIntervalSince(d.lastSeen) < 30 {
            d.anomaly = "Beacon spoofing? Same TUID from \(d.ip) and \(ip) within 30 s"
        }
        d.ip = ip
        d.auth = auth
        let presence = tlvs.contains { $0.tid == 0x0002 }
        if presence || uri.kind != "node" { d.lastSeen = Date() }
        switch uri.kind {
        case "node_lost": d.state = heartbeat && d.state.hasPrefix("Online") ? "node_lost while Online: polls not reaching it" : "node_lost"
        case "node_beacon": d.state = "Beacon"
        default: if presence || d.state == "Lost" { d.state = open ? "Online (Open, unauthenticated)" : "Online" }
        }
        var repoll = false
        for tlv in tlvs {
            let v = tlv.value
            switch tlv.tid {
            case 0x0002 where v.count == 12:
                d.soem = mgrU32(v[6...])
                let cc = mgrU16(v[10...])
                if uri.kind == "node", let old = d.changeCount, old != cc { repoll = true }
                if uri.kind != "node_beacon" { d.changeCount = cc }
            case 0x0003 where v.count == 3: // SET_REPLY: same or +1 is expected, anything else → refresh
                let cc = mgrU16(v[1...])
                if let old = d.changeCount, cc != old, cc != old &+ 1 { repoll = true }
                d.changeCount = cc
            case 0x0302:
                d.rdm.append("EP\(uri.ep) " + ManagerRDM.describe(v))
                if d.rdm.count > 50 { d.rdm.removeFirst() }
            case 0x0304 where v.count >= 2:
                if v[0] == 1 { d.tod[uri.ep] = [] }
                d.tod[uri.ep, default: []] += stride(from: 2, to: v.count - 5, by: 6).map { Array(v[$0..<$0 + 6]) }
            default:
                d.params[uri.ep, default: [:]][tlv.tid] = v
            }
        }
        devices[id] = d
        if repoll, Date().timeIntervalSince(repolled[id] ?? .distantPast) > 1 { // CHANGE_COUNT moved under us (§10.4.4)
            repolled[id] = Date()
            poll(lo: t, hi: t, level: 2, ep: 0xFFFF, to: unicast ? ip : nil)
        }
        if uri.kind == "node" { match(t, uri.ep, tlvs) }
    }

    private func match(_ t: [UInt8], _ ep: UInt16, _ tlvs: [ManagerTLV]) {
        guard var p = pending, p.target == t, p.ep == 0xFFFF || p.ep == ep else { return }
        let asked = Set(p.tlvs.map(\.tid))
        switch p.kind {
        case .get, .probe:
            let got = tlvs.filter { asked.contains($0.tid) }
            guard !got.isEmpty else { return }
            let values = got.map { "\(ManagerTID.name($0.tid)) = \(ManagerTID.describe($0.tid, $0.value))" }.joined(separator: "; ")
            if case .probe = p.kind {
                finish(ManagerResult(text: "No confirmation after retry; GET probe answered → SET refused by the Node (\(values))", tlvs: got))
            } else {
                finish(ManagerResult(ok: true, text: "EP\(ep): " + values, tlvs: got))
            }
        case .set:
            let mine = tlvs.filter { asked.contains($0.tid) }
            // A proactive notification (e.g. EP_STATUS after a re-patch) also ends in
            // SET_REPLY; without any echoed TLV it is not our confirmation.
            guard !mine.isEmpty || !p.collected.isEmpty else { return }
            p.collected += mine
            pending = p
            guard let reply = tlvs.last(where: { $0.tid == 0x0003 }), reply.value.count == 3 else { return }
            let echoed = p.tlvs.allSatisfy { p.collected.contains($0) }
            let names = p.collected.map { ManagerTID.name($0.tid) }.joined(separator: ", ")
            finish(ManagerResult(ok: echoed, text: "EP\(ep): echo [\(names)]\(echoed ? "" : " (echo differs from request!)") + SET_REPLY CHANGE_COUNT \(mgrU16(reply.value[1...]))",
                                 tlvs: p.collected + [reply]))
        case .rdm(let n):
            for r in tlvs where r.tid == 0x0302 && r.value.count >= 26 {
                let f = r.value
                guard Array(f[3..<9]) == tuid, f[15] == n else { continue }
                guard f[16] != 1 else { // ACK_TIMER: wait longer, don't re-ask (§10.5.4)
                    p.id = UUID() // orphan the running timeout
                    p.attempt = 1
                    pending = p
                    let id = p.id
                    DispatchQueue.main.asyncAfter(deadline: .now() + Double(mgrU16(f.dropFirst(24))) / 10 + 0.5) { [weak self] in self?.timedOut(id) }
                    return
                }
                return finish(ManagerResult(ok: ManagerRDM.valid(f) && f[16] == 0, text: "EP\(ep) " + ManagerRDM.describe(f), frame: f))
            }
        case .tod:
            guard let last = tlvs.last(where: { $0.tid == 0x0304 }), last.value.count >= 2, last.value[0] == last.value[1] else { return }
            let uids = devices[Identity.hex(t)]?.tod[ep] ?? []
            finish(ManagerResult(ok: true, text: "EP\(ep) ToD: " + (uids.isEmpty ? "empty" : uids.map(ManagerRDM.uid).joined(separator: " "))))
        }
    }

    // MARK: - Log

    private func record(tx: Bool, peer: String, _ p: ManagerPacket, _ bytes: [UInt8], auth: String, tlvs: [ManagerTLV]) {
        let mode = [0x00: "Secure", 0x01: "Open", 0xFF: "Beacon"][Int(p.mode)] ?? "?"
        let text = tlvs.map { "\(ManagerTID.name($0.tid)): \(ManagerTID.describe($0.tid, $0.value))" }.joined(separator: "\n")
        append(ManagerLogEntry(tx: tx, peer: peer, uri: p.uri, sender: p.senderID, mode: mode,
                               lane: "\(p.session)/\(p.seq)", auth: auth, tlvs: text, hex: mgrHex(bytes)))
    }

    private func record(peer: String, uri: String, note: String, _ bytes: [UInt8]) {
        append(ManagerLogEntry(tx: false, peer: peer, uri: uri, sender: "?", mode: "?", lane: "–", auth: note, tlvs: "", hex: mgrHex(bytes)))
    }

    private func append(_ e: ManagerLogEntry) {
        log.append(e)
        if log.count > 1000 { log.removeFirst(log.count - 1000) }
    }
}
