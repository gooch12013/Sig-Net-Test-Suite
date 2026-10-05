import Crypto
import Foundation

// Hand-built Manager wire layer (docs/manager-wire.md). The library linked by
// this app has no Manager, so every byte here is from the spec.

public func mgrBE16(_ v: UInt16) -> [UInt8] { [UInt8(v >> 8), UInt8(v & 0xFF)] }
public func mgrBE32(_ v: UInt32) -> [UInt8] { [UInt8(v >> 24), UInt8(v >> 16 & 0xFF), UInt8(v >> 8 & 0xFF), UInt8(v & 0xFF)] }
public func mgrU16<C: Collection>(_ b: C) -> UInt16 where C.Element == UInt8 { b.prefix(2).reduce(0) { $0 << 8 | UInt16($1) } }
public func mgrU32<C: Collection>(_ b: C) -> UInt32 where C.Element == UInt8 { b.prefix(4).reduce(0) { $0 << 8 | UInt32($1) } }
public func mgrHex<C: Collection>(_ b: C) -> String where C.Element == UInt8 { b.map { String(format: "%02x", $0) }.joined() }
public func mgrBytes(hex: String) -> [UInt8]? {
    let s = hex.filter { !" :-".contains($0) }.lowercased().replacingOccurrences(of: "0x", with: "")
    guard s.count % 2 == 0 else { return nil }
    var out: [UInt8] = [], i = s.startIndex
    while i < s.endIndex {
        let j = s.index(i, offsetBy: 2)
        guard let b = UInt8(s[i..<j], radix: 16) else { return nil }
        out.append(b); i = j
    }
    return out
}

// MARK: - Keys (§1)

/// K0 → role keys by HKDF-Expand only (L = 32 ⇒ HMAC(K0, info ‖ 0x01)).
/// SymmetricKey zeroes its storage on release; the caller's K0 array is wiped here.
struct ManagerKeys {
    private let k0: SymmetricKey
    let kmGlobal: SymmetricKey
    let kc: SymmetricKey
    private var local: [String: SymmetricKey] = [:]

    init(k0 bytes: inout [UInt8]) {
        let prk = SymmetricKey(data: bytes)
        wipe(&bytes)
        k0 = prk
        kmGlobal = Self.expand(prk, "Sig-Net-Manager-v1")
        kc = Self.expand(prk, "Sig-Net-Citizen-v1")
    }

    static func expand(_ prk: SymmetricKey, _ info: String) -> SymmetricKey {
        SymmetricKey(data: HMAC<SHA256>.authenticationCode(for: Array(info.utf8) + [0x01], using: prk))
    }

    /// Km_local of the *target* Node: info = "Sig-Net-Manager-v1-" + 12 uppercase hex.
    mutating func kmLocal(_ tuid: [UInt8]) -> SymmetricKey {
        let hex = Identity.hex(tuid)
        if let k = local[hex] { return k }
        let k = Self.expand(k0, "Sig-Net-Manager-v1-" + hex)
        local[hex] = k
        return k
    }
}

// MARK: - CoAP + Sig-Net options (§2) and HMAC (§4)

public struct ManagerPacket {
    var mid: UInt16 = 0
    var tkl = 0
    var segs: [String] = []
    var query: [String] = []
    var mode: UInt8 = 0
    var tuid = [UInt8](repeating: 0, count: 6)
    var ep: UInt16 = 0
    var mfg: UInt16 = 0
    var session: UInt32 = 0
    var seq: UInt32 = 0
    var auth: [UInt8] = []
    var payload: [UInt8] = []

    var uri: String { "/" + segs.joined(separator: "/") + (query.isEmpty ? "" : "?" + query.joined(separator: "&")) }
    var senderID: String { Identity.hex(tuid) + String(format: ":%d", ep) }

    /// uri ‖ 19-byte meta ‖ payload. Header, token, option headers and Auth are not covered.
    var macInput: [UInt8] {
        Array(uri.utf8) + [mode] + tuid + mgrBE16(ep) + mgrBE16(mfg) + mgrBE32(session) + mgrBE32(seq) + payload
    }

    mutating func sign(_ key: SymmetricKey) {
        auth = Array(HMAC<SHA256>.authenticationCode(for: macInput, using: key))
    }

    /// Constant-time compare (CryptoKit).
    func verify(_ key: SymmetricKey) -> Bool {
        auth.count == 32 && HMAC<SHA256>.isValidAuthenticationCode(auth, authenticating: macInput, using: key)
    }

    func encode() -> [UInt8] {
        var out: [UInt8] = [0x50, 0x02] + mgrBE16(mid), prev = 0
        func opt(_ n: Int, _ v: [UInt8]) {
            func nib(_ x: Int) -> Int { x < 13 ? x : x < 269 ? 13 : 14 }
            func ext(_ x: Int) -> [UInt8] { x < 13 ? [] : x < 269 ? [UInt8(x - 13)] : mgrBE16(UInt16(x - 269)) }
            let d = n - prev
            out += [UInt8(nib(d) << 4 | nib(v.count))] + ext(d) + ext(v.count) + v
            prev = n
        }
        segs.forEach { opt(11, Array($0.utf8)) }
        query.forEach { opt(15, Array($0.utf8)) }
        opt(2076, [mode])
        opt(2108, tuid + mgrBE16(ep))
        opt(2140, mgrBE16(mfg))
        opt(2172, mgrBE32(session))
        opt(2204, mgrBE32(seq))
        opt(2236, auth) // always present; length 0 in Open/Beacon (library decoder requires it)
        if !payload.isEmpty { out += [0xFF] + payload }
        return out
    }

    /// As strict as the library decoder (manager-wire.md §2 "Decoder strictness").
    static func decode(_ b: [UInt8]) throws -> ManagerPacket {
        guard b.count >= 4 else { throw SigNetError("shorter than CoAP header") }
        guard b.count <= 1400 else { throw SigNetError("datagram over 1400 B") }
        guard b[0] >> 6 == 1 else { throw SigNetError("CoAP version \(b[0] >> 6)") }
        var p = ManagerPacket()
        p.tkl = Int(b[0] & 0x0F)
        guard p.tkl <= 8 else { throw SigNetError("TKL \(p.tkl) > 8") }
        p.mid = mgrU16(b[2...])
        var i = 4 + p.tkl, num = 0, seen = Set<Int>()
        func ext(_ n: Int) throws -> Int {
            switch n {
            case 13:
                guard i < b.count else { throw SigNetError("truncated option header") }
                i += 1; return Int(b[i - 1]) + 13
            case 14:
                guard i + 1 < b.count else { throw SigNetError("truncated option header") }
                i += 2; return Int(mgrU16(b[(i - 2)...])) + 269
            case 15: throw SigNetError("reserved option nibble 15")
            default: return n
            }
        }
        while i < b.count {
            let h = b[i]
            i += 1
            if h == 0xFF {
                guard i < b.count else { throw SigNetError("payload marker with empty payload") }
                p.payload = Array(b[i...])
                break
            }
            guard !seen.contains(2236) else { throw SigNetError("option after Sig-Net-Auth") }
            num += try ext(Int(h >> 4))
            let len = try ext(Int(h & 0x0F))
            guard i + len <= b.count else { throw SigNetError("truncated option \(num)") }
            let v = Array(b[i..<i + len])
            i += len
            switch num {
            case 11: p.segs.append(String(decoding: v, as: UTF8.self))
            case 15: p.query.append(String(decoding: v, as: UTF8.self))
            case 2076, 2108, 2140, 2172, 2204, 2236:
                guard seen.insert(num).inserted else { throw SigNetError("duplicate option \(num)") }
                let want = [2076: 1, 2108: 8, 2140: 2, 2172: 4, 2204: 4][num]
                guard want.map({ len == $0 }) ?? (len == 0 || len == 32) else {
                    throw SigNetError("option \(num) length \(len)")
                }
                switch num {
                case 2076: p.mode = v[0]
                case 2108: p.tuid = Array(v[0..<6]); p.ep = mgrU16(v[6...])
                case 2140: p.mfg = mgrU16(v)
                case 2172: p.session = mgrU32(v)
                case 2204: p.seq = mgrU32(v)
                default: p.auth = v
                }
            default:
                if num & 1 == 1 { throw SigNetError("unknown critical option \(num)") }
            }
        }
        guard seen.count == 6 else { throw SigNetError("missing Sig-Net security option(s) \(Set([2076, 2108, 2140, 2172, 2204, 2236]).subtracting(seen).sorted())") }
        guard [0x00, 0x01, 0xFF].contains(p.mode) else { throw SigNetError(String(format: "security mode 0x%02X", p.mode)) }
        guard (p.mode == 0) == (p.auth.count == 32) else { throw SigNetError("auth length \(p.auth.count) for mode \(p.mode)") }
        if p.mode != 0xFF { // beacons skip these checks in the library too
            guard b[0] >> 4 & 3 == 1 else { throw SigNetError("not CoAP NON") }
            guard b[1] == 0x02 else { throw SigNetError(String(format: "CoAP code 0x%02X, not POST", b[1])) }
        }
        if p.mode != 0, p.session != 0 || p.seq != 0 { throw SigNetError("non-zero session/seq in unauthenticated mode") }
        return p
    }
}

// MARK: - TLV (§10)

public struct ManagerTLV: Hashable {
    public var tid: UInt16
    public var value: [UInt8]
    public init(tid: UInt16, value: [UInt8] = []) { self.tid = tid; self.value = value }

    static func encode(_ list: [ManagerTLV]) -> [UInt8] {
        list.flatMap { mgrBE16($0.tid) + mgrBE16(UInt16($0.value.count)) + $0.value }
    }

    /// nil when a TLV runs past the end of the payload.
    static func decode(_ b: [UInt8]) -> [ManagerTLV]? {
        var out: [ManagerTLV] = [], i = 0
        while i < b.count {
            guard i + 4 <= b.count else { return nil }
            let len = Int(mgrU16(b[(i + 2)...]))
            guard i + 4 + len <= b.count else { return nil }
            out.append(ManagerTLV(tid: mgrU16(b[i...]), value: Array(b[(i + 4)..<(i + 4 + len)])))
            i += 4 + len
        }
        return out
    }
}

// MARK: - URI grammar (§3)

struct ManagerURI {
    let kind: String // poll, manager, node, node_lost, node_beacon, aux
    let scope: String
    var tuid: [UInt8]? = nil
    var ep: UInt16 = 0

    /// Same rules as the library parser: uppercase TUID, decimal ep without leading zeros.
    init(_ segs: [String]) throws {
        guard segs.count >= 4, segs[0] == "sig-net", segs[1] == "v1" else { throw SigNetError("not /sig-net/v1/…") }
        scope = segs[2]
        kind = segs[3]
        switch kind {
        case "poll":
            guard segs.count == 4 else { throw SigNetError("poll takes no parameters") }
        case "manager", "node", "aux", "node_lost", "node_beacon":
            guard segs.count == 6 else { throw SigNetError("\(kind) needs TUID and endpoint") }
            let t = segs[4]
            guard t.count == 12, t.allSatisfy({ "0123456789ABCDEF".contains($0) }), let raw = mgrBytes(hex: t) else {
                throw SigNetError("bad TUID segment \(t)")
            }
            let e = segs[5]
            guard let v = UInt16(e), e == String(v) else { throw SigNetError("bad endpoint segment \(e)") }
            if kind == "node_lost" || kind == "node_beacon", v != 0 { throw SigNetError("\(kind) endpoint must be 0") }
            tuid = raw
            ep = v
        default: throw SigNetError("unknown resource \(kind)")
        }
    }
}

// MARK: - E1.20 frames (built independently of the Device tab's responder, so a shared bug can't cancel out)

public enum ManagerRDM {
    static func frame(dest: [UInt8], src: [UInt8], tn: UInt8, cc: UInt8, pid: UInt16, pd: [UInt8], sub: UInt16 = 0) -> [UInt8] {
        var body: [UInt8] = [0xCC, 0x01, UInt8(24 + pd.count)]
        body += dest
        body += src
        body += [tn, 0x01, 0x00] // TN, port 1, message count 0
        body += mgrBE16(sub)
        body += [cc]
        body += mgrBE16(pid)
        body += [UInt8(pd.count)]
        body += pd
        return body + mgrBE16(body.reduce(0) { $0 &+ UInt16($1) })
    }

    public static func valid(_ f: [UInt8]) -> Bool {
        guard f.count >= 26, f.count <= 257, f[0] == 0xCC, f[1] == 0x01, Int(f[2]) == f.count - 2,
              Int(f[23]) == f.count - 26 else { return false }
        return f.dropLast(2).reduce(0) { $0 &+ UInt16($1) } == mgrU16(f.suffix(2))
    }

    public static let pids: [UInt16: String] = [
        0x0050: "SUPPORTED_PARAMETERS", 0x0060: "DEVICE_INFO", 0x0082: "DEVICE_LABEL",
        0x00C0: "SOFTWARE_VERSION_LABEL", 0x00F0: "DMX_START_ADDRESS", 0x1000: "IDENTIFY_DEVICE",
    ]
    static let nacks: [UInt16: String] = [
        0: "UNKNOWN_PID", 1: "FORMAT_ERROR", 2: "HARDWARE_FAULT", 3: "PROXY_REJECT", 4: "WRITE_PROTECT",
        5: "UNSUPPORTED_COMMAND_CLASS", 6: "DATA_OUT_OF_RANGE", 7: "BUFFER_FULL", 8: "PACKET_SIZE_UNSUPPORTED",
        9: "SUB_DEVICE_OUT_OF_RANGE", 10: "PROXY_BUFFER_FULL",
    ]

    public static func uid(_ b: [UInt8]) -> String { String(format: "%02X%02X:%02X%02X%02X%02X", b[0], b[1], b[2], b[3], b[4], b[5]) }

    /// One-line decode of a response (or request) frame.
    static func describe(_ f: [UInt8]) -> String {
        guard f.count >= 24 else { return "short frame (\(f.count) B)" }
        let pid = mgrU16(f[21...])
        let pd = Array(f.dropFirst(24).prefix(Int(f[23])))
        let cc = [0x20: "GET", 0x21: "GET_RESPONSE", 0x30: "SET", 0x31: "SET_RESPONSE"][Int(f[20])] ?? String(format: "CC 0x%02X", f[20])
        var s = "\(cc) \(pids[pid] ?? String(format: "PID 0x%04X", pid)) TN \(f[15])"
        if f[20] & 1 == 1 {
            switch f[16] {
            case 0: s += " ACK" + (pd.isEmpty ? "" : ": " + decode(pid: pid, pd))
            case 1: s += " ACK_TIMER \(Int(mgrU16(pd)) * 100) ms"
            case 2: let r = mgrU16(pd); s += " NACK " + (nacks[r] ?? String(format: "0x%04X", r))
            case 3: s += " ACK_OVERFLOW (\(pd.count) B)"
            default: s += " response type \(f[16])"
            }
        } else if !pd.isEmpty { s += " PD \(mgrHex(pd))" }
        return s + (valid(f) ? "" : " [BAD FRAME/CHECKSUM]")
    }

    static func decode(pid: UInt16, _ pd: [UInt8]) -> String {
        let text = { String(decoding: pd, as: UTF8.self) }
        switch pid {
        case 0x0060 where pd.count >= 19:
            return String(format: "RDM %d.%d, model 0x%04X, category 0x%04X, sw 0x%08X, footprint %d, personality %d/%d, start %d, sub-devices %d, sensors %d",
                          pd[0], pd[1], mgrU16(pd[2...]), mgrU16(pd[4...]), mgrU32(pd[6...]), mgrU16(pd[10...]),
                          pd[12], pd[13], mgrU16(pd[14...]), mgrU16(pd[16...]), pd[18])
        case 0x0050: return stride(from: 0, to: pd.count - 1, by: 2).map { String(format: "0x%04X", mgrU16(pd[$0...])) }.joined(separator: " ")
        case 0x0082, 0x00C0: return "\"\(text())\""
        case 0x00F0 where pd.count == 2: return "\(mgrU16(pd))"
        case 0x1000 where pd.count == 1: return pd[0] == 0 ? "off" : "on"
        default: return mgrHex(pd)
        }
    }
}
