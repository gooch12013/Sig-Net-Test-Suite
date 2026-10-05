import Foundation

/// TID catalogue (docs/manager-semantics.md §4). Data-plane TIDs (0x01xx/0x02xx) are left out:
/// they never travel on the Command URI.
public struct ManagerTID: Identifiable, Hashable {
    public enum Kind { case label, u8, u16, u32, bits8, bits32, ipv4, ipv6, text, hex }

    public let tid: UInt16
    public let name: String
    public let family: String
    public let get: Bool
    public let set: Bool
    let scope: String // R root, D data EP, R+D both
    let kind: Kind
    public let layout: String
    public var id: UInt16 { tid }
    public var hex: String { String(format: "0x%04X", tid) }

    public static let all: [ManagerTID] = [
        .init(tid: 0x0001, name: "POLL", family: "Discovery", get: false, set: false, scope: "R+D", kind: .hex, layout: "TUID, SoemCode u32, TUID_LO, TUID_HI, EP u16, QL u8 (Manager → /poll only)"),
        .init(tid: 0x0002, name: "POLL_REPLY", family: "Discovery", get: false, set: false, scope: "R+D", kind: .hex, layout: "TUID(6), SoemCode u32, CHANGE_COUNT u16"),
        .init(tid: 0x0003, name: "SET_REPLY", family: "Discovery", get: false, set: false, scope: "R+D", kind: .hex, layout: "flags u8 (0), CHANGE_COUNT u16"),
        .init(tid: 0x0301, name: "RDM_COMMAND", family: "RDM", get: false, set: false, scope: "D", kind: .hex, layout: "E1.20 request frame 26-257 B (use the RDM tab)"),
        .init(tid: 0x0302, name: "RDM_RESPONSE", family: "RDM", get: false, set: false, scope: "D", kind: .hex, layout: "E1.20 response frame"),
        .init(tid: 0x0303, name: "RDM_TOD_CONTROL", family: "RDM", get: false, set: true, scope: "D", kind: .u8, layout: "0 send ToD, 1 flush + full discovery"),
        .init(tid: 0x0304, name: "RDM_TOD_DATA", family: "RDM", get: false, set: false, scope: "D", kind: .hex, layout: "index, total, UID×6…"),
        .init(tid: 0x0305, name: "RDM_EP_CONFIG", family: "RDM", get: true, set: true, scope: "D", kind: .bits8, layout: "bit0 background discovery, bit1 background queue polling"),
        .init(tid: 0x0306, name: "RDM_FLOW_CONTROL", family: "RDM", get: true, set: false, scope: "D", kind: .hex, layout: "total FIFO u8, available u8"),
        .init(tid: 0x0401, name: "RT_OFFBOARD", family: "Offboard", get: false, set: true, scope: "R", kind: .hex, layout: "57495045 \"WIPE\" (only SET in packet)"),
        .init(tid: 0x0501, name: "NW_MAC_ADDRESS", family: "Network", get: true, set: false, scope: "R", kind: .hex, layout: "MAC(6)"),
        .init(tid: 0x0502, name: "NW_IPV4_MODE", family: "Network", get: true, set: true, scope: "R", kind: .u8, layout: "0 static, 1 DHCP"),
        .init(tid: 0x0503, name: "NW_IPV4_ADDRESS", family: "Network", get: true, set: true, scope: "R", kind: .ipv4, layout: "IPv4"),
        .init(tid: 0x0504, name: "NW_IPV4_NETMASK", family: "Network", get: true, set: true, scope: "R", kind: .ipv4, layout: "IPv4"),
        .init(tid: 0x0505, name: "NW_IPV4_GATEWAY", family: "Network", get: true, set: true, scope: "R", kind: .ipv4, layout: "IPv4"),
        .init(tid: 0x0506, name: "NW_IPV4_CURRENT", family: "Network", get: true, set: false, scope: "R", kind: .ipv4, layout: "IP, mask, gateway (3×IPv4)"),
        .init(tid: 0x0581, name: "NW_IPV6_MODE", family: "Network", get: true, set: true, scope: "R", kind: .u8, layout: "0 static, 1 SLAAC, 2 DHCPv6"),
        .init(tid: 0x0582, name: "NW_IPV6_ADDRESS", family: "Network", get: true, set: true, scope: "R", kind: .ipv6, layout: "IPv6(16)"),
        .init(tid: 0x0583, name: "NW_IPV6_PREFIX", family: "Network", get: true, set: true, scope: "R", kind: .u8, layout: "prefix 0-128"),
        .init(tid: 0x0584, name: "NW_IPV6_GATEWAY", family: "Network", get: true, set: true, scope: "R", kind: .ipv6, layout: "IPv6(16)"),
        .init(tid: 0x0585, name: "NW_IPV6_CURRENT", family: "Network", get: true, set: false, scope: "R", kind: .hex, layout: "addr(16), prefix u8, gateway(16)"),
        .init(tid: 0x0601, name: "RT_SUPPORTED_TIDS", family: "Root", get: true, set: false, scope: "R", kind: .hex, layout: "u16 array"),
        .init(tid: 0x0602, name: "RT_ENDPOINT_COUNT", family: "Root", get: true, set: false, scope: "R", kind: .u16, layout: "u16 data EPs"),
        .init(tid: 0x0603, name: "RT_PROTOCOL_VERSION", family: "Root", get: true, set: false, scope: "R", kind: .u8, layout: "u8 major"),
        .init(tid: 0x0604, name: "RT_FIRMWARE_VERSION", family: "Root", get: true, set: false, scope: "R", kind: .hex, layout: "u32 version + ASCII ≤64"),
        .init(tid: 0x0605, name: "RT_DEVICE_LABEL", family: "Root", get: true, set: true, scope: "R", kind: .label, layout: "enc 0x00 + text ≤64"),
        .init(tid: 0x0606, name: "RT_MULT_OVERRIDE", family: "Root", get: true, set: true, scope: "R", kind: .u8, layout: "read 0/1; SET only 0 (reset all)"),
        .init(tid: 0x0607, name: "RT_IDENTIFY", family: "Root", get: true, set: true, scope: "R", kind: .u8, layout: "0 off, 1 subtle, 2 full, 3 mute, 4 un-mute"),
        .init(tid: 0x0608, name: "RT_STATUS", family: "Root", get: true, set: false, scope: "R", kind: .bits32, layout: "0 hw fault, 1 factory defaults, 2 UI locked, 3 Open Mode"),
        .init(tid: 0x0609, name: "RT_ROLE_CAPABILITY", family: "Root", get: true, set: false, scope: "R", kind: .bits32, layout: "0 Node, 1 Sender, 2 Manager, 3 Visualiser, 6 Root FW, 7 Open Mode"),
        .init(tid: 0x060A, name: "RT_REBOOT", family: "Root", get: false, set: true, scope: "R", kind: .hex, layout: "FF/FE + 424F4F54 \"BOOT\""),
        .init(tid: 0x060B, name: "RT_MODEL_NAME", family: "Root", get: true, set: false, scope: "R", kind: .label, layout: "enc 0x00 + text ≤64"),
        .init(tid: 0x060D, name: "RT_OTW_CAPABILITY", family: "Root", get: true, set: false, scope: "R", kind: .hex, layout: "port u16, bits: DTLS1.2, DTLS1.3, TLS1.2, TLS1.3, PIN"),
        .init(tid: 0x0901, name: "EP_UNIVERSE", family: "Endpoint", get: true, set: true, scope: "D", kind: .u16, layout: "u16 1-63999, 0 unpatched"),
        .init(tid: 0x0902, name: "EP_LABEL", family: "Endpoint", get: true, set: true, scope: "D", kind: .label, layout: "enc 0x00 + text ≤64"),
        .init(tid: 0x0903, name: "EP_MULT_OVERRIDE", family: "Endpoint", get: true, set: true, scope: "D", kind: .ipv4, layout: "IPv4 group, 0.0.0.0 clear"),
        .init(tid: 0x0904, name: "EP_CAPABILITY", family: "Endpoint", get: true, set: false, scope: "D", kind: .bits32, layout: "0 consume LEVEL, 1 supply, 2 consume RDM, 3 supply RDM, 4 virtual, 5 per-slot prio"),
        .init(tid: 0x0905, name: "EP_DIRECTION", family: "Endpoint", get: true, set: true, scope: "D", kind: .bits8, layout: "bits0-1 0 off/1 cons/2 supp/3 fallback, bit2 RDM"),
        .init(tid: 0x0906, name: "EP_INPUT_PRIORITY", family: "Endpoint", get: true, set: true, scope: "D", kind: .hex, layout: "0-200 per slot; 1 B = all"),
        .init(tid: 0x0907, name: "EP_STATUS", family: "Endpoint", get: true, set: false, scope: "D", kind: .bits32, layout: "0 active, 1 hw fault, 2 UI lock, 3 rx LEVEL, 4 >1 stream, 5 fallback, 6 failover"),
        .init(tid: 0x0908, name: "EP_FAILOVER", family: "Endpoint", get: true, set: true, scope: "D", kind: .hex, layout: "mode u8 (0 hold…4 stop), scene u16"),
        .init(tid: 0x0909, name: "EP_DMX_TIMING", family: "Endpoint", get: true, set: true, scope: "D", kind: .hex, layout: "mode u8, timing u8"),
        .init(tid: 0x090A, name: "EP_REFRESH_CAPABILITY", family: "Endpoint", get: true, set: false, scope: "D", kind: .u8, layout: "max fps"),
        .init(tid: 0x090B, name: "EP_PROTOCOL", family: "Endpoint", get: true, set: true, scope: "D", kind: .u8, layout: "0 Sig-Net, 1 Art-Net, 2 sACN (unauthenticated!)"),
        .init(tid: 0x090C, name: "EP_IDENTIFY", family: "Endpoint", get: true, set: true, scope: "D", kind: .u8, layout: "0 off, 1 subtle, 2 full"),
        .init(tid: 0xFF01, name: "DG_SECURITY_EVENT", family: "Diagnostic", get: true, set: false, scope: "R", kind: .hex, layout: "code u16, count u32, addr type, IP"),
        .init(tid: 0xFF02, name: "DG_MESSAGE", family: "Diagnostic", get: true, set: false, scope: "R+D", kind: .text, layout: "ASCII ≤64"),
        .init(tid: 0xFF03, name: "DG_LEVEL_FOLDBACK", family: "Diagnostic", get: true, set: false, scope: "D", kind: .hex, layout: "DMX buffer"),
    ]
    public static let byTID = Dictionary(uniqueKeysWithValues: all.map { ($0.tid, $0) })

    static func name(_ tid: UInt16) -> String { byTID[tid]?.name ?? String(format: "TID 0x%04X", tid) }

    /// Human-readable value. Unknown or odd-length values fall back to hex.
    static func describe(_ tid: UInt16, _ v: [UInt8]) -> String {
        func bits(_ x: UInt32) -> String {
            let on = (0..<32).filter { x >> $0 & 1 == 1 }.map(String.init)
            return String(format: "0x%0*X", v.count * 2, x) + " bits[" + on.joined(separator: ",") + "]"
        }
        switch tid {
        case 0x0002 where v.count == 12:
            return "TUID \(Identity.hex(Array(v[0..<6]))) soem " + String(format: "0x%08X", mgrU32(v[6...])) + " CC \(mgrU16(v[10...]))"
        case 0x0003 where v.count == 3: return "flags \(v[0]) CC \(mgrU16(v[1...]))"
        case 0x0302: return ManagerRDM.describe(v)
        case 0x0304 where v.count >= 2:
            let uids = stride(from: 2, to: v.count - 5, by: 6).map { ManagerRDM.uid(Array(v[$0..<$0 + 6])) }
            return "packet \(v[0])/\(v[1]): " + (uids.isEmpty ? "empty" : uids.joined(separator: " "))
        case 0x0306 where v.count == 2: return "total \(v[0]) available \(v[1])"
        case 0x0506 where v.count == 12: return (0..<3).map { ip4(Array(v[$0 * 4..<$0 * 4 + 4])) }.joined(separator: " / ")
        case 0x0601: return stride(from: 0, to: v.count - 1, by: 2).map { String(format: "%04X", mgrU16(v[$0...])) }.joined(separator: " ")
        case 0x0604 where v.count >= 4: return String(format: "0x%08X ", mgrU32(v)) + "\"\(String(decoding: v[4...], as: UTF8.self))\""
        case 0x060D where v.count == 3: return "port \(mgrU16(v)) " + bits(UInt32(v[2]))
        case 0x0908 where v.count == 3: return "mode \(v[0]) scene \(mgrU16(v[1...]))"
        case 0xFF01 where v.count >= 7:
            var s = String(format: "code 0x%04X count %d", mgrU16(v), mgrU32(v[2...]))
            if v[6] == 1, v.count >= 11 { s += " from " + ip4(Array(v[7..<11])) }
            return s
        default: break
        }
        switch (byTID[tid]?.kind ?? .hex, v.count) {
        case (.label, 1...): return "enc 0x\(String(format: "%02X", v[0])) \"\(String(decoding: v[1...], as: UTF8.self))\""
        case (.text, _): return "\"\(String(decoding: v, as: UTF8.self))\""
        case (.u8, 1): return "\(v[0])"
        case (.u16, 2): return "\(mgrU16(v))"
        case (.u32, 4): return "\(mgrU32(v))"
        case (.bits8, 1): return bits(UInt32(v[0]))
        case (.bits32, 4): return bits(mgrU32(v))
        case (.ipv4, 4): return ip4(v)
        case (.ipv6, 16): return stride(from: 0, to: 16, by: 2).map { String(format: "%x", mgrU16(v[$0...])) }.joined(separator: ":")
        default: return v.isEmpty ? "(empty)" : mgrHex(v)
        }
    }

    static func ip4(_ b: [UInt8]) -> String { b.map(String.init).joined(separator: ".") }

    /// Typed SET value from text: labels take plain text, numbers take decimal or 0x…,
    /// IPv4 dotted quad; everything else (and anything prefixed "hex:") is hex.
    public static func parse(_ tid: UInt16, _ text: String) -> [UInt8]? {
        let t = text.trimmingCharacters(in: .whitespaces)
        if t.hasPrefix("hex:") { return mgrBytes(hex: String(t.dropFirst(4))) }
        func num(_ max: UInt64) -> UInt64? {
            let v = t.hasPrefix("0x") ? UInt64(t.dropFirst(2), radix: 16) : UInt64(t)
            return v.flatMap { $0 <= max ? $0 : nil }
        }
        switch byTID[tid]?.kind ?? .hex {
        case .label: return t.utf8.count <= 64 ? [0x00] + Array(t.utf8) : nil
        case .text: return Array(t.utf8)
        case .u8, .bits8: return num(0xFF).map { [UInt8($0)] }
        case .u16: return num(0xFFFF).map { mgrBE16(UInt16($0)) }
        case .u32, .bits32: return num(0xFFFF_FFFF).map { mgrBE32(UInt32($0)) }
        case .ipv4:
            let parts = t.split(separator: ".").compactMap { UInt8($0) }
            return parts.count == 4 ? parts : nil
        case .ipv6, .hex: return mgrBytes(hex: t)
        }
    }
}
