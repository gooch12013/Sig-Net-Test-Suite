import Foundation

/// Plain-language names, values and editors for the Manager screens.
/// Protocol names (TID hex, RT_/EP_ prefixes) stay in the Tools tab.
enum ManagerLabels {
    static let titles: [UInt16: String] = [
        0x0305: "RDM background tasks", 0x0306: "RDM queue",
        0x0501: "MAC address", 0x0502: "IPv4 mode", 0x0503: "IPv4 address", 0x0504: "Netmask", 0x0505: "Gateway",
        0x0506: "IPv4 in use", 0x0581: "IPv6 mode", 0x0582: "IPv6 address", 0x0583: "IPv6 prefix",
        0x0584: "IPv6 gateway", 0x0585: "IPv6 in use",
        0x0601: "Supported parameters", 0x0602: "Endpoints", 0x0603: "Protocol version", 0x0604: "Firmware",
        0x0605: "Label", 0x0606: "Multicast override", 0x0607: "Identify", 0x0608: "Device status",
        0x0609: "Roles", 0x060B: "Model", 0x060D: "Onboarding (SNOW)",
        0x0901: "Universe", 0x0902: "Label", 0x0903: "Multicast override", 0x0904: "Capabilities",
        0x0905: "Direction", 0x0906: "Input priority", 0x0907: "Status", 0x0908: "Failover", 0x0909: "DMX timing",
        0x090A: "Max refresh rate", 0x090B: "Protocol", 0x090C: "Identify",
        0xFF01: "Security events", 0xFF02: "Message", 0xFF03: "Output levels",
    ]

    static func title(_ tid: UInt16) -> String { titles[tid] ?? ManagerTID.name(tid) }

    static let identifyNames = [0: "Off", 1: "Subtle", 2: "Full", 3: "Mute", 4: "Un-mute"]
    static let protocolNames = [0: "Sig-Net", 1: "Art-Net", 2: "sACN"]
    static let failoverNames = [0: "Hold last state", 1: "Blackout", 2: "Full", 3: "Play scene", 4: "Stop output"]

    static func dmxTiming(_ mode: UInt8, _ timing: UInt8) -> String {
        (mode == 1 ? "Change only" : "Continuous") + " · " + (["Maximum", "Medium", "Minimum"].indices.contains(Int(timing)) ? ["Maximum", "Medium", "Minimum"][Int(timing)] : "\(timing)") + " timing"
    }

    static let eventNames: [UInt16: String] = [
        0x0001: "Signature failures", 0x0002: "Replays", 0x0003: "Rate limiting", 0x0004: "Unauthorised onboarding",
        0x0005: "Sender table full", 0x0006: "Older session seen", 0x0007: "Out-of-order packets", 0x0008: "Rejected offboard",
    ]

    static func direction(_ v: UInt8) -> String {
        ["Disabled", "Consumer", "Supplier", "Fallback"][Int(v & 3)] + (v & 4 != 0 ? " · RDM on" : "")
    }

    /// Readable value for a parameter; falls back to the catalogue's decoder.
    static func value(_ tid: UInt16, _ v: [UInt8]) -> String {
        func bits(_ names: [Int: String], none: String) -> String {
            let word = mgrU32([UInt8](repeating: 0, count: max(0, 4 - v.count)) + v)
            let on = names.keys.sorted().filter { word & (1 << UInt32($0)) != 0 }.compactMap { names[$0] }
            return on.isEmpty ? none : on.joined(separator: " · ")
        }
        switch tid {
        case 0x0605, 0x060B, 0x0902, 0xFF02:
            let s = String(decoding: v.dropFirst(), as: UTF8.self)
            return s.isEmpty ? "—" : s
        case 0x0607, 0x090C: return identifyNames[Int(v.first ?? 0)] ?? "\(v.first ?? 0)"
        case 0x0905: return direction(v.first ?? 0)
        case 0x0907: return bits([0: "Active", 1: "Hardware fault", 2: "Locked at device", 3: "Receiving levels",
                                  4: "Several sources", 5: "Using fallback", 6: "Failover active"], none: "Idle")
        case 0x0608: return bits([0: "Hardware fault", 1: "Factory defaults", 2: "Locked at device", 3: "Open Mode"], none: "Normal")
        case 0x0609: return bits([0: "Node", 1: "Sender", 2: "Manager", 3: "Visualiser", 6: "Root firmware updates",
                                  7: "Open Mode supported"], none: "None")
        case 0x0904: return bits([0: "Receives levels", 1: "Sends levels", 2: "RDM to fixtures", 3: "RDM from fixtures",
                                  4: "Virtual", 5: "Per-channel priority"], none: "None")
        case 0x0305: return ["Off", "Background discovery", "Queue polling", "Discovery and queue polling"][Int((v.first ?? 0) & 3)]
        case 0x0306 where v.count >= 2: return "\(v[1]) of \(v[0]) slots free"
        case 0x0502: return v.first == 1 ? "DHCP" : "Static"
        case 0x090B: return protocolNames[Int(v.first ?? 0)] ?? "\(v.first ?? 0)"
        case 0x090A: return "\(v.first ?? 0) fps"
        case 0x0901: return mgrU16(v) == 0 ? "Unpatched" : "\(mgrU16(v))"
        case 0x0602: return "\(mgrU16(v))"
        case 0x0604 where v.count >= 4:
            let text = String(decoding: v.dropFirst(4), as: UTF8.self)
            return (text.isEmpty ? "Version" : text) + " · build \(mgrU32(v))"
        case 0x0501: return v.map { String(format: "%02X", $0) }.joined(separator: ":")
        case 0x0606: return v.first == 0 ? "Default addresses" : "Custom addresses"
        case 0x0908 where !v.isEmpty:
            return v[0] == 3 && v.count >= 3 ? "Play scene \(mgrU16(v.dropFirst()))" : failoverNames[Int(v[0])] ?? "Mode \(v[0])"
        case 0x0909 where v.count >= 2: return dmxTiming(v[0], v[1])
        case 0xFF03: return "\(v.filter { $0 > 0 }.count) of \(v.count) channels above zero"
        default: return ManagerTID.describe(tid, v)
        }
    }

    /// How a parameter is edited in Settings; nil = read-only there
    /// (network SETs, offboard and reboot are deliberately left to the Tools tab).
    enum Editor {
        case text, number(ClosedRange<Int>), choice([(UInt8, String)]), raw
    }

    /// Choice editors whose values are more than one byte. Play scene needs a scene number, so it stays in Debug.
    static let multiByteChoices: [UInt16: [([UInt8], String)]] = [
        0x0908: [0, 1, 2, 4].map { ([UInt8($0), 0, 0], failoverNames[$0]!) },
        0x0909: [0, 1].flatMap { m in [0, 1, 2].map { t in ([UInt8(m), UInt8(t)], dmxTiming(UInt8(m), UInt8(t))) } },
    ]

    static func editor(_ tid: UInt16) -> Editor? {
        switch tid {
        case 0x0605, 0x0902: return .text
        case 0x0901: return .number(0...63999)
        case 0x0607, 0x090C: return .choice([(0, "Off"), (1, "Subtle"), (2, "Full")])
        case 0x0905: return .choice((0...3).flatMap { d in [UInt8(d), UInt8(d) | 4] }.map { ($0, direction($0)) })
        case 0x0305: return .choice([(0, "Off"), (1, "Background discovery"), (2, "Queue polling"), (3, "Both")])
        case 0x090B: return .choice([(0, "Sig-Net"), (1, "Art-Net"), (2, "sACN")])
        case 0x0606: return .choice([(0, "Reset to default addresses")])
        case 0x0903, 0x0906: return .raw
        default: return nil
        }
    }

    /// Text shown in the editor for the current value.
    static func draft(_ tid: UInt16, _ v: [UInt8]?) -> String {
        guard let v else { return "" }
        switch editor(tid) {
        case .text: return String(decoding: v.dropFirst(), as: UTF8.self)
        case .number: return "\(mgrU16(v))"
        default: return mgrHex(v)
        }
    }

    /// Wire bytes for an edited value, or nil when it doesn't parse.
    static func encode(_ tid: UInt16, _ text: String) -> [UInt8]? {
        switch editor(tid) {
        case .text: return text.utf8.count <= 64 ? [0] + Array(text.utf8) : nil
        case .number(let r): return Int(text).flatMap { r.contains($0) ? mgrBE16(UInt16($0)) : nil }
        default: return ManagerTID.parse(tid, text)
        }
    }

    /// How the last reply from a device authenticated, in words.
    static func auth(_ a: String) -> String {
        switch a {
        case "OK": return "Verified"
        case "": return "—"
        case let x where x.hasPrefix("Open"): return "Not authenticated (Open Mode)"
        case let x where x.hasPrefix("none"): return "None (offboarded beacon)"
        default: return "Failed: \(a)"
        }
    }

    static func displayName(_ d: ManagerDevice) -> String {
        !d.label.isEmpty ? d.label : !d.model.isEmpty ? d.model : d.id
    }
}
