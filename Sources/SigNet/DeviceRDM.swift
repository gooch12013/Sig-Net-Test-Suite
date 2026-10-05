import Foundation

/// Virtual E1.20 responder behind one virtual endpoint (PF §6.8.2: the Node
/// terminates RDM itself). Pure frames-in/frames-out, so the self-test can
/// drive it without a network.
public struct DeviceRDMResponder {
    public static let modelID: UInt16 = 0x0001 // also the SoemCode variant (PF §6.5 recommends they match)
    public static let softwareID: UInt32 = 0x0001_0000
    static let footprint: UInt16 = 8

    public let uid: [UInt8]
    var label: String
    let softwareLabel: String
    public var identify = false
    var startAddress: UInt16 = 1

    public init(uid: [UInt8], label: String, softwareLabel: String) { self.uid = uid; self.label = label; self.softwareLabel = softwareLabel }

    /// The response to `req`, or nil when E1.20 says stay silent: bad frame,
    /// someone else's UID, a broadcast, or a non-GET/SET class.
    public mutating func handle(_ req: [UInt8]) -> [UInt8]? {
        guard Self.valid(req) else { return nil }
        let dest = Array(req[3..<9])
        let broadcast = dest[2...] == [0xFF, 0xFF, 0xFF, 0xFF] && (dest[..<2] == [0xFF, 0xFF] || dest[..<2] == uid[..<2])
        guard dest == uid || broadcast, req[20] == 0x20 || req[20] == 0x30 else { return nil }
        let reply = answer(req)
        return broadcast ? nil : reply
    }

    private mutating func answer(_ req: [UInt8]) -> [UInt8] {
        let get = req[20] == 0x20
        let pid = UInt16(req[21]) << 8 | UInt16(req[22])
        let pd = Array(req[24..<24 + Int(req[23])])
        func ack(_ data: [UInt8] = []) -> [UInt8] { Self.response(to: req, from: uid, type: 0x00, pd: data) }
        func nack(_ reason: UInt16) -> [UInt8] { Self.nack(req, from: uid, reason: reason) }

        guard req[18] == 0, req[19] == 0 else { return nack(0x0009) } // SUB_DEVICE_OUT_OF_RANGE: root only
        switch (pid, get) {
        case (0x0060, true): // DEVICE_INFO
            var info: [UInt8] = [0x01, 0x00] + be(Self.modelID) + [0x01, 0x00] // RDM 1.0, model, category fixture
            info += be(Self.softwareID) + be(Self.footprint)
            info += [1, 1] + be(startAddress) + [0, 0, 0] // personality 1/1, address, no sub-devices or sensors
            return ack(info)
        case (0x0050, true): // SUPPORTED_PARAMETERS: only the non-required ones (E1.20 §10.4.1)
            return ack(be(UInt16(0x0082)))
        case (0x0082, true): return ack(Array(label.utf8.prefix(32)))
        case (0x0082, false):
            guard pd.count <= 32 else { return nack(0x0001) } // FORMAT_ERROR
            label = String(decoding: pd, as: UTF8.self)
            return ack()
        case (0x1000, true): return ack([identify ? 1 : 0])
        case (0x1000, false):
            guard pd.count == 1 else { return nack(0x0001) }
            guard pd[0] <= 1 else { return nack(0x0006) } // DATA_OUT_OF_RANGE
            identify = pd[0] == 1
            return ack()
        case (0x00C0, true): return ack(Array(softwareLabel.utf8.prefix(32)))
        case (0x00F0, true): return ack(be(startAddress))
        case (0x00F0, false):
            guard pd.count == 2 else { return nack(0x0001) }
            let address = UInt16(pd[0]) << 8 | UInt16(pd[1])
            guard (1...513 - Self.footprint).contains(address) else { return nack(0x0006) }
            startAddress = address
            return ack()
        case (0x0060, false), (0x0050, false), (0x00C0, false):
            return nack(0x0005) // UNSUPPORTED_COMMAND_CLASS
        default:
            return nack(0x0000) // UNKNOWN_PID
        }
    }

    /// PF §10.5.2: a state change is followed by an unsolicited
    /// GET_COMMAND_RESPONSE, broadcast, so every Manager's cache follows.
    public mutating func notification(after reply: [UInt8]) -> [UInt8]? {
        guard reply.count >= 26, reply[20] == 0x31, reply[16] == 0x00 else { return nil }
        let get = Self.frame(dest: uid, src: [UInt8](repeating: 0xFF, count: 6), tn: 0, type: 1, sub: (0, 0),
                             cc: 0x20, pid: UInt16(reply[21]) << 8 | UInt16(reply[22]), pd: [])
        return answer(get) // answers to the request's source: all-FF, i.e. everyone
    }

    // MARK: - Frame plumbing

    /// Start codes, length relation and additive checksum (E1.20 §6.2).
    static func valid(_ f: [UInt8]) -> Bool {
        guard f.count >= 26, f[0] == 0xCC, f[1] == 0x01 else { return false }
        let length = Int(f[2])
        guard length >= 24, f.count == length + 2, Int(f[23]) == length - 24 else { return false }
        return checksum(f[..<length]) == UInt16(f[length]) << 8 | UInt16(f[length + 1])
    }

    static func response(to req: [UInt8], from uid: [UInt8], type: UInt8, pd: [UInt8]) -> [UInt8] {
        frame(dest: Array(req[9..<15]), src: uid, tn: req[15], type: type, sub: (req[18], req[19]),
              cc: req[20] + 1, pid: UInt16(req[21]) << 8 | UInt16(req[22]), pd: pd)
    }

    public static func nack(_ req: [UInt8], from uid: [UInt8], reason: UInt16) -> [UInt8] {
        response(to: req, from: uid, type: 0x02, pd: be(reason))
    }

    static func frame(dest: [UInt8], src: [UInt8], tn: UInt8, type: UInt8, sub: (UInt8, UInt8),
                      cc: UInt8, pid: UInt16, pd: [UInt8]) -> [UInt8] {
        var body: [UInt8] = [0xCC, 0x01, UInt8(24 + pd.count)] + dest + src
        body += [tn, type, 0, sub.0, sub.1, cc] + be(pid)
        body += [UInt8(pd.count)] + pd
        return sealed(body)
    }

    private static func sealed(_ body: [UInt8]) -> [UInt8] { body + be(checksum(body[...])) }
    private static func checksum(_ bytes: ArraySlice<UInt8>) -> UInt16 { bytes.reduce(0) { $0 &+ UInt16($1) } }

    static let pidNames: [UInt16: String] = [
        0x0050: "SUPPORTED_PARAMETERS", 0x0060: "DEVICE_INFO", 0x0082: "DEVICE_LABEL",
        0x00C0: "SOFTWARE_VERSION_LABEL", 0x00F0: "DMX_START_ADDRESS", 0x1000: "IDENTIFY_DEVICE",
    ]

    /// One log line: "GET DEVICE_INFO (0x0060) PDL 0", "GET_RESPONSE … ACK PDL 19 …".
    public static func describe(_ f: [UInt8]) -> String {
        guard f.count >= 24 else { return "short frame (\(f.count) bytes)" }
        let classes: [UInt8: String] = [0x20: "GET", 0x21: "GET_RESPONSE", 0x30: "SET", 0x31: "SET_RESPONSE"]
        let pid = UInt16(f[21]) << 8 | UInt16(f[22])
        let type = f[20] & 1 == 1 && f[16] < 4 ? [" ACK", " ACK_TIMER", " NACK", " ACK_OVERFLOW"][Int(f[16])] : ""
        let pd = Identity.hex(Array(f.dropFirst(24).prefix(Int(f[23]))))
        return "\(classes[f[20]] ?? String(format: "CC 0x%02X", f[20])) \(pidNames[pid] ?? "PID")"
            + String(format: " (0x%04X)", pid) + "\(type) PDL \(f[23])" + (pd.isEmpty ? "" : " \(pd)")
            + (valid(f) ? "" : " [bad frame]")
    }
}

private func be(_ v: UInt16) -> [UInt8] { [UInt8(v >> 8), UInt8(v & 0xFF)] }
private func be(_ v: UInt32) -> [UInt8] { [UInt8(v >> 24), UInt8(v >> 16 & 0xFF), UInt8(v >> 8 & 0xFF), UInt8(v & 0xFF)] }
