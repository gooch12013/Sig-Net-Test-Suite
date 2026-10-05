import Foundation

/// What the app knows about one RDM parameter: a plain name, whether it can be read and set,
/// and how its parameter data is shown and typed. From ANSI E1.20-2025 Table A-3 and E1.37-1 Table A-1;
/// manufacturer-specific PIDs are described by the fixture itself (PARAMETER_DESCRIPTION).
public struct RDMSpec {
    public enum Kind {
        case text(Int)                          // UTF-8, max bytes
        case bool(String, String)               // off / on wording
        case number(bytes: Int, signed: Bool, unit: String, exponent: Int, range: ClosedRange<Int64>?)
        case enumeration([UInt8: String])
        case selector(description: UInt16)      // GET: current, count; names from the description PID
        case fields([(String, Int)])            // fixed-size unsigned fields, typed as "a, b, c"
        case blockAddress                       // GET footprint + base address; SET base address
        case selfTest                           // GET running flag; SET test number
        case clock
        case productDetails
        case languages
        case raw
    }

    public let name: String
    public let get: Bool
    public let set: Bool
    public let kind: Kind
    public init(name: String, get: Bool, set: Bool, kind: Kind) { self.name = name; self.get = get; self.set = set; self.kind = kind }
}

public enum RDMCatalog {
    static func number(_ bytes: Int, _ unit: String = "", range: ClosedRange<Int64>? = nil) -> RDMSpec.Kind {
        .number(bytes: bytes, signed: false, unit: unit, exponent: 0, range: range)
    }

    public static let standard: [UInt16: RDMSpec] = [
        0x0070: .init(name: "Product type", get: true, set: false, kind: .productDetails),
        0x0080: .init(name: "Model", get: true, set: false, kind: .text(32)),
        0x0081: .init(name: "Manufacturer", get: true, set: false, kind: .text(32)),
        0x0082: .init(name: "Label", get: true, set: true, kind: .text(32)),
        // SET restores factory defaults: kept in Debug.
        0x0090: .init(name: "At factory defaults", get: true, set: false, kind: .bool("No", "Yes")),
        0x00A0: .init(name: "Languages available", get: true, set: false, kind: .languages),
        0x00B0: .init(name: "Language", get: true, set: true, kind: .text(2)),
        0x00C0: .init(name: "Software", get: true, set: false, kind: .text(32)),
        0x00C1: .init(name: "Boot software ID", get: true, set: false, kind: number(4)),
        0x00C2: .init(name: "Boot software", get: true, set: false, kind: .text(32)),
        0x00E0: .init(name: "Personality", get: true, set: true, kind: .selector(description: 0x00E1)),
        0x00F0: .init(name: "DMX start address", get: true, set: true, kind: number(2, range: 1...512)),
        0x0400: .init(name: "Device hours", get: true, set: true, kind: number(4, "h")),
        0x0401: .init(name: "Lamp hours", get: true, set: true, kind: number(4, "h")),
        0x0402: .init(name: "Lamp strikes", get: true, set: true, kind: number(4)),
        0x0403: .init(name: "Lamp state", get: true, set: true, kind: .enumeration([0: "Off", 1: "On", 2: "Striking", 3: "Standby", 4: "Not present", 0x7F: "Error"])),
        0x0404: .init(name: "Lamp on mode", get: true, set: true, kind: .enumeration([0: "Off", 1: "On with DMX", 2: "On", 3: "After calibration"])),
        0x0405: .init(name: "Power cycles", get: true, set: true, kind: number(4)),
        0x0500: .init(name: "Display invert", get: true, set: true, kind: .enumeration([0: "Off", 1: "On", 2: "Auto"])),
        0x0501: .init(name: "Display level", get: true, set: true, kind: number(1, range: 0...255)),
        0x0600: .init(name: "Pan invert", get: true, set: true, kind: .bool("Off", "On")),
        0x0601: .init(name: "Tilt invert", get: true, set: true, kind: .bool("Off", "On")),
        0x0602: .init(name: "Pan/tilt swap", get: true, set: true, kind: .bool("Off", "On")),
        0x0603: .init(name: "Clock", get: true, set: true, kind: .clock),
        0x1000: .init(name: "Identify", get: true, set: true, kind: .bool("Off", "On")),
        0x1010: .init(name: "Power state", get: true, set: true, kind: .enumeration([0: "Full off", 1: "Shutdown", 2: "Standby", 0xFF: "Normal"])),
        0x1020: .init(name: "Self test", get: true, set: true, kind: .selfTest),
        0x1031: .init(name: "Preset playback", get: true, set: true, kind: .fields([("Mode", 2), ("Level", 1)])),
        // E1.37-1
        0x0140: .init(name: "DMX block address", get: true, set: true, kind: .blockAddress),
        0x0141: .init(name: "DMX fail mode", get: true, set: true, kind: .fields([("Scene", 2), ("Loss delay", 2), ("Hold time", 2), ("Level", 1)])),
        0x0142: .init(name: "DMX startup mode", get: true, set: true, kind: .fields([("Scene", 2), ("Startup delay", 2), ("Hold time", 2), ("Level", 1)])),
        0x0340: .init(name: "Dimmer info", get: true, set: false, kind: .fields([("Min level low", 2), ("Min level high", 2), ("Max level low", 2),
                                                                                  ("Max level high", 2), ("Curves", 1), ("Resolution bits", 1), ("Split levels", 1)])),
        0x0341: .init(name: "Minimum level", get: true, set: true, kind: .fields([("Increasing", 2), ("Decreasing", 2), ("On below minimum", 1)])),
        0x0342: .init(name: "Maximum level", get: true, set: true, kind: number(2)),
        0x0343: .init(name: "Dimmer curve", get: true, set: true, kind: .selector(description: 0x0344)),
        0x0345: .init(name: "Output response time", get: true, set: true, kind: .selector(description: 0x0346)),
        0x0347: .init(name: "Modulation frequency", get: true, set: true, kind: .selector(description: 0x0348)),
        0x0440: .init(name: "Burn-in", get: true, set: true, kind: number(1, "h")),
        // SET needs the current PIN: kept in Debug.
        0x0640: .init(name: "Lock PIN", get: true, set: false, kind: number(2)),
        0x0641: .init(name: "Lock state", get: true, set: false, kind: .selector(description: 0x0642)),
        0x1040: .init(name: "Identify mode", get: true, set: true, kind: .enumeration([0: "Quiet", 0xFF: "Loud"])),
        0x1041: .init(name: "Preset info", get: true, set: false, kind: .raw),
        0x1043: .init(name: "Preset merge mode", get: true, set: true, kind: .enumeration([0: "Default", 1: "HTP", 2: "LTP", 3: "DMX only", 0xFF: "Other"])),
        0x1044: .init(name: "Power-on self test", get: true, set: true, kind: .bool("Off", "On")),
        // E1.37-5
        0x00D0: .init(name: "Manufacturer web page", get: true, set: false, kind: .text(231)),
        0x00D1: .init(name: "Product web page", get: true, set: false, kind: .text(231)),
        0x00D2: .init(name: "Firmware web page", get: true, set: false, kind: .text(231)),
        0x00D3: .init(name: "Serial number", get: true, set: false, kind: .text(231)),
        0x0650: .init(name: "Shipping lock", get: true, set: true, kind: .enumeration([0: "Unlocked", 1: "Locked", 2: "Partially locked"])),
        0x0656: .init(name: "Unit number", get: true, set: true, kind: number(4)),
        0x1050: .init(name: "Identify timeout", get: true, set: true, kind: number(2, "s")),
        0x1051: .init(name: "Ready to power off", get: true, set: false, kind: .bool("No", "Yes")),
    ]

    /// PIDs the panel handles itself (structure, descriptions, sensors, channels) or keeps out of the main panel.
    public static let notListed: Set<UInt16> = [
        0x0010, 0x0011, 0x0015, 0x0020, 0x0030, 0x0031, 0x0032, 0x0033, 0x0034,
        0x0050, 0x0051, 0x0055, 0x0056, 0x0058, 0x0059, 0x005A, 0x0060,
        0x00E1, 0x0344, 0x0346, 0x0348, 0x0642, 0x1021, 0x1022,
        0x0120, 0x0121, 0x0122, 0x0200, 0x0201, 0x0202,
        0x1200, 0x1201, 0x1202, 0x1203, 0x1204, 0x1205, // file transfer (E1.37-4): the Firmware update module
        0x1001, 0x1030, 0x1042, // reset, capture preset, preset status (needs a scene number): Debug only
    ]

    /// Offset of the text in each description PID's answer.
    public static let descriptionTextOffset: [UInt16: Int] = [0x00E1: 3, 0x0344: 1, 0x0346: 1, 0x0348: 5, 0x0642: 1, 0x1021: 1]

    static let productDetails: [UInt16: String] = [
        0x0001: "Arc lamp", 0x0002: "Metal halide", 0x0003: "Incandescent", 0x0004: "LED", 0x0005: "Fluorescent",
        0x0006: "Cold cathode", 0x0007: "Electroluminescent", 0x0008: "Laser", 0x0009: "Flash tube",
        0x0100: "Colour scroller", 0x0101: "Colour wheel", 0x0102: "Colour change", 0x0103: "Iris/douser",
        0x0104: "Dimming shutter", 0x0105: "Profile shutter", 0x0106: "Barndoor shutter", 0x0107: "Effects disc", 0x0108: "Gobo rotator",
        0x0200: "Video", 0x0201: "Slide", 0x0202: "Film", 0x0203: "Oil wheel", 0x0204: "LCD gate",
        0x0300: "Glycol hazer", 0x0301: "Mineral oil hazer", 0x0302: "Water hazer", 0x0305: "Bubble", 0x0309: "Snow",
        0x0400: "Phase control", 0x0401: "Reverse phase control", 0x0402: "Sine", 0x0403: "PWM", 0x0404: "DC",
        0x0600: "Splitter", 0x0601: "Ethernet node", 0x0602: "Merger", 0x0604: "Wireless link",
        0x0902: "Test equipment", 0x0A01: "Battery powered", 0x7FFF: "Other",
    ]

    public static let units: [UInt8: String] = [
        0x01: "°C", 0x02: "V DC", 0x03: "V AC peak", 0x04: "V AC", 0x05: "A DC", 0x06: "A AC peak", 0x07: "A AC", 0x08: "Hz",
        0x09: "Ω", 0x0A: "W", 0x0B: "kg", 0x0C: "m", 0x0D: "m²", 0x0E: "m³", 0x0F: "kg/m³", 0x10: "m/s", 0x11: "m/s²",
        0x12: "N", 0x13: "J", 0x14: "Pa", 0x15: "s", 0x16: "°", 0x17: "sr", 0x18: "cd", 0x19: "lm", 0x1A: "lx", 0x1B: "IRE",
        0x1C: "B", 0x1D: "dB", 0x1E: "dBV", 0x1F: "dBW", 0x20: "dBm", 0x21: "%", 0x22: "mol/m³", 0x23: "rpm", 0x24: "B/s",
    ]

    public static let prefixExponent: [UInt8: Int] = [
        0x01: -1, 0x02: -2, 0x03: -3, 0x04: -6, 0x05: -9, 0x06: -12, 0x07: -15, 0x08: -18, 0x09: -21, 0x0A: -24,
        0x11: 1, 0x12: 2, 0x13: 3, 0x14: 6, 0x15: 9, 0x16: 12, 0x17: 15, 0x18: 18, 0x19: 21, 0x1A: 24,
    ]

    public static let sensorTypes: [UInt8: String] = [
        0x00: "Temperature", 0x01: "Voltage", 0x02: "Current", 0x03: "Frequency", 0x04: "Resistance", 0x05: "Power",
        0x06: "Mass", 0x07: "Length", 0x08: "Area", 0x09: "Volume", 0x0A: "Density", 0x0B: "Velocity", 0x0C: "Acceleration",
        0x0D: "Force", 0x0E: "Energy", 0x0F: "Pressure", 0x10: "Time", 0x11: "Angle", 0x12: "Position X", 0x13: "Position Y",
        0x14: "Position Z", 0x15: "Angular velocity", 0x16: "Luminous intensity", 0x17: "Luminous flux", 0x18: "Illuminance",
        0x19: "Red", 0x1A: "Green", 0x1B: "Blue", 0x1C: "Contacts", 0x1D: "Memory", 0x1E: "Items", 0x1F: "Humidity",
        0x20: "Counter", 0x21: "CPU load", 0x22: "Bandwidth", 0x23: "Concentration", 0x24: "Sound level", 0x7F: "Sensor",
    ]

    /// A manufacturer-specific PID described by the fixture (PARAMETER_DESCRIPTION, E1.20 §10.4.2).
    public static func described(_ pd: [UInt8]) -> (pid: UInt16, spec: RDMSpec)? {
        guard pd.count >= 20 else { return nil }
        let pid = mgrU16(pd), size = Int(pd[2]), type = pd[3], cc = pd[4]
        let unit = units[pd[6]] ?? "", exponent = prefixExponent[pd[7]] ?? 0
        let lo = Int64(Int32(bitPattern: mgrU32(pd[8...]))), hi = Int64(Int32(bitPattern: mgrU32(pd[12...])))
        let range: ClosedRange<Int64>? = lo <= hi && !(lo == 0 && hi == 0) ? lo...hi : nil
        let name = String(decoding: pd.dropFirst(20).prefix { $0 != 0 }, as: UTF8.self)
        let kind: RDMSpec.Kind
        switch type {
        case 0x02: kind = .text(max(1, size))
        case 0x03, 0x04: kind = .number(bytes: 1, signed: type == 0x04, unit: unit, exponent: exponent, range: range)
        case 0x05, 0x06: kind = .number(bytes: 2, signed: type == 0x06, unit: unit, exponent: exponent, range: range)
        case 0x07, 0x08: kind = .number(bytes: 4, signed: type == 0x08, unit: unit, exponent: exponent, range: range)
        default: kind = .raw
        }
        return (pid, RDMSpec(name: name.isEmpty ? String(format: "Parameter %04X", pid) : name, get: cc & 1 != 0, set: cc & 2 != 0, kind: kind))
    }

    // MARK: - Showing and typing values

    static func signedValue(_ pd: [UInt8], bytes: Int, signed: Bool) -> Int64? {
        guard pd.count >= bytes else { return nil }
        let raw = pd.prefix(bytes).reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
        guard signed else { return Int64(raw) }
        let shift = UInt64(64 - bytes * 8)
        return Int64(bitPattern: raw << shift) >> Int64(shift)
    }

    public static func scaled(_ v: Int64, exponent: Int, unit: String) -> String {
        let text = exponent == 0 ? "\(v)" : String(format: "%g", Double(v) * pow(10, Double(exponent)))
        return unit.isEmpty ? text : "\(text) \(unit)"
    }

    /// Readable value; `names` are the selector's item names when known.
    public static func show(_ spec: RDMSpec, _ pd: [UInt8], names: [UInt8: String] = [:]) -> String {
        switch spec.kind {
        case .text: let s = String(decoding: pd.prefix { $0 != 0 }, as: UTF8.self); return s.isEmpty ? "(empty)" : s
        case .bool(let off, let on): return pd.first.map { $0 == 0 ? off : on } ?? "—"
        case .number(let bytes, let signed, let unit, let exponent, _):
            return signedValue(pd, bytes: bytes, signed: signed).map { scaled($0, exponent: exponent, unit: unit) } ?? mgrHex(pd)
        case .enumeration(let map): return pd.first.map { map[$0] ?? "Value \($0)" } ?? "—"
        case .selector:
            guard pd.count >= 2 else { return mgrHex(pd) }
            return "\(pd[0]) of \(pd[1])" + (names[pd[0]].map { $0.isEmpty ? "" : " · \($0)" } ?? "")
        case .fields(let fields):
            var at = 0
            return fields.compactMap { name, size -> String? in
                defer { at += size }
                guard pd.count >= at + size else { return nil }
                return "\(name) \(pd[at..<at + size].reduce(0) { $0 << 8 | Int($1) })"
            }.joined(separator: " · ")
        case .blockAddress: return pd.count >= 4 ? "Base \(mgrU16(pd[2...])) · footprint \(mgrU16(pd))" : mgrHex(pd)
        case .selfTest: return pd.first.map { $0 == 0 ? "Not running" : "Running" } ?? "—"
        case .clock:
            guard pd.count >= 7 else { return mgrHex(pd) }
            return String(format: "%04d-%02d-%02d %02d:%02d:%02d", mgrU16(pd), pd[2], pd[3], pd[4], pd[5], pd[6])
        case .productDetails:
            let list = stride(from: 0, to: pd.count - 1, by: 2).map { mgrU16(pd[$0...]) }.filter { $0 != 0 }
            return list.isEmpty ? "Not declared" : list.map { productDetails[$0] ?? String(format: "Type %04X", $0) }.joined(separator: " · ")
        case .languages:
            return stride(from: 0, to: pd.count - 1, by: 2).map { String(decoding: pd[$0..<$0 + 2], as: UTF8.self) }.joined(separator: ", ")
        case .raw: return pd.isEmpty ? "(no data)" : mgrHex(pd)
        }
    }

    /// Text the SET field opens with.
    public static func draft(_ spec: RDMSpec, _ pd: [UInt8]?) -> String {
        guard let pd else { return "" }
        switch spec.kind {
        case .text: return String(decoding: pd.prefix { $0 != 0 }, as: UTF8.self)
        case .number(let bytes, let signed, _, _, _): return signedValue(pd, bytes: bytes, signed: signed).map(String.init) ?? ""
        case .fields(let fields):
            var at = 0
            return fields.compactMap { _, size -> String? in
                defer { at += size }
                return pd.count >= at + size ? "\(pd[at..<at + size].reduce(0) { $0 << 8 | Int($1) })" : nil
            }.joined(separator: ", ")
        case .blockAddress: return pd.count >= 4 ? "\(mgrU16(pd[2...]))" : ""
        default: return mgrHex(pd)
        }
    }

    /// Prompt shown in an empty SET field.
    static func hint(_ spec: RDMSpec) -> String {
        switch spec.kind {
        case .text(let n): return "up to \(n) characters"
        case .number(_, _, let unit, _, let range):
            return (range.map { "\($0.lowerBound)–\($0.upperBound)" } ?? "a number") + (unit.isEmpty ? "" : " (\(unit))")
        case .fields(let f): return f.map(\.0).joined(separator: ", ")
        case .blockAddress: return "base address 1–512"
        case .selfTest: return "test number"
        case .clock: return "year, month, day, hour, minute, second"
        default: return "hex bytes"
        }
    }

    /// Parameter data for a typed value, or a reason it can't be sent.
    public static func encode(_ spec: RDMSpec, _ text: String) -> Result<[UInt8], ValueError> {
        func numbers() -> [Int64]? {
            let parts = text.split(whereSeparator: { $0 == "," || $0 == " " }).map(String.init)
            let values = parts.map { $0.hasPrefix("0x") ? Int64($0.dropFirst(2), radix: 16) : Int64($0) }
            return values.contains(nil) || values.isEmpty ? nil : values.map { $0! }
        }
        func be(_ v: Int64, _ bytes: Int) -> [UInt8] { (0..<bytes).reversed().map { UInt8(truncatingIfNeeded: v >> ($0 * 8)) } }
        switch spec.kind {
        case .text(let n):
            let b = Array(text.utf8)
            return b.count <= n ? .success(b) : .failure(.init("At most \(n) characters"))
        case .number(let bytes, let signed, _, _, let range):
            guard let v = numbers()?.first else { return .failure(.init("Type a number")) }
            let limit = signed ? -(Int64(1) << (bytes * 8 - 1))...((Int64(1) << (bytes * 8 - 1)) - 1) : 0...((Int64(1) << (bytes * 8)) - 1)
            guard (range ?? limit).contains(v) else { return .failure(.init("Use \((range ?? limit).lowerBound)–\((range ?? limit).upperBound)")) }
            return .success(be(v, bytes))
        case .fields(let fields):
            guard let v = numbers(), v.count == fields.count else { return .failure(.init("Type \(fields.count) numbers: \(fields.map(\.0).joined(separator: ", "))")) }
            return .success(zip(v, fields).flatMap { be($0, $1.1) })
        case .blockAddress:
            guard let v = numbers()?.first, (1...512).contains(v) else { return .failure(.init("Use a base address 1–512")) }
            return .success(be(v, 2))
        case .selfTest:
            guard let v = numbers()?.first, (0...255).contains(v) else { return .failure(.init("Type a test number 0–255")) }
            return .success([UInt8(v)])
        case .clock:
            guard let v = numbers(), v.count == 6 else { return .failure(.init("Type year, month, day, hour, minute, second")) }
            return .success(be(v[0], 2) + v.dropFirst().map { UInt8(clamping: $0) })
        default:
            return mgrBytes(hex: text).map { .success($0) } ?? .failure(.init("Type hex bytes"))
        }
    }

    public struct ValueError: Error { public let message: String; init(_ m: String) { message = m } }
}
