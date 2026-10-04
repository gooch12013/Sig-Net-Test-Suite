import CSignet
import Foundation
import Security

enum SecurityMode: String, CaseIterable, Identifiable {
    case open = "Open", secure = "Secure"
    var id: Self { self }
    var raw: UInt8 { UInt8((self == .secure ? SIGNET_MODE_SECURE : SIGNET_MODE_OPEN).rawValue) }
}

/// Security settings every device in the app is created with. Locked while
/// any device is running, because mode/scope/keys are fixed at creation.
final class SecuritySettings: ObservableObject {
    @Published var mode: SecurityMode = .open
    @Published var passphrase = ""
    @Published var scope = "local"
    @Published private(set) var activeDevices = 0

    var scopeOrDefault: String { scope.isEmpty ? "local" : scope }
    var locked: Bool { activeDevices > 0 }

    func deviceStarted() { activeDevices += 1 }
    func deviceStopped() { activeDevices = max(0, activeDevices - 1) }

    /// PF §7.2.3 requires feedback naming the failed rule. nil = valid.
    var passphraseProblem: String? {
        var report = signet_passphrase_report_t()
        report.struct_size = MemoryLayout<signet_passphrase_report_t>.size
        _ = signet_passphrase_validate(passphrase, passphrase.utf8.count, &report)
        switch report.verdict {
        case SIGNET_PASSPHRASE_VALID: return nil
        case SIGNET_PASSPHRASE_TOO_SHORT: return "Needs at least 10 characters (\(report.length) so far)"
        case SIGNET_PASSPHRASE_TOO_LONG: return "At most 64 characters"
        case SIGNET_PASSPHRASE_INSUFFICIENT_CLASSES:
            return "Use 3 of: uppercase, lowercase, digit, symbol (\(String(cString: signet_passphrase_symbols())))"
        case SIGNET_PASSPHRASE_CONSECUTIVE_IDENTICAL: return "No more than 2 identical characters in a row"
        case SIGNET_PASSPHRASE_CONSECUTIVE_SEQUENTIAL: return "No more than 3 sequential characters in a row (abcd, 4321)"
        default: return "Invalid passphrase"
        }
    }

    /// True when a device can be created with these settings.
    var ready: Bool { mode == .open || passphraseProblem == nil }

    /// 32-byte K0 for Secure Mode, empty for Open Mode. Caller wipes it
    /// (signet_device_create also wipes the buffer it is handed).
    func rootKey() throws -> [UInt8] {
        guard mode == .secure else { return [] }
        var k0 = [UInt8](repeating: 0, count: 32)
        let err = signet_k0_from_passphrase(nil, passphrase, passphrase.utf8.count, &k0, k0.count)
        guard err == SIGNET_OK else { throw SignetError("Key derivation", err) }
        return k0
    }
}

struct SignetError: Error, CustomStringConvertible {
    let description: String
    init(_ what: String, _ err: signet_error_t) {
        let detail = signet_get_last_error_string().map { String(cString: $0) } ?? ""
        description = "\(what) failed (error \(err.rawValue))" + (detail.isEmpty ? "" : ": \(detail)")
    }
}

/// Throws unless `err` is SIGNET_OK.
func check(_ what: String, _ err: signet_error_t) throws {
    if err != SIGNET_OK { throw SignetError(what, err) }
}

func wipe(_ bytes: inout [UInt8]) {
    _ = memset_s(&bytes, bytes.count, 0, bytes.count)
}

enum Identity {
    /// One persisted TUID per role ("sender", "receiver", "device", "manager"),
    /// so each device keeps its identity and Secure-Mode session record across
    /// launches. 0x7FF0 is ESTA's prototyping manufacturer ID; the Device ID is
    /// in the dynamic (software) range.
    static func tuid(_ role: String) -> [UInt8] {
        let key = "tuid.\(role)"
        let defaults = UserDefaults.standard
        if let saved = defaults.data(forKey: key), saved.count == 6 { return [UInt8](saved) }
        var id = [UInt8](repeating: 0, count: 4)
        _ = SecRandomCopyBytes(kSecRandomDefault, id.count, &id)
        id[0] |= 0x80
        if id[0] == 0xFF && id[1] == 0xFF && id[2] == 0xFF { id[1] = 0 } // avoid reserved 0xFFFFFFF0+
        let tuid: [UInt8] = [0x7F, 0xF0] + id
        defaults.set(Data(tuid), forKey: key)
        return tuid
    }

    static func tuple(_ t: [UInt8]) -> (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8) {
        (t[0], t[1], t[2], t[3], t[4], t[5])
    }

    static func hex(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02X", $0) }.joined() }
}

// MARK: - File-backed persistence

/// ~/Library/Application Support/SignetTestSuite/state/<tuid>-<key>.bin.
/// One provider serves every device: records are namespaced by TUID.
private let stateDir: URL = {
    let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("SignetTestSuite/state")
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir
}()

private func stateURL(_ tuid: UnsafePointer<UInt8>?, _ key: UInt32) -> URL {
    let hex = (0..<6).map { String(format: "%02x", tuid![$0]) }.joined()
    return stateDir.appendingPathComponent("\(hex)-\(key).bin")
}

let filePersistence: signet_persistence_provider_t = {
    var p = signet_persistence_provider_t()
    p.struct_size = MemoryLayout<signet_persistence_provider_t>.size
    p.load = { _, tuid, key, buf, cap, outLen in
        guard let data = try? Data(contentsOf: stateURL(tuid, key)) else { return SIGNET_ERR_STATE }
        guard data.count <= cap, let buf else { return SIGNET_ERR_BUFFER_TOO_SMALL }
        data.copyBytes(to: buf, count: data.count)
        outLen?.pointee = data.count
        return SIGNET_OK
    }
    p.store = { _, tuid, key, bytes, len in
        let data = bytes.map { Data(bytes: $0, count: len) } ?? Data()
        // .atomic writes a temp file then renames: a torn record would brick the session.
        do { try data.write(to: stateURL(tuid, key), options: .atomic) } catch { return SIGNET_ERR_PROVIDER_FAILURE }
        return SIGNET_OK
    }
    return p
}()
