import Combine
import CSignet
import Foundation
import SigNet

extension SecurityMode {
    var raw: UInt8 { UInt8((self == .secure ? SIGNET_MODE_SECURE : SIGNET_MODE_OPEN).rawValue) }
}

/// SigNet's settings and Manager engines, observable for SwiftUI.
final class SecuritySettings: SecurityConfig, ObservableObject {
    let objectWillChange = ObservableObjectPublisher()
    override func willChange() { objectWillChange.send() }
}

final class Manager: ManagerEngine, ObservableObject {
    let objectWillChange = ObservableObjectPublisher()
    override func willChange() { objectWillChange.send() }
    var securitySettings: SecuritySettings { settings as! SecuritySettings } // the app only makes Managers with these
}

extension SecuritySettings {
    /// The chosen NIC for signet configs' multicast_interface; nil = OS default.
    func interfaceAddress() throws -> signet_address_t? {
        guard !interface.isEmpty else { return nil }
        var a = signet_address_t()
        a.family = UInt8(SIGNET_AF_IPV4.rawValue)
        guard withUnsafeMutableBytes(of: &a.bytes, { inet_pton(AF_INET, interface, $0.baseAddress) }) == 1 else {
            throw InterfaceError(description: "Interface must be an IPv4 address")
        }
        return a
    }

    /// Calls `body` with the chosen NIC, nil = OS default. Only valid inside
    /// `body`; signet_device_create copies the address.
    func withInterface<R>(_ body: (UnsafePointer<signet_address_t>?) -> R) throws -> R {
        guard var a = try interfaceAddress() else { return body(nil) }
        return withUnsafePointer(to: &a, body)
    }
}

struct InterfaceError: Error, CustomStringConvertible { let description: String }

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
