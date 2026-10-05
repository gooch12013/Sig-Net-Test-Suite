import Crypto
import Foundation

/// Shared by every role: role keys (PF §7.3), the persisted Session-ID record (§8.3) and multicast groups (§9.2, Appendix A).
public enum SigNetKeys {
    /// Ks = HKDF-Expand(K0, "Sig-Net-Sender-v1", 32).
    public static func sender(k0: [UInt8]) -> SymmetricKey { ManagerKeys.expand(SymmetricKey(data: k0), "Sig-Net-Sender-v1") }
    /// Kc = HKDF-Expand(K0, "Sig-Net-Citizen-v1", 32).
    public static func citizen(k0: [UInt8]) -> SymmetricKey { ManagerKeys.expand(SymmetricKey(data: k0), "Sig-Net-Citizen-v1") }

    /// §8.3: load the Session ID bound to `tuid`, +1, persist, and only then use it. Throws when the record can't be
    /// saved or the ID would reach 0xFFFFFFFF (exhausted: rekey or new TUID). Stored in UserDefaults ("session.<TUID>"),
    /// like Identity's TUIDs, so it survives restarts wherever Foundation runs.
    public static func nextSession(_ tuid: [UInt8]) throws -> UInt32 {
        let key = "session.\(Identity.hex(tuid))", defaults = UserDefaults.standard
        let stored = UInt32(clamping: defaults.integer(forKey: key))
        guard stored < 0xFFFF_FFFE else { throw SigNetError("Session ID exhausted: rekey or use a new TUID") }
        defaults.set(Int(stored + 1), forKey: key)
        guard defaults.synchronize() else { throw SigNetError("Could not persist Session ID") }
        return stored + 1
    }

    /// §9.2.3 default Multicast Folding: universe 1, 110, 219… → 239.254.0.1.
    public static func levelGroup(_ universe: Int) -> String { "239.254.0.\((universe - 1) % 109 + 1)" }
    public static let timeGroup = "239.254.255.250", previewGroup = "239.254.255.249", nodeGroup = "239.254.255.253"
}
