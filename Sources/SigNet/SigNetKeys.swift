import Crypto
import Foundation

/// Sig-Net key derivation and multicast addressing shared by Sender, Receiver and Node.
public enum SigNetKeys {
    /// Ks (PF §7.3): HKDF-Expand of K0 with "Sig-Net-Sender-v1".
    public static func sender(k0: [UInt8]) -> SymmetricKey { ManagerKeys.expand(SymmetricKey(data: k0), "Sig-Net-Sender-v1") }

    /// Default Multicast Folding (PF §9.2.3): 239.254.0.((u - 1) % 109 + 1).
    public static func levelGroup(_ universe: UInt16) -> String { "239.254.0.\((Int(universe) - 1) % 109 + 1)" }

    public static let timeGroup = "239.254.255.250", previewGroup = "239.254.255.249"
}
