import Crypto

/// Data-plane key and address helpers shared by Sender, Node and Receiver.
public enum SigNetKeys {
    /// Ks (PF §7.3): HKDF-Expand(K0, "Sig-Net-Sender-v1", 32) = HMAC-SHA256(K0, info ‖ 0x01).
    public static func sender(k0: [UInt8]) -> SymmetricKey { ManagerKeys.expand(SymmetricKey(data: k0), "Sig-Net-Sender-v1") }

    /// <mult_u1…109> for a universe by default Multicast Folding (PF §9.2.3, Appendix A).
    public static func levelGroup(_ universe: UInt16) -> String { "239.254.0.\((Int(universe) - 1) % 109 + 1)" }
    /// <mult_time> (sync and timecode) and <mult_preview>, PF Appendix A.
    public static let timeGroup = "239.254.255.250", previewGroup = "239.254.255.249"
}
