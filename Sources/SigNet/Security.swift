// The passphrase rules below are ported from the Sig-Net SDK (sig-net-crypto.cpp, AnalysePassphrase):
//
// Copyright (c) 2026 Singularity (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

import Crypto
import Foundation

public enum SecurityMode: String, CaseIterable, Identifiable {
    case open = "Open", secure = "Secure"
    public var id: Self { self }
}

/// Security settings every device in the app is created with. Locked while
/// any device is running, because mode/scope/keys are fixed at creation.
/// The app's ObservableObject subclass turns `willChange()` into objectWillChange.
open class SecurityConfig {
    public var mode = SecurityMode.open { willSet { willChange() } }
    public var passphrase = "" { willSet { willChange() } }
    public var scope = "local" { willSet { willChange() } }
    /// IPv4 address of the NIC every device uses; empty = OS default.
    public var interface = "" { willSet { willChange() } }
    public private(set) var activeDevices = 0 { willSet { willChange() } }

    public init() {}

    /// Called before any property above changes.
    open func willChange() {}

    public var scopeOrDefault: String { scope.isEmpty ? "local" : scope }
    public var locked: Bool { activeDevices > 0 }

    public func deviceStarted() { activeDevices += 1 }
    public func deviceStopped() { activeDevices = max(0, activeDevices - 1) }

    /// PF §7.2.3 symbol class.
    public static let symbols = "!@#$%^&*()-_=+[]{}|;:',.<>?/"

    /// PF §7.2.3 requires feedback naming the failed rule. nil = valid.
    public var passphraseProblem: String? {
        let p = passphrase.utf8.map(Int.init)
        let symbols = Set(Self.symbols.utf8.map(Int.init))
        let classes = [(65...90).contains, (97...122).contains, (48...57).contains, symbols.contains]
            .filter { test in p.contains(where: test) }.count
        let identical = p.indices.dropLast(2).contains { p[$0] == p[$0 + 1] && p[$0] == p[$0 + 2] }
        let sequential = p.indices.dropLast(3).contains { i in
            [1, -1].contains { d in (1...3).allSatisfy { p[i + $0] == p[i] + d * $0 } }
        }
        let short = "Needs at least 10 characters (\(p.count) so far)"
        if p.isEmpty { return short }
        if identical { return "No more than 2 identical characters in a row" }
        if sequential { return "No more than 3 sequential characters in a row (abcd, 4321)" }
        if classes < 3 { return "Use 3 of: uppercase, lowercase, digit, symbol (\(Self.symbols))" }
        if p.count < 10 { return short }
        if p.count > 64 { return "At most 64 characters" }
        return nil
    }

    /// True when a device can be created with these settings.
    public var ready: Bool { mode == .open || passphraseProblem == nil }

    /// 32-byte K0 for Secure Mode, empty for Open Mode. Caller wipes it.
    /// PBKDF2-HMAC-SHA256, 100 000 iterations, salt "Sig-Net-K0-Salt-v1" (PF §7.2.3); one 32-byte block.
    public func rootKey() throws -> [UInt8] {
        guard mode == .secure else { return [] }
        guard !passphrase.isEmpty else { throw SigNetError("Key derivation failed: empty passphrase") }
        let keyed = HMAC<SHA256>(key: SymmetricKey(data: Array(passphrase.utf8)))
        func mac(_ m: [UInt8]) -> [UInt8] {
            var h = keyed // copy of the keyed state: skips re-keying on every round
            h.update(data: m)
            return Array(h.finalize())
        }
        var u = mac(Array("Sig-Net-K0-Salt-v1".utf8) + [0, 0, 0, 1])
        var k0 = u
        for _ in 1..<100_000 {
            u = mac(u)
            for i in 0..<32 { k0[i] ^= u[i] }
        }
        wipe(&u)
        return k0
    }
}

public struct SigNetError: Error, CustomStringConvertible {
    public let description: String
    public init(_ d: String) { description = d }
}

public func wipe(_ bytes: inout [UInt8]) {
    #if canImport(Darwin)
    _ = memset_s(&bytes, bytes.count, 0, bytes.count)
    #else
    // ponytail: plain store, the optimiser may drop it for a dying array; explicit_bzero / SecureZeroMemory if that matters.
    for i in bytes.indices { bytes[i] = 0 }
    #endif
}

public enum Identity {
    /// One persisted TUID per role ("sender-v2", "receiver", "device-v2", "manager-v2"),
    /// so each device keeps its identity and Secure-Mode session record across
    /// launches ("-v2": the C library's session records could not be carried over).
    /// 0x7FF0 is ESTA's prototyping manufacturer ID; the Device ID is in the dynamic (software) range.
    public static func tuid(_ role: String) -> [UInt8] {
        let key = "tuid.\(role)"
        let defaults = UserDefaults.standard
        if let saved = defaults.data(forKey: key), saved.count == 6 { return [UInt8](saved) }
        var id = (0..<4).map { _ in UInt8.random(in: 0...0xFF) } // SystemRandomNumberGenerator: the OS CSPRNG
        id[0] |= 0x80
        if id[0] == 0xFF && id[1] == 0xFF && id[2] == 0xFF { id[1] = 0 } // avoid reserved 0xFFFFFFF0+
        let tuid: [UInt8] = [0x7F, 0xF0] + id
        defaults.set(Data(tuid), forKey: key)
        return tuid
    }

    public static func tuple(_ t: [UInt8]) -> (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8) {
        (t[0], t[1], t[2], t[3], t[4], t[5])
    }

    public static func hex(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02X", $0) }.joined() }
}
