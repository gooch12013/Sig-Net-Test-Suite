/// PF §11.2.5 timecode value.
public enum Timecode {
    /// 5-byte value for absolute frame `n` since 00:00:00:00.
    /// Labels per second are the rate maximum + 1 (29.97 counts 0–29); drop-frame
    /// rates skip 2/4/8 labels at each minute not divisible by ten (SMPTE 12M).
    public static func value(frame n: Int, rate: UInt8) -> [UInt8] {
        let nominal = [24, 25, 30, 30, 48, 50, 60, 60, 100, 120, 120][Int(rate)]
        let drop = [0x02, 0x06, 0x09].contains(rate) ? nominal / 15 : 0
        let perTenMin = nominal * 600 - drop * 9
        var n = n % (drop > 0 ? perTenMin * 144 : nominal * 86400) // wrap at 24 h
        if drop > 0 {
            let tens = n / perTenMin, rem = n % perTenMin
            n += drop * 9 * tens + (rem > drop ? drop * ((rem - drop) / (nominal * 60 - drop)) : 0)
        }
        return [UInt8(n / (nominal * 3600)), UInt8(n / (nominal * 60) % 60), UInt8(n / nominal % 60), UInt8(n % nominal), rate]
    }

    /// Frame-counter check for --selftest.
    public static func selfTest() -> Bool {
        let cases: [(Int, UInt8, [UInt8])] = [
            (29, 0x03, [0, 0, 0, 29]), (30, 0x03, [0, 0, 1, 0]), (24 * 3600, 0x00, [1, 0, 0, 0]),
            (25 * 86400, 0x01, [0, 0, 0, 0]), // 24 h wrap
            (29, 0x02, [0, 0, 0, 29]), // fractional rate: frames 0–29
            (1799, 0x02, [0, 0, 59, 29]), (1800, 0x02, [0, 1, 0, 2]), // DF skips ;00 ;01
            (17982, 0x02, [0, 10, 0, 0]), // ...but not on the 10th minute
            (3600, 0x06, [0, 1, 0, 4]), (7200, 0x09, [0, 1, 0, 8]), (119, 0x0A, [0, 0, 0, 119]),
        ]
        return cases.allSatisfy { Array(value(frame: $0.0, rate: $0.1).prefix(4)) == $0.2 }
    }
}
