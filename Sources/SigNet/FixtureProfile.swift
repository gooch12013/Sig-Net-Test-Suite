import Foundation

/// A fixture's DMX personalities, channels and named value ranges, read from a profile JSON that follows
/// docs/fixture.schema.json v0.0.1. `load` applies the schema (unknown fields, types, limits) and the three rules a
/// schema can't express: footprint equals the channel count, `ch` runs 1…n, each channel's ranges cover 0–255 with no gaps.
public struct FixtureProfile: Codable, Equatable {
    public struct Range: Codable, Hashable {
        public var from: UInt8
        public var to: UInt8
        public var name: String
    }
    public struct Channel: Codable, Equatable {
        public var ch: Int
        public var name: String
        public var note: String?
        public var ranges: [Range]
    }
    public struct Personality: Codable, Equatable {
        public var personality: Int
        public var name: String
        public var footprint: Int
        public var channels: [Channel]
    }
    public var manufacturer: String
    public var model: String
    public var personalities: [Personality]

    public struct Invalid: Error, CustomStringConvertible {
        public let description: String
    }

    public func personality(_ n: Int) -> Personality? { personalities.first { $0.personality == n } }

    public static func load(_ data: Data) throws -> FixtureProfile {
        guard let json = try? JSONSerialization.jsonObject(with: data) else { throw Invalid(description: "The file isn't JSON") }
        if let extra = unknownFields(json).first { throw Invalid(description: "Unknown field \(extra)") }
        let p: FixtureProfile
        do { p = try JSONDecoder().decode(FixtureProfile.self, from: data) } catch let e as DecodingError {
            throw Invalid(description: describe(e))
        }
        if let problem = p.problems.first { throw Invalid(description: problem) }
        return p
    }

    /// The schema's additionalProperties: false, at each of the four levels.
    static func unknownFields(_ json: Any) -> [String] {
        let allowed: [Set<String>] = [["manufacturer", "model", "personalities"], ["personality", "name", "footprint", "channels"],
                                      ["ch", "name", "note", "ranges"], ["from", "to", "name"]]
        let child = ["personalities", "channels", "ranges"]
        var out: [String] = []
        func walk(_ o: Any, _ depth: Int, _ path: String) {
            guard let d = o as? [String: Any] else { return }
            out += d.keys.filter { !allowed[depth].contains($0) }.sorted().map { "\(path).\($0)" }
            guard depth < child.count, let list = d[child[depth]] as? [Any] else { return }
            for (i, x) in list.enumerated() { walk(x, depth + 1, "\(path).\(child[depth])[\(i)]") }
        }
        walk(json, 0, "$")
        return out
    }

    /// The schema's limits Codable doesn't check, then the three cross-field rules.
    var problems: [String] {
        var out: [String] = []
        if manufacturer.isEmpty || model.isEmpty { out.append("manufacturer and model can't be empty") }
        if personalities.isEmpty { out.append("no personalities") }
        for p in personalities {
            let at = "personality \(p.personality) (\(p.name))"
            if p.personality < 1 || p.name.isEmpty { out.append("\(at): number must be 1 or more and the name can't be empty") }
            if !(1...512).contains(p.footprint) { out.append("\(at): footprint \(p.footprint) is outside 1–512") }
            if p.footprint != p.channels.count { out.append("\(at): footprint \(p.footprint) but \(p.channels.count) channels") }
            let nums = p.channels.map(\.ch)
            if nums.isEmpty || nums != Array(1...nums.count) { out.append("\(at): ch numbers \(nums), expected 1…\(p.channels.count)") }
            for c in p.channels {
                let cw = "\(at) ch \(c.ch)"
                if c.name.isEmpty { out.append("\(cw): no name") }
                guard let first = c.ranges.first, let last = c.ranges.last else { out.append("\(cw): no ranges"); continue }
                if first.from != 0 { out.append("\(cw): first range starts at \(first.from), not 0") }
                if last.to != 255 { out.append("\(cw): last range ends at \(last.to), not 255") }
                for r in c.ranges where r.from > r.to || r.name.isEmpty { out.append("\(cw): range \(r.from)–\(r.to) \"\(r.name)\" is backwards or unnamed") }
                for (a, b) in zip(c.ranges, c.ranges.dropFirst()) where Int(b.from) != Int(a.to) + 1 {
                    out.append("\(cw): \"\(a.name)\" ends at \(a.to), \"\(b.name)\" starts at \(b.from)")
                }
            }
        }
        return out
    }

    private static func describe(_ e: DecodingError) -> String {
        func path(_ c: DecodingError.Context) -> String {
            "$" + c.codingPath.map { $0.intValue.map { "[\($0)]" } ?? ".\($0.stringValue)" }.joined()
        }
        switch e {
        case .keyNotFound(let k, let c): return "\(path(c)).\(k.stringValue) is missing"
        case .typeMismatch(_, let c), .valueNotFound(_, let c): return "\(path(c)) has the wrong type"
        case .dataCorrupted(let c): return "\(path(c)): \(c.debugDescription)"
        @unknown default: return "\(e)"
        }
    }

    /// nil when a good profile loads and each kind of bad one is refused.
    static func selfTest() -> String? {
        let good = #"{"manufacturer":"M","model":"X","personalities":[{"personality":1,"name":"2CH","footprint":2,"channels":["#
            + #"{"ch":1,"name":"Dim","ranges":[{"from":0,"to":255,"name":"0-100%"}]},"#
            + #"{"ch":2,"name":"Strobe","note":"n","ranges":[{"from":0,"to":9,"name":"Off"},{"from":10,"to":255,"name":"Slow-fast"}]}]}]}"#
        guard let p = try? load(Data(good.utf8)), p.personality(1)?.channels[1].ranges.count == 2 else { return "good profile refused" }
        let bad = [
            good.replacingOccurrences(of: #""footprint":2"#, with: #""footprint":3"#),          // footprint ≠ channels
            good.replacingOccurrences(of: #""ch":2"#, with: #""ch":3"#),                          // ch gap
            good.replacingOccurrences(of: #""from":10"#, with: #""from":11"#),                    // range gap
            good.replacingOccurrences(of: #""to":255,"name":"Slow"#, with: #""to":254,"name":"Slow"#), // short of 255
            good.replacingOccurrences(of: #""to":9"#, with: #""to":300"#),                        // not a DMX value
            good.replacingOccurrences(of: #""note":"n""#, with: #""notes":"n""#),                 // unknown field
            good.replacingOccurrences(of: #""model":"X","#, with: ""),                            // missing field
        ]
        for (i, b) in bad.enumerated() where (try? load(Data(b.utf8))) != nil { return "bad profile \(i + 1) accepted" }
        return nil
    }
}
