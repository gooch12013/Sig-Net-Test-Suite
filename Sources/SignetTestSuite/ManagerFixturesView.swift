import AppKit
import SigNet
import SwiftUI
import UniformTypeIdentifiers

/// Everything learned about each RDM fixture, kept across tab switches.
final class FixtureStore: ObservableObject {
    struct Sensor { var name: String; var unit: String; var exponent: Int; var value: [UInt8]? }

    struct Fixture {
        var info: [UInt8]?                              // DEVICE_INFO parameter data
        var supported: [UInt16]?                        // SUPPORTED_PARAMETERS
        var values: [UInt16: [UInt8]] = [:]             // last parameter data per PID
        var described: [UInt16: RDMSpec] = [:]          // manufacturer PIDs, from PARAMETER_DESCRIPTION
        var names: [UInt16: [UInt8: String]] = [:]      // selector PID → item → name
        var sensors: [UInt8: Sensor] = [:]
        var channels: [UInt16: String] = [:]            // channel offset → description
        var progress = ""
        var universe: UInt16?                           // universe of the port it was read through
        var profile: FixtureProfile?                    // personalities and value ranges, from the fixture (FTC) or a file
        var profileNote = ""                            // where the profile came from, or why there isn't one

        /// DMX start address: the last DMX_START_ADDRESS answer, else DEVICE_INFO's.
        var startAddress: Int? {
            values[0x00F0].flatMap { $0.count >= 2 ? Int(mgrU16($0)) : nil } ?? info.flatMap { $0.count >= 16 ? Int(mgrU16($0[14...])) : nil }
        }

        var label: String? { values[0x0082].map { String(decoding: $0, as: UTF8.self) } }
        var sensorCount: Int { info.map { $0.count >= 19 ? Int($0[18]) : 0 } ?? 0 }
        var footprint: Int? { info.flatMap { $0.count >= 12 ? Int(mgrU16($0[10...])) : nil } }
        var software: String? { values[0x00C0].map { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) } }

        /// Personality in use: the last PERSONALITY answer, else DEVICE_INFO's.
        var personality: Int? { values[0x00E0]?.first.map(Int.init) ?? info.flatMap { $0.count >= 13 ? Int($0[12]) : nil } }
        var activeProfile: FixtureProfile.Personality? { personality.flatMap { profile?.personality($0) } }
    }
    @Published var byUID: [String: Fixture] = [:]

    /// The channels each fixture on `universe` occupies, and what to call it.
    struct Span: Hashable { let start: Int; let end: Int; let name: String }

    func spans(universe: Int) -> [Span] {
        byUID.values.filter { $0.universe.map(Int.init) == universe }.compactMap { f in
            guard let start = f.startAddress, start > 0 else { return nil }
            let count = max(f.channels.keys.max().map { Int($0) + 1 } ?? 0, f.footprint ?? 0)
            guard count > 0 else { return nil }
            let model = f.values[0x0080].map { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
            let name = [f.label, model].compactMap { $0 }.first { !$0.isEmpty } ?? "Fixture"
            return Span(start: start, end: min(512, start + count - 1), name: name)
        }
        .sorted { $0.start < $1.start }
    }

    /// DMX channel (1–512) → what it does, from every fixture read on `universe`.
    func channelNames(universe: Int) -> [Int: String] {
        var out: [Int: String] = [:]
        for f in byUID.values where f.universe.map(Int.init) == universe {
            guard let start = f.startAddress, start > 0 else { continue }
            var named = f.channels
            for c in f.activeProfile?.channels ?? [] where named[UInt16(c.ch - 1)] == nil { named[UInt16(c.ch - 1)] = c.name }
            for (slot, name) in named {
                let ch = start + Int(slot)
                guard (1...512).contains(ch) else { continue }
                out[ch] = out[ch].map { "\($0) / \(name)" } ?? name
            }
        }
        return out
    }

    /// DMX channel (1–512) → the profile's channel, for every fixture on `universe` with a profile for its personality.
    func profileChannels(universe: Int) -> [Int: FixtureProfile.Channel] {
        var out: [Int: FixtureProfile.Channel] = [:]
        for f in byUID.values where f.universe.map(Int.init) == universe {
            guard let start = f.startAddress, start > 0, let p = f.activeProfile else { continue }
            for c in p.channels where (1...512).contains(start + c.ch - 1) { out[start + c.ch - 1] = c }
        }
        return out
    }
}

/// RDM: discover the fixtures behind a port, then read and change everything each one supports.
struct ManagerFixturesView: View {
    @ObservedObject var manager: Manager
    let device: ManagerDevice
    @ObservedObject var store: FixtureStore
    @State private var port: UInt16 = 1
    @State private var uid: String?
    @State private var note = ""

    /// Ports that can carry RDM; all ports when the device hasn't said.
    private var ports: [UInt16] {
        let n = device.root(0x0602).map(mgrU16) ?? 0
        let all = n == 0 ? [UInt16(1)] : Array(1...n)
        let rdm = all.filter { (device.params[$0]?[0x0904].map { mgrU32([UInt8](repeating: 0, count: max(0, 4 - $0.count)) + $0) & 0x0C != 0 }) ?? true }
        return rdm.isEmpty ? all : rdm
    }
    private var uids: [String] { (device.tod[port] ?? []).map(Identity.hex) }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                ModeKeys(options: ports.map { ($0, "Port \($0)") }, selection: $port)
                Button("Discover", action: discover).buttonStyle(.softKey).disabled(manager.busy || !manager.running)
                    .help("Clear the port's fixture list, run full RDM discovery, then read the list")
                Button("Reload list", action: loadList).buttonStyle(.softKey).disabled(manager.busy || !manager.running)
                Text(note).font(.system(size: 11.5)).foregroundStyle(Color.silk)
                Spacer()
            }
            HStack(alignment: .top, spacing: 12) {
                ModulePanel("Fixtures") {
                    Text("\(uids.count)").font(.system(size: 11, design: .monospaced)).foregroundStyle(Color.silk)
                } content: {
                    if uids.isEmpty {
                        Text("None listed. Press Discover.").font(.system(size: 12)).foregroundStyle(Color.silk)
                    }
                    ForEach(uids, id: \.self) { u in
                        Button { uid = u } label: { fixtureRow(u) }.buttonStyle(.plain)
                            .accessibilityAddTraits(u == uid ? .isSelected : [])
                    }
                }
                .frame(width: 220)
                if let uid {
                    ManagerFixturePanel(manager: manager, device: device, port: port, uid: uid, store: store)
                } else {
                    Spacer()
                }
            }
        }
        .onAppear {
            if !ports.contains(port) { port = ports.first ?? 1 }
            if uids.isEmpty, manager.running, !manager.busy { loadList() }
            if uid == nil { uid = uids.first }
        }
        .onChange(of: port) { _ in uid = nil; if uids.isEmpty { loadList() } else { uid = uids.first } }
        .onChange(of: uids) { list in if uid == nil || !list.contains(uid!) { uid = list.first } }
    }

    private func fixtureRow(_ u: String) -> some View {
        let f = store.byUID[u]
        return HStack(alignment: .top, spacing: 9) {
            Lamp(color: f?.values[0x1000]?.first.map { $0 != 0 ? Color.lampLatch : nil } ?? nil).padding(.top, 4)
            VStack(alignment: .leading, spacing: 2) {
                Text(f?.label.flatMap { $0.isEmpty ? nil : $0 } ?? "Fixture").font(.system(size: 13, weight: .semibold)).foregroundStyle(Color.ink)
                Text(ManagerRDM.uid(mgrBytes(hex: u) ?? [0, 0, 0, 0, 0, 0])).font(.system(size: 10.5, design: .monospaced)).foregroundStyle(Color.silk)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 10).padding(.vertical, 8)
        .background(RoundedRectangle(cornerRadius: 5, style: .continuous).fill(u == uid ? Color.readoutWindow : .clear)
            .overlay(RoundedRectangle(cornerRadius: 5, style: .continuous).strokeBorder(u == uid ? Color.lampLatch.opacity(0.7) : .clear, lineWidth: 1)))
        .contentShape(Rectangle())
    }

    private func loadList() {
        note = "Reading fixture list…"
        manager.requestToD(device.tuid, ep: port) { r in note = r.ok ? "" : "No fixture list from the device" }
    }

    /// The flush gets no reply, so give the device time to rediscover the line, then read the list.
    private func discover() {
        note = "Discovering…"
        manager.flushToD(device.tuid, ep: port)
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) { loadList() }
    }
}

/// One fixture: its main controls, every other parameter it supports, its sensors and its channels.
private struct ManagerFixturePanel: View {
    @ObservedObject var manager: Manager
    let device: ManagerDevice
    let port: UInt16
    let uid: String
    @ObservedObject var store: FixtureStore

    private static let core: [UInt16] = [0x0082, 0x00F0, 0x1000, 0x00E0]
    private static let details: [UInt16] = [0x0080, 0x0081, 0x0070, 0x00C0, 0x00C2, 0x00C1]

    private var f: FixtureStore.Fixture { store.byUID[uid] ?? .init() }
    private var enabled: Bool { manager.running && !manager.busy }

    /// Everything else the fixture says it supports, in PID order.
    private var others: [UInt16] {
        (f.supported ?? []).filter { !RDMCatalog.notListed.contains($0) && !Self.core.contains($0) && !Self.details.contains($0) }.sorted()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            ModulePanel(f.label.flatMap { $0.isEmpty ? nil : $0 } ?? "Fixture") {
                if !f.progress.isEmpty { Text(f.progress).font(.system(size: 11.5)).foregroundStyle(Color.silk) }
                Button("Read all", action: loadAll).buttonStyle(.softKey).disabled(!enabled)
            } content: {
                ForEach(Self.core, id: \.self) { row($0) }
            }
            ModulePanel("Settings and readings") {
                Text(f.supported == nil ? "" : "\(others.count) more").font(.system(size: 11, design: .monospaced)).foregroundStyle(Color.silk)
            } content: {
                if f.supported == nil {
                    Text("Press Read all to ask the fixture what it supports.").font(.system(size: 12)).foregroundStyle(Color.silk)
                } else if others.isEmpty {
                    Text("The fixture supports no other parameters.").font(.system(size: 12)).foregroundStyle(Color.silk)
                }
                ForEach(others, id: \.self) { row($0) }
            }
            if f.sensorCount > 0 {
                ModulePanel("Sensors") {
                    Text("\(f.sensorCount)").font(.system(size: 11, design: .monospaced)).foregroundStyle(Color.silk)
                } content: {
                    ForEach(0..<f.sensorCount, id: \.self) { i in sensorRow(UInt8(i)) }
                }
            }
            ModulePanel("Channels") {
                Button("Read channels") { loadChannels() }.buttonStyle(.softKey).disabled(!enabled)
            } content: {
                if f.channels.isEmpty {
                    Text(f.footprint.map { "\($0) channels. Press Read channels for what each one does." } ?? "Press Read channels for what each one does.")
                        .font(.system(size: 12)).foregroundStyle(Color.silk)
                }
                ForEach(f.channels.keys.sorted(), id: \.self) { slot in
                    ReadoutRow(label: "Channel \(Int(slot) + 1)", value: f.channels[slot])
                }
            }
            ModulePanel("Profile") {
                if f.supported?.contains(0x1200) == true {
                    Button("Read from fixture") { fetchProfile() }.buttonStyle(.softKey).disabled(!enabled || FirmwareUpdate.active)
                        .help("Download the fixture's JSON profile over RDM file transfer")
                }
                Button("Open file…", action: openProfile).buttonStyle(.softKey)
                    .help("Load a profile JSON from this Mac")
            } content: {
                ReadoutRow(label: "Software", value: f.software)
                ReadoutRow(label: "Profile", value: f.profile.map { "\($0.manufacturer) \($0.model) · \($0.personalities.count) personalities" })
                ReadoutRow(label: "Personality in use", value: f.personality.map { n in
                    f.activeProfile.map { "\(n) · \($0.name), \($0.footprint) channels" } ?? (f.profile == nil ? "\(n)" : "\(n) · not in the profile")
                })
                if !f.profileNote.isEmpty {
                    Text(f.profileNote).font(.system(size: 11.5)).foregroundStyle(Color.silk).padding(.leading, ReadoutRow.labelWidth + 8)
                }
                if f.activeProfile != nil {
                    Text("Double-click a fader on the Transmit tab to pick one of its values.").font(.system(size: 11.5)).foregroundStyle(Color.silk)
                        .padding(.leading, ReadoutRow.labelWidth + 8)
                }
            }
            if f.supported?.contains(0x1200) == true { ManagerFirmwarePanel(manager: manager, device: device, port: port, uid: uid, name: f.label.flatMap { $0.isEmpty ? nil : $0 } ?? "the fixture").id(uid) }
            ModulePanel("Details") {
                ForEach(Self.details.filter { f.supported?.contains($0) ?? ($0 == 0x00C0) }, id: \.self) { row($0) }
                ReadoutRow(label: "Channels used", value: f.footprint.map(String.init), get: { get(0x0060, done: $0) }, enabled: enabled)
                ReadoutRow(label: "Category", value: f.info.flatMap { $0.count >= 6 ? ManagerFixturesCategory.name(mgrU16($0[4...])) : nil },
                           get: { get(0x0060, done: $0) }, enabled: enabled)
                ReadoutRow(label: "Fixture ID", value: ManagerRDM.uid(mgrBytes(hex: uid) ?? [0, 0, 0, 0, 0, 0]))
            }
        }
        .onAppear { if store.byUID[uid]?.supported == nil { loadAll() } }
        .onChange(of: uid) { _ in if store.byUID[uid]?.supported == nil { loadAll() } }
    }

    private func spec(_ pid: UInt16) -> RDMSpec {
        RDMCatalog.standard[pid] ?? f.described[pid]
            ?? RDMSpec(name: String(format: "Parameter %04X", pid), get: true, set: false, kind: .raw)
    }

    /// A readout row for one PID, with GET and SET exactly as the standard or the fixture allows.
    private func row(_ pid: UInt16) -> ReadoutRow {
        let s = spec(pid)
        let names = f.names[pid] ?? [:]
        let current = f.values[pid]
        var setMode: SetMode?
        if s.set {
            switch s.kind {
            case .bool(let off, let on):
                setMode = .choices([off, on]) { i, done in set(pid, [UInt8(i)], done) }
            case .enumeration(let map):
                let keys = map.keys.sorted()
                setMode = .choices(keys.map { map[$0]! }) { i, done in set(pid, [keys[i]], done) }
            case .selector:
                let count = Int(current.flatMap { $0.count >= 2 ? $0[1] : nil } ?? 0)
                if count > 0 {
                    setMode = .choices((1...count).map { n in "\(n)" + (names[UInt8(n)].map { $0.isEmpty ? "" : " · \($0)" } ?? "") }) { i, done in
                        set(pid, [UInt8(i + 1)], done)
                    }
                }
            case .number(let bytes, let signed, let unit, _, let range):
                let limit: ClosedRange<Int64> = signed ? -(Int64(1) << (bytes * 8 - 1))...((Int64(1) << (bytes * 8 - 1)) - 1) : 0...((Int64(1) << (bytes * 8)) - 1)
                setMode = .number(initial: RDMCatalog.draft(s, current), range: range ?? limit, unit: unit) { text, done in
                    switch RDMCatalog.encode(s, text) {
                    case .success(let pd): set(pid, pd, done)
                    case .failure(let e): done(.refused(e.message))
                    }
                }
            case .blockAddress, .selfTest:
                let isBlock: Bool = { if case .blockAddress = s.kind { return true } else { return false } }()
                setMode = .number(initial: RDMCatalog.draft(s, current), range: isBlock ? 1...512 : 0...255) { text, done in
                    switch RDMCatalog.encode(s, text) {
                    case .success(let pd): set(pid, pd, done)
                    case .failure(let e): done(.refused(e.message))
                    }
                }
            default:
                setMode = .text(initial: RDMCatalog.draft(s, current)) { text, done in
                    switch RDMCatalog.encode(s, text) {
                    case .success(let pd): set(pid, pd, done)
                    case .failure(let e): done(.refused(e.message))
                    }
                }
            }
        }
        return ReadoutRow(label: s.name, value: current.map { RDMCatalog.show(s, $0, names: names) },
                          get: s.get ? { done in get(pid, done: done) } : nil, set: setMode, enabled: enabled)
    }

    private func sensorRow(_ n: UInt8) -> ReadoutRow {
        let sensor = f.sensors[n]
        let value = sensor?.value.flatMap { v -> String? in
            guard v.count >= 9, let s = sensor else { return nil }
            func at(_ i: Int) -> Int64 { Int64(Int16(bitPattern: mgrU16(v[i...]))) }
            let now = RDMCatalog.scaled(at(1), exponent: s.exponent, unit: s.unit)
            let low = RDMCatalog.scaled(at(3), exponent: s.exponent, unit: s.unit), high = RDMCatalog.scaled(at(5), exponent: s.exponent, unit: s.unit)
            return at(3) == 0 && at(5) == 0 ? now : "\(now) · low \(low) · high \(high)"
        }
        return ReadoutRow(label: sensor?.name ?? "Sensor \(n + 1)", value: value,
                          get: { done in readSensor(n, done: done) }, enabled: enabled)
    }

    // MARK: - Reading

    /// Supported list, manufacturer descriptions, every readable value (with selector names), then sensors.
    private func loadAll() {
        store.byUID[uid, default: .init()].universe = device.params[port]?[0x0901].map(mgrU16)
        var steps: [(@escaping () -> Void) -> Void] = [
            { next in get(0x0060) { _ in next() } },
            { next in
                rdm(false, 0x0050, []) { pd in
                    store.byUID[uid, default: .init()].supported = pd.map { p in stride(from: 0, to: p.count - 1, by: 2).map { mgrU16(p[$0...]) } }
                        ?? [0x0060, 0x0082, 0x00C0, 0x00F0, 0x1000, 0x00E0] // E1.20 minimum when the list isn't offered
                    next()
                }
            },
        ]
        steps.append { next in
            let manufacturer = (store.byUID[uid]?.supported ?? []).filter { $0 >= 0x8000 }
            runSteps(manufacturer.map { pid in { inner in
                rdm(false, 0x0051, mgrBE16(pid)) { pd in
                    if let pd, let d = RDMCatalog.described(pd) { store.byUID[uid, default: .init()].described[d.pid] = d.spec }
                    inner()
                }
            } }, then: next)
        }
        steps.append { next in
            let fixture = store.byUID[uid] ?? .init()
            let wanted = (Self.core + Self.details + others).filter { (fixture.supported ?? []).contains($0) || Self.core.contains($0) }
            let readable = wanted.filter { spec($0).get }
            runSteps(readable.enumerated().map { i, pid in { inner in
                store.byUID[uid, default: .init()].progress = "Reading \(i + 1) of \(readable.count)"
                get(pid) { _ in inner() }
            } }, then: next)
        }
        steps.append { next in
            runSteps((0..<(store.byUID[uid]?.sensorCount ?? 0)).map { n in { inner in readSensor(UInt8(n)) { _ in inner() } } }, then: next)
        }
        steps.append { next in loadChannels(then: next) } // channel names also label the Transmit faders
        steps.append { next in
            store.byUID[uid]?.profile == nil && store.byUID[uid]?.supported?.contains(0x1200) == true ? fetchProfile(then: next) : next()
        }
        runSteps(steps) { store.byUID[uid, default: .init()].progress = "" }
    }

    /// SLOT_INFO for the offsets, then SLOT_DESCRIPTION for each channel.
    private func loadChannels(then: @escaping () -> Void = {}) {
        store.byUID[uid, default: .init()].universe = device.params[port]?[0x0901].map(mgrU16)
        rdm(false, 0x0120, []) { pd in
            let offsets: [UInt16] = pd.map { p in stride(from: 0, to: p.count - 4, by: 5).map { mgrU16(p[$0...]) } }
                ?? (0..<(f.footprint ?? 0)).map(UInt16.init)
            runSteps(offsets.map { slot in { next in
                rdm(false, 0x0121, mgrBE16(slot)) { d in
                    store.byUID[uid, default: .init()].channels[slot] = d.map { String(decoding: $0.dropFirst(2), as: UTF8.self) } ?? "No description"
                    next()
                }
            } }, then: then)
        }
    }

    // MARK: - Profile

    /// FTC_FILELIST, then download the JSON file (the one naming the software version, when there are several) and load it.
    /// Holds the app-wide transfer lock, like a firmware download.
    private func fetchProfile(then: @escaping () -> Void = {}) {
        guard manager.running, !FirmwareUpdate.active, let dest = mgrBytes(hex: uid) else { return then() }
        let fixture = uid, software = f.software ?? ""
        store.byUID[fixture, default: .init()].profileNote = "Looking for a profile on the fixture…"
        let fw = FirmwareUpdate(transport: FirmwareUpdate.managerTransport(manager, node: device.tuid, ep: port, dest: dest, busySeconds: 300),
                                sleep: FirmwareUpdate.realSleep)
        FirmwareUpdate.active = true
        DispatchQueue.global(qos: .userInitiated).async {
            let json = (fw.fileList() ?? []).filter { $0.suffix.lowercased() == "json" && $0.acceptsDownload && !$0.needsKey }
            let pick = json.first { !software.isEmpty && $0.description.contains(software) } ?? json.first
            let got = pick.map { fw.download(fileID: $0.id) }
            DispatchQueue.main.async {
                FirmwareUpdate.active = false
                defer { then() }
                guard let pick, let got else {
                    store.byUID[fixture, default: .init()].profileNote = "The fixture offers no JSON profile to download."
                    return
                }
                let (o, data) = got
                let title = pick.description.isEmpty ? "file \(pick.id)" : pick.description
                guard o.ok else {
                    store.byUID[fixture, default: .init()].profileNote = "Couldn't download \(title) (file \(pick.id)): \(FirmwareUpdate.reason(o))"
                    return
                }
                apply(Data(data), to: fixture, from: "\(title), downloaded from the fixture")
            }
        }
    }

    private func openProfile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        guard let data = try? Data(contentsOf: url) else {
            store.byUID[uid, default: .init()].profileNote = "Couldn't read \(url.lastPathComponent)"
            return
        }
        apply(data, to: uid, from: url.lastPathComponent)
    }

    /// Keeps the old profile when the new one fails the schema, and says why.
    private func apply(_ data: Data, to fixture: String, from source: String) {
        do {
            store.byUID[fixture, default: .init()].profile = try FixtureProfile.load(data)
            store.byUID[fixture, default: .init()].profileNote = "From \(source)"
        } catch {
            store.byUID[fixture, default: .init()].profileNote = "\(source) doesn't match the profile schema: \(error)"
        }
    }

    private func readSensor(_ n: UInt8, done: @escaping (Signal) -> Void) {
        let read = {
            rdm(false, 0x0201, [n], done: done) { pd in store.byUID[uid, default: .init()].sensors[n]?.value = pd }
        }
        guard store.byUID[uid]?.sensors[n] == nil else { return read() }
        rdm(false, 0x0200, [n]) { pd in
            if let pd, pd.count >= 13 {
                let text = String(decoding: pd.dropFirst(13).prefix { $0 != 0 }, as: UTF8.self)
                store.byUID[uid, default: .init()].sensors[n] = .init(
                    name: text.isEmpty ? (RDMCatalog.sensorTypes[pd[1]] ?? "Sensor \(n + 1)") : text,
                    unit: RDMCatalog.units[pd[2]] ?? "", exponent: RDMCatalog.prefixExponent[pd[3]] ?? 0, value: nil)
            } else {
                store.byUID[uid, default: .init()].sensors[n] = .init(name: "Sensor \(n + 1)", unit: "", exponent: 0, value: nil)
            }
            read()
        }
    }

    /// GET a PID, file the answer, and for a selector fetch the names of its items once.
    private func get(_ pid: UInt16, done: @escaping (Signal) -> Void) {
        rdm(false, pid, [], done: { signal in
            guard signal == .latched, case .selector(let descPID) = spec(pid).kind,
                  let v = store.byUID[uid]?.values[pid], v.count >= 2, store.byUID[uid]?.names[pid] == nil else { return done(signal) }
            let offset = RDMCatalog.descriptionTextOffset[descPID] ?? 1
            runSteps((1...max(1, min(Int(v[1]), 32))).map { n in { next in
                rdm(false, descPID, [UInt8(n)]) { d in
                    if let d { store.byUID[uid, default: .init()].names[pid, default: [:]][UInt8(n)] = String(decoding: d.dropFirst(offset).prefix { $0 != 0 }, as: UTF8.self) }
                    next()
                }
            } }, then: { done(signal) })
        }) { pd in
            if pid == 0x0060 { store.byUID[uid, default: .init()].info = pd } else { store.byUID[uid, default: .init()].values[pid] = pd }
        }
    }

    /// SET a PID, then read it back so the readout shows what the fixture now holds.
    private func set(_ pid: UInt16, _ pd: [UInt8], _ done: @escaping (Signal) -> Void) {
        rdm(true, pid, pd, done: { signal in
            if signal == .latched, pid == 0x00E0 {
                // A new personality is a new channel layout: drop the old names, then read footprint, personality and channels again.
                store.byUID[uid, default: .init()].channels = [:]
                return get(0x0060) { _ in get(pid) { _ in loadChannels { done(.latched) } } }
            }
            guard signal == .latched, spec(pid).get else { return done(signal) }
            get(pid) { _ in done(.latched) }
        }) { _ in }
    }

    /// One RDM request; `filed` gets the ACK's parameter data, `done` the panel signal.
    private func rdm(_ isSet: Bool, _ pid: UInt16, _ pd: [UInt8], done: @escaping (Signal) -> Void = { _ in }, filed: @escaping ([UInt8]?) -> Void) {
        guard let dest = mgrBytes(hex: uid), manager.running else { filed(nil); return done(.silent("The Manager isn't running")) }
        manager.rdm(device.tuid, ep: port, dest: dest, set: isSet, pid: pid, pd: pd) { r in
            if r.ok, ManagerRDM.valid(r.frame), r.frame[16] == 0 {
                filed(Array(r.frame.dropFirst(24).prefix(Int(r.frame[23]))))
                done(.latched)
            } else {
                filed(nil)
                done(nack(r))
            }
        }
    }

    private func rdm(_ isSet: Bool, _ pid: UInt16, _ pd: [UInt8], filed: @escaping ([UInt8]?) -> Void) {
        rdm(isSet, pid, pd, done: { _ in }, filed: filed)
    }

    private func runSteps(_ steps: [(@escaping () -> Void) -> Void], then: @escaping () -> Void) {
        guard let first = steps.first else { return then() }
        first { runSteps(Array(steps.dropFirst()), then: then) }
    }

    /// A NACK names its reason; anything else is silence.
    private func nack(_ r: ManagerResult) -> Signal {
        guard r.ok, r.frame.count > 25, r.frame[16] == 2 else {
            return .silent(r.text.hasPrefix("Busy") ? "Busy with another request" : "No answer from the fixture")
        }
        let reason = mgrU16(r.frame.dropFirst(24))
        let names: [UInt16: String] = [0: "unknown parameter", 1: "format error", 2: "hardware fault", 3: "proxy reject",
                                       4: "write protected", 5: "unsupported command", 6: "value out of range", 7: "buffer full",
                                       8: "packet too large", 9: "sub-device out of range", 10: "proxy buffer full",
                                       0x15: "sensor out of range", 0x16: "sensor fault"]
        return .refused("The fixture refused: \(names[reason] ?? String(format: "reason %04X", reason))")
    }
}

/// E1.20 product categories, by name.
enum ManagerFixturesCategory {
    static func name(_ c: UInt16) -> String {
        let names: [UInt16: String] = [
            0x0100: "Fixture", 0x0101: "Fixed fixture", 0x0102: "Moving yoke", 0x0103: "Moving mirror", 0x01FF: "Fixture",
            0x0200: "Fixture accessory", 0x0201: "Colour accessory", 0x0202: "Yoke accessory", 0x0203: "Mirror accessory",
            0x0204: "Effect accessory", 0x0205: "Beam accessory", 0x02FF: "Fixture accessory",
            0x0300: "Projector", 0x0301: "Fixed projector", 0x0302: "Moving yoke projector", 0x0303: "Moving mirror projector", 0x03FF: "Projector",
            0x0400: "Atmospheric", 0x0401: "Atmospheric effect", 0x0402: "Pyrotechnic", 0x04FF: "Atmospheric",
            0x0500: "Dimmer", 0x0600: "Power", 0x0700: "Scenic", 0x0800: "Data distribution", 0x0900: "Audio-visual",
            0x0A00: "Monitoring", 0x7000: "Control", 0x7100: "Test equipment", 0x7FFF: "Other",
        ]
        return names[c] ?? names[c & 0xFF00] ?? String(format: "Category %04X", c)
    }
}
