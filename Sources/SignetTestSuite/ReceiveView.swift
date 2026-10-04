import CSignet
import Foundation
import SwiftUI

/// A data-plane-only Sig-Net Node (no device_info, so no discovery, no
/// management and no persistence) consuming a list of universes, preview
/// universes and timecode streams. The library runtime receives; the UI
/// polls the lock-free readers on a 20 Hz timer.
final class Receiver: ObservableObject {
    struct Preview { var frame: signet_universe_frame_t; var levels: [UInt8] }

    let settings: SecuritySettings
    @Published var universesText = "1"
    @Published var previewText = ""
    @Published var timecodeText = "1"
    @Published var sourcesPerUniverse = 4
    @Published var selected = 1 { didSet { tapCount = 0; windowStart = nowNs } }
    @Published var logLevel = Int(SIGNET_LOG_INFO.rawValue) { didSet { applyLogLevel() } }
    @Published var autoDiagnostics = true
    @Published private(set) var running = false
    @Published private(set) var status = "Stopped"

    @Published private(set) var levels = [UInt8](repeating: 0, count: 512)
    @Published private(set) var frame: signet_universe_frame_t?
    @Published private(set) var fps = 0.0
    @Published private(set) var nowNs: Int64 = 0
    @Published private(set) var timecodes: [UInt16: signet_timecode_t] = [:]
    @Published private(set) var previews: [UInt16: Preview] = [:]
    @Published private(set) var counters = signet_diag_counters_t()
    @Published private(set) var rejections: [signet_rejection_record_t] = []
    @Published private(set) var log: [String] = []
    private(set) var universes: [UInt16] = []
    private(set) var previewUniverses: [UInt16] = []
    private(set) var timecodeStreams: [UInt16] = []

    let tuid = Identity.tuid("receiver")
    private var device: OpaquePointer?
    private var ctx: OpaquePointer?
    private var scopeC: UnsafeMutablePointer<CChar>?
    private var logger: UnsafeMutablePointer<signet_log_provider_t>?
    private var timer: Timer?
    private var tapCount = 0
    private var windowStart: Int64 = 0

    init(settings: SecuritySettings) { self.settings = settings }

    func start() {
        guard !running else { return }
        do {
            try create()
        } catch {
            stop()
            status = "\(error)"
            return
        }
        running = true
        settings.deviceStarted()
        status = "Receiving \(universes.count) universe(s) · \(settings.mode.rawValue) Mode · scope \(settings.scopeOrDefault)"
        timer = Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { [weak self] _ in self?.tick() }
    }

    private func create() throws {
        universes = try parseList(universesText, max: 63999, what: "universe")
        previewUniverses = try parseList(previewText, max: 63999, what: "preview universe")
        timecodeStreams = try parseList(timecodeText, max: 255, what: "timecode stream")
        guard !universes.isEmpty else { throw Problem(description: "Enter at least one universe") }
        if !universes.contains(UInt16(clamping: selected)) { selected = Int(universes[0]) }

        let secure = settings.mode == .secure
        var k0 = try settings.rootKey()
        defer { wipe(&k0) }

        scopeC = strdup(settings.scopeOrDefault)
        logger = .allocate(capacity: 1)
        logger!.initialize(to: signet_log_provider_t())
        logger!.pointee.struct_size = MemoryLayout<signet_log_provider_t>.size
        logger!.pointee.user_data = Unmanaged.passUnretained(self).toOpaque()
        // Runs on the runtime thread during drain; record pointers are borrowed
        // and not NUL-terminated, so format now and hop to main with a String.
        logger!.pointee.on_record = { user, record in
            guard let user, let record else { return SIGNET_OK }
            let line = Receiver.format(record.pointee)
            let rx = Unmanaged<Receiver>.fromOpaque(user).takeUnretainedValue()
            DispatchQueue.main.async { rx.append(line) }
            return SIGNET_OK
        }

        var cfg = signet_context_config_t()
        cfg.struct_size = MemoryLayout<signet_context_config_t>.size
        cfg.identity.struct_size = MemoryLayout<signet_identity_t>.size
        cfg.identity.tuid = Identity.tuple(tuid)
        cfg.identity.scope = UnsafePointer(scopeC)
        cfg.identity.security_mode = settings.mode.raw
        cfg.logger = UnsafePointer(logger)
        cfg.sources_per_universe = sourcesPerUniverse
        cfg.frame_tap_depth = 16 // only for an accurate fps: the 20 Hz UI poll would undercount a 44 Hz stream
        // No persistence: the header requires it only with device_info.

        let err = universes.withUnsafeBufferPointer { uPtr in
            previewUniverses.withUnsafeBufferPointer { pPtr in
                k0.withUnsafeMutableBufferPointer { keyPtr in
                    cfg.universes = uPtr.baseAddress
                    cfg.universe_count = uPtr.count
                    cfg.preview_universes = pPtr.isEmpty ? nil : pPtr.baseAddress
                    cfg.preview_universe_count = pPtr.count
                    if secure {
                        cfg.root_key = keyPtr.baseAddress // wiped by signet_device_create
                        cfg.root_key_len = keyPtr.count
                    }
                    return withUnsafePointer(to: &cfg) { cfgPtr in
                        var deviceCfg = signet_device_config_t()
                        deviceCfg.struct_size = MemoryLayout<signet_device_config_t>.size
                        deviceCfg.roles = SIGNET_DEVICE_ROLE_NODE.rawValue
                        deviceCfg.node = cfgPtr
                        return signet_device_create(&deviceCfg, &device)
                    }
                }
            }
        }
        try check("Device creation", err)
        ctx = signet_device_node(device)
        applyLogLevel()
        try check("Runtime start", signet_device_runtime_start(device))
        nowNs = Self.monotonicNs()
        windowStart = nowNs
    }

    func stop() {
        timer?.invalidate()
        timer = nil
        if let device {
            _ = signet_device_runtime_stop(device)
            _ = signet_device_destroy(device)
        }
        device = nil
        ctx = nil
        free(scopeC)
        scopeC = nil
        logger?.deallocate() // safe: the runtime that called it has stopped
        logger = nil
        if running {
            status = "Stopped"
            settings.deviceStopped()
        }
        running = false
        frame = nil
        fps = 0
    }

    func clearLog() { log.removeAll() }

    /// Probes every timecode stream once and switches the poll list to the live ones.
    func scanTimecode() {
        guard let ctx else { return }
        let found = (1...255).map(UInt16.init).filter { var tc = Self.newTimecode(); return signet_context_read_timecode(ctx, $0, &tc) == SIGNET_OK }
        timecodeStreams = found
        timecodes = timecodes.filter { found.contains($0.key) }
    }

    func refreshDiagnostics() {
        guard let ctx else { return }
        var c = signet_diag_counters_t()
        c.struct_size = MemoryLayout<signet_diag_counters_t>.size
        if signet_context_diag_counters(ctx, &c) == SIGNET_OK { counters = c }
        var r = signet_rejection_record_t()
        r.struct_size = MemoryLayout<signet_rejection_record_t>.size
        var records = [signet_rejection_record_t](repeating: r, count: 32)
        var n = 0
        if signet_context_diag_rejections(ctx, &records, records.count, &n) == SIGNET_OK { rejections = Array(records.prefix(n)) }
    }

    private func tick() {
        guard let ctx else { return }
        nowNs = Self.monotonicNs()
        var buf = [UInt8](repeating: 0, count: 512)
        var f = Self.newFrame()
        let sel = UInt16(clamping: selected)
        if signet_context_read_universe(ctx, sel, &buf, buf.count, &f) == SIGNET_OK {
            levels = buf
            frame = f
        } else {
            frame = nil
        }

        // Drain every tap (a full ring drops and counts), counting the selected universe.
        var one: UInt8 = 0
        for u in universes {
            while signet_context_read_tap(ctx, u, &one, 1, &f) == SIGNET_OK { if u == sel { tapCount += 1 } }
        }
        if nowNs - windowStart >= 1_000_000_000 {
            fps = Double(tapCount) * 1e9 / Double(nowNs - windowStart)
            tapCount = 0
            windowStart = nowNs
        }

        for s in timecodeStreams {
            var tc = Self.newTimecode()
            if signet_context_read_timecode(ctx, s, &tc) == SIGNET_OK { timecodes[s] = tc }
        }
        for u in previewUniverses {
            var latest: Preview?
            while signet_context_read_preview(ctx, u, &buf, buf.count, &f) == SIGNET_OK { latest = Preview(frame: f, levels: buf) }
            if let latest { previews[u] = latest }
        }
        if autoDiagnostics { refreshDiagnostics() }
    }

    private func applyLogLevel() {
        guard let ctx else { return }
        _ = signet_context_set_log_level(ctx, signet_log_level_t(rawValue: UInt32(logLevel)))
    }

    private func append(_ line: String) {
        log.append(line)
        if log.count > 500 { log.removeFirst(log.count - 500) }
    }

    /// The default clock is std::chrono::steady_clock,
    /// which Apple's libc++ implements as CLOCK_MONOTONIC_RAW (counts sleep;
    /// UPTIME_RAW does not, and the selftest's age check catches the mismatch).
    static func monotonicNs() -> Int64 { Int64(clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)) }

    private static func newFrame() -> signet_universe_frame_t {
        var f = signet_universe_frame_t()
        f.struct_size = MemoryLayout<signet_universe_frame_t>.size
        return f
    }

    private static func newTimecode() -> signet_timecode_t {
        var tc = signet_timecode_t()
        tc.struct_size = MemoryLayout<signet_timecode_t>.size
        return tc
    }

    static let levelNames = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "CRITICAL", "OFF"]

    private static func format(_ r: signet_log_record_t) -> String {
        func text(_ p: UnsafeRawPointer?, _ n: Int) -> String {
            p.map { String(decoding: UnsafeRawBufferPointer(start: $0, count: n), as: UTF8.self) } ?? ""
        }
        var line = String(format: "%.3f ", Double(r.monotonic_ns) / 1e9)
            + (levelNames.indices.contains(Int(r.level)) ? levelNames[Int(r.level)] : "?") + " "
            + (r.component_name.map { String(cString: $0) } ?? "#\(r.component_id)") + ": "
            + text(r.message, r.message_len)
        for i in 0..<r.field_count {
            guard let field = r.fields?[i] else { break }
            let value: String
            switch Int32(field.kind) {
            case Int32(SIGNET_LOG_FIELD_I64.rawValue): value = "\(field.value.i64_value)"
            case Int32(SIGNET_LOG_FIELD_F64.rawValue): value = "\(field.value.f64_value)"
            case Int32(SIGNET_LOG_FIELD_BOOL.rawValue): value = field.value.u64_value != 0 ? "true" : "false"
            case Int32(SIGNET_LOG_FIELD_STRING.rawValue): value = text(field.data, field.data_len)
            case Int32(SIGNET_LOG_FIELD_BYTES.rawValue):
                value = field.data.map { Identity.hex(Array(UnsafeBufferPointer(start: $0, count: field.data_len))) } ?? ""
            default: value = "\(field.value.u64_value)"
            }
            line += " \(field.key.map { String(cString: $0) } ?? "?")=\(value)"
        }
        return line
    }

    // MARK: - Self test

    /// In-process loopback: a Transmitter on universe 1 at 77, this Node must see it.
    static func selfTest(settings: SecuritySettings) -> Bool {
        func fail(_ why: String) -> Bool { print("  receive: \(why)"); return false }
        guard (try? parseList("1-4, 10,3", max: 63999, what: "")) == [1, 2, 3, 4, 10],
              (try? parseList("0", max: 63999, what: "")) == nil,
              (try? parseList("5-2", max: 63999, what: "")) == nil else { return fail("universe list parser") }

        let rx = Receiver(settings: settings)
        rx.previewText = "1"
        rx.start()
        defer { rx.stop() }
        guard rx.running else { return fail(rx.status) }
        let tx = Transmitter(settings: settings)
        tx.start()
        defer { tx.stop() }
        guard tx.running else { return fail(tx.status) }
        tx.setAll(77)

        var buf = [UInt8](repeating: 0, count: 512)
        var f = newFrame()
        let deadline = Date().addingTimeInterval(2)
        while Date() < deadline {
            RunLoop.main.run(until: Date().addingTimeInterval(0.05))
            guard let ctx = rx.ctx, signet_context_read_universe(ctx, 1, &buf, buf.count, &f) == SIGNET_OK, buf[0] == 77 else { continue }
            guard f.source_count >= 1 else { return fail("source_count \(f.source_count)") }
            let age = monotonicNs() - f.published_ns
            guard (0..<1_000_000_000).contains(age) else { return fail("frame age \(age) ns: clock mismatch") }
            return true
        }
        return fail("no level 77 on universe 1 within 2 s (got \(buf[0]), \(rx.counters.drops_total) drops)")
    }
}

private struct Problem: Error, CustomStringConvertible { let description: String }

/// "1-4, 10" -> [1, 2, 3, 4, 10]; unique, sorted, each in 1...max.
private func parseList(_ text: String, max: UInt16, what: String) throws -> [UInt16] {
    var out = Set<UInt16>()
    for item in text.split(separator: ",") where !item.allSatisfy(\.isWhitespace) {
        let ends = item.split(separator: "-", omittingEmptySubsequences: false)
            .map { UInt16($0.trimmingCharacters(in: .whitespaces)) }
        guard (1...2).contains(ends.count), let lo = ends.first!, let hi = ends.last!, 1 <= lo, lo <= hi, hi <= max
        else { throw Problem(description: "Bad \(what) “\(item.trimmingCharacters(in: .whitespaces))” (1–\(max))") }
        out.formUnion(lo...hi)
    }
    return out.sorted()
}

private let dropNames = [
    "none", "malformed", "unsupported mode", "mode mismatch", "bad version", "bad code", "bad URI",
    "routing scope", "routing TUID", "replay session", "replay seq", "auth failed", "payload invalid",
    "table saturated", "internal", "CoAP duplicate",
]

private func dropName(_ reason: UInt8) -> String {
    dropNames.indices.contains(Int(reason)) ? dropNames[Int(reason)] : "reason \(reason)"
}

// MARK: - View

struct ReceiveView: View {
    @ObservedObject var rx: Receiver
    @State private var pane = Pane.live

    enum Pane: String, CaseIterable { case live = "Live", timecode = "Timecode", preview = "Preview", diagnostics = "Diagnostics", log = "Log" }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Form {
                TextField("Universes (e.g. 1-4, 10)", text: $rx.universesText)
                TextField("Preview universes", text: $rx.previewText)
                TextField("Timecode streams", text: $rx.timecodeText)
                Stepper("Sources per universe: \(rx.sourcesPerUniverse)", value: $rx.sourcesPerUniverse, in: 1...64)
                LabeledContent("TUID", value: Identity.hex(rx.tuid))
            }
            .disabled(rx.running)

            HStack {
                Button(rx.running ? "Stop" : "Start") { rx.running ? rx.stop() : rx.start() }
                    .disabled(!rx.running && !rx.settings.ready)
                Text(rx.status).foregroundStyle(.secondary).lineLimit(2)
            }

            Picker("View", selection: $pane) {
                ForEach(Pane.allCases, id: \.self) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()

            switch pane {
            case .live: live
            case .timecode: timecode
            case .preview: preview
            case .diagnostics: diagnostics
            case .log: logPane
            }
        }
        .padding()
    }

    private func age(_ ns: Int64) -> String { "\(max(0, (rx.nowNs - ns) / 1_000_000)) ms" }

    private var live: some View {
        VStack(alignment: .leading) {
            HStack {
                TextField("Universe", value: $rx.selected, format: .number.grouping(.never)).frame(width: 80)
                Stepper("Universe", value: $rx.selected, in: 1...63999).labelsHidden()
                if let f = rx.frame {
                    Text("Slots \(f.slot_count) · Sources \(f.source_count) · Age \(age(f.published_ns)) · \(rx.fps, specifier: "%.1f") fps")
                        .monospacedDigit()
                } else {
                    Text(rx.universes.contains(UInt16(clamping: rx.selected)) || !rx.running ? "No data" : "Not monitored")
                        .foregroundStyle(.secondary)
                }
            }
            LevelGrid(levels: rx.levels, numbers: true, name: "Universe \(rx.selected)")
        }
    }

    private var timecode: some View {
        VStack(alignment: .leading) {
            Button("Scan streams 1–255") { rx.scanTimecode() }.disabled(!rx.running)
            List(rx.timecodes.keys.sorted(), id: \.self) { s in
                let tc = rx.timecodes[s]!
                let v = tc.value
                let drop = [0x02, 0x06, 0x09].contains(v.4)
                HStack {
                    Text("Stream \(s)").frame(width: 80, alignment: .leading)
                    Text(String(format: "%02d:%02d:%02d%@%02d", v.0, v.1, v.2, drop ? ";" : ":", v.3)).font(.body.monospacedDigit())
                    Text("\(Double(signet_timecode_rate_millifps(v.4)) / 1000, specifier: "%g") fps").foregroundStyle(.secondary)
                    if tc.lost != 0 { Text("LOST").bold().foregroundStyle(.red) }
                }
            }
        }
    }

    private var preview: some View {
        ScrollView {
            VStack(alignment: .leading) {
                if rx.previewUniverses.isEmpty { Text("No preview universes configured.").foregroundStyle(.secondary) }
                ForEach(rx.previewUniverses, id: \.self) { u in
                    if let p = rx.previews[u] {
                        Text("Universe \(u) · Slots \(p.frame.slot_count) · Age \(age(p.frame.published_ns))").monospacedDigit()
                        LevelGrid(levels: p.levels, numbers: false, name: "Preview universe \(u)").frame(height: 96)
                    } else {
                        Text("Universe \(u) · no preview frame yet").foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    private var diagnostics: some View {
        let c = rx.counters
        var drops = withUnsafeBytes(of: c.drops) { Array($0.bindMemory(to: UInt64.self)) }
        drops.append(c.coap_duplicates)
        let rows: [(String, UInt64)] = [
            ("Accepted", c.accepted), ("Beacons", c.beacons), ("Drops total", c.drops_total),
            ("Rejections recorded", c.rejections_recorded), ("Merge saturations", c.merge_saturations),
            ("DoS packets dropped", c.dos_packets_dropped), ("Preview frames dropped", c.preview_frames_dropped),
            ("Tap frames dropped", c.tap_frames_dropped), ("Tap frames stale", c.tap_frames_stale),
            ("Send failures", c.send_failures), ("Recv failures", c.transport_recv_failures),
            ("Recv truncated", c.transport_recv_truncated), ("Runtime poll failures", c.runtime_poll_failures),
            ("Runtime faulted", UInt64(c.runtime_faulted)), ("Poll jobs dropped", c.poll_jobs_dropped),
            ("Log records dropped", c.log_records_dropped), ("Log delivery failures", c.log_delivery_failures),
            ("Log muted", UInt64(max(0, c.log_muted))), ("RDM frames rejected", c.rdm_frames_rejected),
            ("RDM SETs blocked", c.rdm_sets_blocked), ("Offboard persist failures", c.offboard_persist_failures),
            ("Booted offboard pending", UInt64(c.booted_offboard_pending)),
        ]
        return VStack(alignment: .leading) {
            HStack {
                Toggle("Auto refresh", isOn: $rx.autoDiagnostics)
                Button("Refresh") { rx.refreshDiagnostics() }.disabled(!rx.running)
            }
            HStack(alignment: .top, spacing: 24) {
                counterGrid(rows)
                counterGrid(drops.indices.dropFirst().map { ("Drop: \(dropNames[$0])", drops[$0]) })
            }
            Text("Flight recorder").font(.headline)
            List(Array(rx.rejections.enumerated().reversed()), id: \.offset) { _, r in
                let header = withUnsafeBytes(of: r.header) { Identity.hex(Array($0.prefix(Int(r.header_len)))) }
                HStack {
                    Text("−\(age(r.monotonic_ns))").frame(width: 80, alignment: .trailing)
                    Text(dropName(r.drop_reason)).frame(width: 120, alignment: .leading)
                    Text("\(r.datagram_len) B").frame(width: 60, alignment: .trailing)
                    Text(header).font(.caption.monospaced()).textSelection(.enabled)
                }
                .monospacedDigit()
            }
        }
    }

    private func counterGrid(_ rows: [(String, UInt64)]) -> some View {
        Grid(alignment: .leading, verticalSpacing: 1) {
            ForEach(rows, id: \.0) { name, value in
                GridRow {
                    Text(name).foregroundStyle(.secondary)
                    Text("\(value)").monospacedDigit().foregroundStyle(value > 0 && name.hasPrefix("Drop") ? .orange : .primary)
                }
            }
        }
        .font(.caption)
    }

    private var logPane: some View {
        VStack(alignment: .leading) {
            HStack {
                Picker("Log level", selection: $rx.logLevel) {
                    ForEach(Receiver.levelNames.indices, id: \.self) { Text(Receiver.levelNames[$0]).tag($0) }
                }
                .frame(width: 200)
                Button("Clear") { rx.clearLog() }
            }
            ScrollViewReader { proxy in
                List(Array(rx.log.enumerated()), id: \.offset) { i, line in
                    Text(line).font(.caption.monospaced()).textSelection(.enabled).id(i)
                }
                .onChange(of: rx.log.count) { n in proxy.scrollTo(n - 1, anchor: .bottom) }
            }
        }
    }
}

/// 32×16 slot grid with intensity shading; drawn in one Canvas so 20 Hz redraws stay cheap.
private struct LevelGrid: View {
    let levels: [UInt8]
    let numbers: Bool
    let name: String

    var body: some View {
        Canvas { ctx, size in
            let w = size.width / 32, h = size.height / 16
            for (i, v) in levels.prefix(512).enumerated() {
                let rect = CGRect(x: CGFloat(i % 32) * w, y: CGFloat(i / 32) * h, width: w - 1, height: h - 1)
                ctx.fill(Path(rect), with: .color(Color.sigNet.opacity(0.08 + 0.92 * Double(v) / 255)))
                if numbers {
                    ctx.draw(Text("\(v)").font(.system(size: 8).monospacedDigit()).foregroundColor(v > 140 ? .white : .primary),
                             at: CGPoint(x: rect.midX, y: rect.midY))
                }
            }
        }
        .frame(minHeight: 120)
        .accessibilityElement()
        .accessibilityLabel(name)
        .accessibilityValue("\(levels.filter { $0 > 0 }.count) of 512 slots above zero, highest \(levels.max() ?? 0), slot 1 at \(levels.first ?? 0)")
    }
}
