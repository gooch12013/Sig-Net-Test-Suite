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

        let err = try settings.withInterface { nic in
            cfg.multicast_interface = nic
            return universes.withUnsafeBufferPointer { uPtr in
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

// MARK: - View

/// Receive as one instrument: a control strip, the local settings, then Monitor, Timecode & preview, or Debug.
/// Hex, drop reasons and the library log live only in Debug.
struct ReceiveView: View {
    @ObservedObject var rx: Receiver
    @ObservedObject private var settings: SecuritySettings
    @State private var mode = Snapshot.arg("--receive-tab") ?? "monitor"

    init(rx: Receiver) {
        self.rx = rx
        settings = rx.settings
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            controlStrip
            HStack {
                ModeKeys(options: [("monitor", "Monitor"), ("timecode", "Timecode & preview"), ("debug", "Debug")], selection: $mode)
                Spacer()
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    switch mode {
                    case "timecode": ReceiveTimecode(rx: rx); ReceivePreview(rx: rx)
                    case "debug": ReceiveDebugView(rx: rx)
                    default: settingsModule; ReceiveMonitor(rx: rx)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    private var controlStrip: some View {
        HStack(spacing: 10) {
            if rx.running {
                Button("Stop") { rx.stop() }.buttonStyle(SoftKeyStyle(lamp: .lampOnline))
            } else {
                Button("Start receiving") { rx.start() }
                    .buttonStyle(SoftKeyStyle(prominent: true))
                    .disabled(!settings.ready)
            }
            // Not running and not "Stopped" means start failed; the status holds the reason.
            let failed = !rx.running && rx.status != "Stopped"
            if failed { Lamp(color: .lampFault) }
            Text(rx.running || failed ? rx.status : settings.ready ? "Stopped. Set the universes below, then Start." : "Stopped. Fix the security settings above to start.")
                .font(.system(size: 11.5))
                .foregroundStyle(failed ? Color.lampFault : Color.silk)
                .lineLimit(1).truncationMode(.middle)
            Spacer()
        }
    }

    private var settingsModule: some View {
        ModulePanel("Settings") {
            if rx.running { Silkscreen("Locked while receiving") }
        } content: {
            ReadoutRow(label: "Universes", value: rx.universesText.isEmpty ? nil : rx.universesText,
                       set: .text(initial: rx.universesText) { t, done in
                           commitList(t, max: 63999, what: "universe", done) { rx.universesText = $0 } },
                       enabled: !rx.running)
            ReadoutRow(label: "Preview universes", value: rx.previewText.isEmpty ? "None" : rx.previewText,
                       set: .text(initial: rx.previewText) { t, done in
                           commitList(t, max: 63999, what: "preview universe", done) { rx.previewText = $0 } },
                       enabled: !rx.running)
            ReadoutRow(label: "Timecode streams", value: rx.timecodeText.isEmpty ? "None" : rx.timecodeText,
                       set: .text(initial: rx.timecodeText) { t, done in
                           commitList(t, max: 255, what: "timecode stream", done) { rx.timecodeText = $0 } },
                       enabled: !rx.running)
            ReadoutRow(label: "Sources per universe", value: "\(rx.sourcesPerUniverse)",
                       set: .number(initial: "\(rx.sourcesPerUniverse)", range: 1...64) { t, done in
                           guard let n = Int(t.trimmingCharacters(in: .whitespaces)), (1...64).contains(n) else { return done(.refused("Enter 1–64")) }
                           rx.sourcesPerUniverse = n
                           done(.latched)
                       },
                       enabled: !rx.running)
        }
    }

    /// Checks a list locally before storing it, so a typo is refused here rather than at Start.
    private func commitList(_ text: String, max: UInt16, what: String, _ done: (Signal) -> Void, store: (String) -> Void) {
        do {
            _ = try parseList(text, max: max, what: what)
            store(text.trimmingCharacters(in: .whitespaces))
            done(.latched)
        } catch {
            done(.refused("\(error)"))
        }
    }
}

/// Live levels for one universe, with the frame's vital signs.
private struct ReceiveMonitor: View {
    @ObservedObject var rx: Receiver

    /// While stopped, the list that Start would use.
    private var universes: [UInt16] {
        rx.running || !rx.universes.isEmpty ? rx.universes : (try? parseList(rx.universesText, max: 63999, what: "")) ?? []
    }
    private var selection: Binding<UInt16> {
        Binding(get: { UInt16(clamping: rx.selected) }, set: { rx.selected = Int($0) })
    }

    var body: some View {
        let f = rx.frame
        ModulePanel("Monitor") {
            chooser
        } content: {
            HStack(spacing: 8) {
                vital("Channels driven", f.map { "\($0.slot_count)" })
                vital("Sources", f.map { "\($0.source_count)" })
                vital("Frame age", f.map { "\(max(0, (rx.nowNs - $0.published_ns) / 1_000_000)) ms" })
                vital("Frame rate", f.map { _ in String(format: "%.1f fps", rx.fps) })
            }
            ZStack {
                LevelGrid(levels: f == nil ? Array(repeating: 0, count: 512) : rx.levels, numbers: f != nil, name: "Universe \(rx.selected) levels")
                    .opacity(f == nil ? 0.55 : 1)
                if f == nil {
                    Text(!rx.running ? "Stopped" : universes.contains(UInt16(clamping: rx.selected)) ? "Waiting for universe \(rx.selected)" : "Universe \(rx.selected) is not in the list")
                        .font(.system(size: 13, weight: .medium, design: .monospaced))
                        .foregroundStyle(Color.inkDim)
                        .padding(.horizontal, 12).padding(.vertical, 6)
                        .background(RoundedRectangle(cornerRadius: 4).fill(Color.readoutWindow.opacity(0.92)))
                }
            }
            .frame(height: 340)
        }
    }

    @ViewBuilder private var chooser: some View {
        HStack(spacing: 8) {
            Silkscreen("Universe")
            if universes.count > 1 && universes.count <= 8 {
                ModeKeys(options: universes.map { ($0, "\($0)") }, selection: selection)
            } else if universes.count > 8 {
                Menu {
                    ForEach(universes, id: \.self) { u in Button("Universe \(u)") { rx.selected = Int(u) } }
                } label: { Text("\(rx.selected)") }
                    .menuStyle(.borderlessButton).fixedSize()
                    .help("Choose the universe to show")
            } else {
                Text("\(rx.selected)").font(.system(size: 13, weight: .semibold, design: .monospaced)).foregroundStyle(Color.ink)
            }
        }
    }

    private func vital(_ label: String, _ value: String?) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Silkscreen(label)
            ReadoutWindow {
                Text(value ?? "—")
                    .font(.system(size: 18, weight: .medium, design: .monospaced)).monospacedDigit()
                    .foregroundStyle(value == nil ? Color.silk : Color.ink)
                    .padding(.vertical, 4)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(label)
        .accessibilityValue(value ?? "no value")
    }
}

/// Each timecode stream as a large display with its rate and a running/lost lamp.
private struct ReceiveTimecode: View {
    @ObservedObject var rx: Receiver

    private var streams: [UInt16] {
        let live = rx.timecodes.keys.sorted()
        if !live.isEmpty { return live }
        return rx.running ? rx.timecodeStreams : (try? parseList(rx.timecodeText, max: 255, what: "")) ?? []
    }

    var body: some View {
        ModulePanel("Timecode") {
            Button("Scan streams") { rx.scanTimecode() }
                .buttonStyle(.softKey)
                .disabled(!rx.running)
                .help("Look for timecode on every stream, 1 to 255, and show the live ones")
        } content: {
            if streams.isEmpty {
                Text(rx.running ? "No timecode streams. Press Scan streams." : "No timecode streams set.")
                    .font(.system(size: 12)).foregroundStyle(Color.silk)
            }
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 300), spacing: 12, alignment: .leading)], alignment: .leading, spacing: 12) {
                ForEach(streams, id: \.self) { s in display(s, rx.timecodes[s]) }
            }
        }
    }

    private func display(_ s: UInt16, _ tc: signet_timecode_t?) -> some View {
        let v = tc?.value
        let drop = v.map { [0x02, 0x06, 0x09].contains($0.4) } ?? false
        let time = v.map { String(format: "%02d:%02d:%02d%@%02d", $0.0, $0.1, $0.2, drop ? ";" : ":", $0.3) } ?? "--:--:--:--"
        let lost = (tc?.lost ?? 0) != 0
        let state = tc == nil ? (rx.running ? "Waiting" : "Stopped") : lost ? "Lost" : "Running"
        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Silkscreen("Stream \(s)")
                Spacer()
                Lamp(color: tc == nil ? nil : lost ? .lampFault : .lampOnline)
                Text(state).font(.system(size: 11, weight: .semibold)).foregroundStyle(lost ? Color.lampFault : Color.inkDim)
            }
            ReadoutWindow(signal: lost ? .refused("") : .idle) {
                HStack(alignment: .firstTextBaseline) {
                    Text(time)
                        .font(.system(size: 34, weight: .medium, design: .monospaced)).monospacedDigit()
                        .foregroundStyle(tc == nil ? Color.silk : lost ? Color.inkDim : Color.lampLatch)
                    Spacer()
                    Text(v.map { String(format: "%g fps", Double(signet_timecode_rate_millifps($0.4)) / 1000) } ?? "")
                        .font(.system(size: 12, design: .monospaced)).foregroundStyle(Color.inkDim)
                }
                .padding(.vertical, 8)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Timecode stream \(s)")
        .accessibilityValue("\(tc == nil ? "no timecode" : time), \(state)")
    }
}

/// Preview universes: the look a console is about to send.
private struct ReceivePreview: View {
    @ObservedObject var rx: Receiver

    private var universes: [UInt16] {
        rx.running || !rx.previewUniverses.isEmpty ? rx.previewUniverses : (try? parseList(rx.previewText, max: 63999, what: "")) ?? []
    }

    var body: some View {
        ModulePanel("Preview") {
            if universes.isEmpty {
                Text("No preview universes set. Add them under Monitor, Settings.")
                    .font(.system(size: 12)).foregroundStyle(Color.silk)
            }
            ForEach(universes, id: \.self) { u in
                let p = rx.previews[u]
                VStack(alignment: .leading, spacing: 6) {
                    HStack(spacing: 14) {
                        Silkscreen("Universe \(u)")
                        if let p {
                            Text("\(p.frame.slot_count) channels  ·  \(max(0, (rx.nowNs - p.frame.published_ns) / 1_000_000)) ms old")
                                .font(.system(size: 11, design: .monospaced)).monospacedDigit().foregroundStyle(Color.inkDim)
                        } else {
                            Text(rx.running ? "No preview yet" : "Stopped").font(.system(size: 11)).foregroundStyle(Color.silk)
                        }
                    }
                    LevelGrid(levels: p?.levels ?? Array(repeating: 0, count: 512), numbers: false, name: "Preview universe \(u)")
                        .frame(height: 110)
                }
            }
        }
    }
}

/// 32×16 slot grid in one Canvas so 20 Hz redraws stay cheap: recessed window, teal by level.
private struct LevelGrid: View {
    let levels: [UInt8]
    let numbers: Bool
    let name: String

    var body: some View {
        Canvas { ctx, size in
            let pad: CGFloat = 6
            let w = (size.width - pad * 2) / 32, h = (size.height - pad * 2) / 16
            for (i, v) in levels.prefix(512).enumerated() {
                let rect = CGRect(x: pad + CGFloat(i % 32) * w, y: pad + CGFloat(i / 32) * h, width: w - 2, height: h - 2)
                let cell = Path(roundedRect: rect, cornerRadius: 2)
                ctx.fill(cell, with: .color(Color.module.opacity(0.55)))
                if v > 0 { ctx.fill(cell, with: .color(Color.lampLatch.opacity(0.18 + 0.82 * Double(v) / 255))) }
                if numbers {
                    ctx.draw(Text("\(v)").font(.system(size: 9, design: .monospaced))
                        .foregroundColor(v > 150 ? Color.readoutWindow : v > 0 ? Color.ink : Color.silk.opacity(0.6)),
                             at: CGPoint(x: rect.midX, y: rect.midY))
                }
            }
        }
        .background(RoundedRectangle(cornerRadius: 4, style: .continuous).fill(Color.readoutWindow)
            .overlay(RoundedRectangle(cornerRadius: 4, style: .continuous).strokeBorder(Color.black.opacity(0.7), lineWidth: 1)))
        .accessibilityElement()
        .accessibilityLabel(name)
        .accessibilityValue("\(levels.filter { $0 > 0 }.count) of 512 channels above zero, highest \(levels.max() ?? 0), channel 1 at \(levels.first ?? 0)")
    }
}
