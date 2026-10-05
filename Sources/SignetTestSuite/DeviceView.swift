import CSignet
import SwiftUI

/// A complete, discoverable Sig-Net Node: a fake fixture with N virtual
/// endpoints, each consuming a universe and hosting a tiny RDM responder.
/// Managers can discover it, SET/GET parameters (backed by an in-memory
/// store, proprietary TIDs included) and tunnel RDM to it.
final class FakeDevice: ObservableObject {
    let settings: SecuritySettings
    // Configurable while stopped.
    @Published var modelName = "Sig-Net Test Fixture"
    @Published var label = "Test Fixture"
    @Published var firmwareLabel = "v1.0.0"
    @Published var endpointCount = 2
    @Published var universes = Array(1...8) // endpoint n consumes universes[n - 1]
    @Published var freshPowerOn = false
    @Published var acceptNetwork = false

    @Published private(set) var running = false
    @Published private(set) var status = "Stopped"
    @Published private(set) var log: [String] = []
    @Published private(set) var identifying: [Bool] = []
    @Published private(set) var live: [Live] = []

    struct Live { var levels = [UInt8](repeating: 0, count: 32), slots = 0, sources = 0 }

    /// Proprietary TIDs (PF §10.1.1 manufacturer range 0x8000-0xFF00), answered
    /// at the root for Managers sending Mfg-Code 0x7FF0: a 1-byte level and a
    /// 1-32 byte UTF-8 note.
    static let tidTestLevel: UInt16 = 0x8001, tidTestNote: UInt16 = 0x8002

    let tuid = Identity.tuid("device")
    private var device: OpaquePointer?
    private var ctx: OpaquePointer?
    private var scopeC: UnsafeMutablePointer<CChar>?
    private var liveTimer: Timer?
    private let launched = Date()

    // Runtime-thread state: only library callbacks touch these while running.
    private var params: [UInt32: [UInt8]] = [:] // (tid << 16 | endpoint) -> value
    private var snapshot: [UInt32: [UInt8]]?
    private var responders: [DeviceRDMResponder] = []
    private var acceptsNetwork = false

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
        status = "Running · \(responders.count) endpoints · \(settings.mode.rawValue) Mode · scope \(settings.scopeOrDefault)"
        append("Started, TUID \(Identity.hex(tuid))")
        liveTimer = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { [weak self] _ in self?.readLevels() }
    }

    func stop() {
        liveTimer?.invalidate()
        liveTimer = nil
        if let device {
            _ = signet_device_runtime_stop(device)
            _ = signet_device_destroy(device)
        }
        device = nil
        ctx = nil
        free(scopeC)
        scopeC = nil
        if running {
            status = "Stopped"
            append("Stopped")
            settings.deviceStopped()
        }
        running = false
        identifying = identifying.map { _ in false }
    }

    /// Same path as a Manager SET (persists, bumps CHANGE_COUNT, publishes).
    @discardableResult func applyLabel() -> Bool {
        guard let device else { return false }
        let err = signet_device_set_label(device, label, label.utf8.count)
        append("set_label \"\(label)\": " + (err == SIGNET_OK ? "OK" : SignetError("Set label", err).description))
        return err == SIGNET_OK
    }

    func clearLog() { log.removeAll() }

    func notifyLabelChange() {
        guard let ctx else { return }
        let err = signet_context_notify_change(ctx, 0x0605, 0) // TID_RT_DEVICE_LABEL, root
        append("notify_change TID_RT_DEVICE_LABEL: " + (err == SIGNET_OK ? "OK" : SignetError("Notify", err).description))
    }

    private func create() throws {
        let open = settings.mode == .open
        var k0 = try settings.rootKey()
        defer { wipe(&k0) }
        let n = min(8, max(1, endpointCount))

        responders = (1...n).map {
            DeviceRDMResponder(uid: uid(for: $0), label: "\(modelName) \($0)", softwareLabel: firmwareLabel)
        }
        params = [Self.key(Self.tidTestLevel, 0): [0x80], Self.key(Self.tidTestNote, 0): Array("hello".utf8)]
        snapshot = nil
        acceptsNetwork = acceptNetwork
        identifying = Array(repeating: false, count: n)
        live = Array(repeating: Live(), count: n)

        // Every buffer the config points at lives until create returns (the library copies them).
        var allocations: [UnsafeMutableRawPointer] = []
        defer { allocations.forEach { $0.deallocate() } }
        func keep<T>(_ items: [T]) -> UnsafeMutablePointer<T> {
            let p = UnsafeMutablePointer<T>.allocate(capacity: max(1, items.count))
            p.initialize(from: items, count: items.count)
            allocations.append(UnsafeMutableRawPointer(p))
            return p
        }
        func keep(_ s: String) -> UnsafePointer<CChar> { UnsafePointer(keep(Array(s.utf8CString))) }
        let me = Unmanaged.passUnretained(self).toOpaque()

        let endpoints: [signet_endpoint_info_t] = (1...n).map { i in
            var e = signet_endpoint_info_t()
            e.struct_size = MemoryLayout<signet_endpoint_info_t>.size
            e.endpoint = UInt16(i)
            e.universe = UInt16(clamping: universes[i - 1])
            e.capability = (0, 0, 0, 0x15) // consume TID_LEVEL | consume RDM | virtual endpoint
            e.direction = 0x05 // consumer, RDM enabled
            return e
        }
        let patches: [signet_endpoint_patch_t] = endpoints.map {
            var p = signet_endpoint_patch_t()
            p.struct_size = MemoryLayout<signet_endpoint_patch_t>.size
            p.endpoint = $0.endpoint
            p.universe = $0.universe
            return p
        }

        var info = signet_device_info_t()
        info.struct_size = MemoryLayout<signet_device_info_t>.size
        info.soem_code = 0x7FF0_0000 | UInt32(DeviceRDMResponder.modelID) // upper half = ESTA prototyping ID
        info.device_label = label.isEmpty ? nil : keep(label) // factory default; a persisted label wins
        info.role_capability = UnsafePointer(keep([0, 0, 0, open ? 0x81 : 0x01] as [UInt8])) // Node (+ Open Mode)
        info.endpoint_count = UInt16(n)
        info.virtual_endpoints = UnsafePointer(keep(endpoints.map(\.endpoint)))
        info.virtual_endpoint_count = n
        info.firmware_version_id = DeviceRDMResponder.softwareID
        info.firmware_version_label = firmwareLabel.isEmpty ? nil : keep(firmwareLabel)
        info.model_name = keep(modelName)
        info.extra_supported_tids = UnsafePointer(keep([Self.tidTestLevel, Self.tidTestNote]))
        info.extra_supported_tids_count = 2
        info.endpoints = UnsafePointer(keep(endpoints))

        var params = signet_param_handler_t()
        params.struct_size = MemoryLayout<signet_param_handler_t>.size
        params.user_data = me
        params.validate_set = { ud, tid, ep, value, len in FakeDevice.from(ud).validate(tid, ep, bytes(value, len)) }
        params.apply_set = { ud, tid, ep, value, len, changed in
            FakeDevice.from(ud).apply(tid, ep, bytes(value, len), changed)
        }
        params.get = { ud, tid, ep, buf, cap, outLen in FakeDevice.from(ud).get(tid, ep, buf, cap, outLen) }
        params.begin_set_transaction = { ud in FakeDevice.from(ud).begin() }
        params.commit_set_transaction = { ud in FakeDevice.from(ud).commit() }
        params.abort_set_transaction = { ud in FakeDevice.from(ud).abort() }

        var rdm = signet_rdm_handler_t()
        rdm.struct_size = MemoryLayout<signet_rdm_handler_t>.size
        rdm.user_data = me
        rdm.on_command = { ud, ep, frame, len in FakeDevice.from(ud).rdmCommand(ep, bytes(frame, len)) }
        rdm.on_tod_control = { ud, ep, command in FakeDevice.from(ud).todControl(ep, command) }
        rdm.on_blocked_set = { ud, ep, pid, frame, len in FakeDevice.from(ud).blockedSet(ep, pid, bytes(frame, len)) }

        var offboard = signet_offboard_handler_t()
        offboard.struct_size = MemoryLayout<signet_offboard_handler_t>.size
        offboard.user_data = me
        offboard.on_offboarded = { ud in FakeDevice.from(ud).post("OFFBOARDED: keys wiped, now beaconing. Restart in Offboarded mode to recover.") }

        var network = signet_network_handler_t()
        network.struct_size = MemoryLayout<signet_network_handler_t>.size
        network.user_data = me
        network.propose = { ud, cfg in FakeDevice.from(ud).propose(cfg) }
        network.apply = { ud, cfg in
            FakeDevice.from(ud).post("network apply \(networkText(cfg)) (logged only, host untouched)")
            return SIGNET_OK
        }
        network.commit = { ud in FakeDevice.from(ud).post("network commit (rollback verified)") }
        network.revert = { ud in FakeDevice.from(ud).post("network revert (rollback window expired)") }

        scopeC = strdup(settings.scopeOrDefault)
        var cfg = signet_context_config_t()
        cfg.struct_size = MemoryLayout<signet_context_config_t>.size
        cfg.identity.struct_size = MemoryLayout<signet_identity_t>.size
        cfg.identity.tuid = Identity.tuple(tuid)
        cfg.identity.scope = UnsafePointer(scopeC)
        cfg.identity.mfg_code = 0x7FF0 // so proprietary TIDs under Mfg-Code 0x7FF0 reach us (PF §10.1.2)
        cfg.identity.security_mode = settings.mode.raw
        cfg.persistence = UnsafePointer(keep([filePersistence])) // Session-ID + CHANGE_COUNT, both modes
        cfg.device_info = UnsafePointer(keep([info]))
        cfg.param_handler = UnsafePointer(keep([params]))
        cfg.rdm_handler = UnsafePointer(keep([rdm]))
        cfg.offboard_handler = UnsafePointer(keep([offboard]))
        cfg.network_handler = UnsafePointer(keep([network]))
        cfg.endpoint_patches = UnsafePointer(keep(patches))
        cfg.endpoint_patch_count = n
        cfg.multicast_interface = try settings.interfaceAddress().map { UnsafePointer(keep([$0])) }
        // App uptime is not physical power-on: keep the §7.7.1 window shut unless asked.
        cfg.power_on_elapsed_s = freshPowerOn ? 0 : 300

        let err = k0.withUnsafeMutableBufferPointer { keyPtr in
            if !open {
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
        try check("Device creation", err)
        ctx = signet_device_node(device)
        try check("Runtime start", signet_device_runtime_start(device))
    }

    /// PF §6.7: an RDM responder's UID is its TUID. Endpoint 1 uses it as is;
    /// further endpoints count up the Device ID so each responder is distinct.
    private func uid(for endpoint: Int) -> [UInt8] {
        let id = tuid[2...].reduce(UInt32(0)) { $0 << 8 | UInt32($1) } &+ UInt32(endpoint - 1)
        return Array(tuid[..<2]) + withUnsafeBytes(of: id.bigEndian, Array.init)
    }

    private func readLevels() {
        guard let ctx else { return }
        var buf = [UInt8](repeating: 0, count: 512)
        for i in live.indices {
            var frame = signet_universe_frame_t()
            frame.struct_size = MemoryLayout<signet_universe_frame_t>.size
            guard signet_context_read_universe(ctx, UInt16(clamping: universes[i]), &buf, buf.count, &frame) == SIGNET_OK
            else { continue }
            live[i] = Live(levels: Array(buf.prefix(32)), slots: Int(frame.slot_count), sources: Int(frame.source_count))
        }
    }

    // MARK: - Parameter handler (runtime thread)

    private static func key(_ tid: UInt16, _ ep: UInt16) -> UInt32 { UInt32(tid) << 16 | UInt32(ep) }

    private func validate(_ tid: UInt16, _ ep: UInt16, _ value: [UInt8]) -> signet_error_t {
        // The library already checked every standard TID; only ours need rules.
        let ok = switch tid {
        case Self.tidTestLevel: ep == 0 && value.count == 1
        case Self.tidTestNote: ep == 0 && (1...32).contains(value.count)
        default: true
        }
        post("validate \(Self.describe(tid, ep, value)) → \(ok ? "accept" : "reject")")
        return ok ? SIGNET_OK : SIGNET_ERR_INVALID_ARGUMENT
    }

    private func apply(_ tid: UInt16, _ ep: UInt16, _ value: [UInt8], _ changed: UnsafeMutablePointer<Int32>?) -> signet_error_t {
        let k = Self.key(tid, ep)
        let differs = params[k] != value
        params[k] = value
        changed?.pointee = Int32(differs ? SIGNET_PARAM_CHANGED : SIGNET_PARAM_UNCHANGED)
        post("apply \(Self.describe(tid, ep, value))\(differs ? "" : " (unchanged)")")
        return SIGNET_OK
    }

    private func get(_ tid: UInt16, _ ep: UInt16, _ buf: UnsafeMutablePointer<UInt8>?, _ cap: Int,
                     _ outLen: UnsafeMutablePointer<Int>?) -> signet_error_t {
        guard let value = params[Self.key(tid, ep)] else {
            post("get \(Self.describe(tid, ep, [])) → unsupported")
            return SIGNET_ERR_UNSUPPORTED
        }
        guard value.count <= cap, let buf else { return SIGNET_ERR_BUFFER_TOO_SMALL }
        buf.update(from: value, count: value.count)
        outLen?.pointee = value.count
        post("get \(Self.describe(tid, ep, value))")
        return SIGNET_OK
    }

    private func begin() -> signet_error_t {
        snapshot = params
        post("SET transaction begin")
        return SIGNET_OK
    }

    private func commit() -> signet_error_t {
        snapshot = nil
        post("SET transaction commit")
        // Mirror Manager edits into the config so the UI (and the next start) follow them.
        let label = params[Self.key(0x0605, 0)].map { String(decoding: $0.dropFirst(), as: UTF8.self) }
        let patched = responders.indices.map { params[Self.key(0x0901, UInt16($0 + 1))] } // TID_EP_UNIVERSE
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            if let label { self.label = label }
            for (i, v) in patched.enumerated() where v?.count == 2 { self.universes[i] = Int(v![0]) << 8 | Int(v![1]) }
        }
        return SIGNET_OK
    }

    private func abort() {
        if let snapshot { params = snapshot }
        snapshot = nil
        post("SET transaction abort (snapshot restored)")
    }

    private func propose(_ cfg: UnsafePointer<signet_network_config_t>?) -> signet_error_t {
        post("network propose \(networkText(cfg)) → \(acceptsNetwork ? "accept" : "refuse")")
        return acceptsNetwork ? SIGNET_OK : SIGNET_ERR_UNSUPPORTED
    }

    private static func describe(_ tid: UInt16, _ ep: UInt16, _ value: [UInt8]) -> String {
        String(format: "tid 0x%04X ep %d", tid, ep) + (value.isEmpty ? "" : " = \(Identity.hex(value))")
    }

    // MARK: - RDM handler (runtime thread)

    private func rdmCommand(_ ep: UInt16, _ frame: [UInt8]) {
        post("RDM ep\(ep) ← \(DeviceRDMResponder.describe(frame))")
        guard let ctx, (1...responders.count).contains(Int(ep)) else { return }
        guard let reply = responders[Int(ep) - 1].handle(frame) else { return post("RDM ep\(ep) no response (not ours)") }
        send(ep, reply, SIGNET_RDM_TX_AUTO, ctx)
        if let note = responders[Int(ep) - 1].notification(after: reply) { send(ep, note, SIGNET_RDM_TX_BACKOFF, ctx) }
        let identify = responders.map(\.identify)
        DispatchQueue.main.async { [weak self] in self?.identifying = identify }
    }

    private func todControl(_ ep: UInt16, _ command: UInt8) {
        guard let ctx, (1...responders.count).contains(Int(ep)) else { return }
        let uid = responders[Int(ep) - 1].uid // virtual: discovery always finds just us
        let err = signet_context_send_rdm_tod(ctx, ep, uid, 1)
        post("RDM ep\(ep) ToD \(command == 0 ? "send" : "flush") → \(Identity.hex(uid)) rc \(err.rawValue)")
    }

    /// PF §10.5.3: network-PID SETs at a virtual endpoint get NR_WRITE_PROTECT.
    private func blockedSet(_ ep: UInt16, _ pid: UInt16, _ frame: [UInt8]) {
        post(String(format: "RDM ep%d blocked network SET PID 0x%04X", ep, pid))
        guard let ctx, (1...responders.count).contains(Int(ep)), frame.count >= 24 else { return }
        send(ep, DeviceRDMResponder.nack(frame, from: responders[Int(ep) - 1].uid, reason: 0x0004), SIGNET_RDM_TX_AUTO, ctx)
    }

    private func send(_ ep: UInt16, _ frame: [UInt8], _ schedule: signet_rdm_schedule_t, _ ctx: OpaquePointer) {
        let err = signet_context_send_rdm_response(ctx, ep, frame, frame.count, schedule)
        post("RDM ep\(ep) → \(DeviceRDMResponder.describe(frame))" + (err == SIGNET_OK ? "" : " send rc \(err.rawValue)"))
    }

    // MARK: - Log

    private static func from(_ ud: UnsafeMutableRawPointer?) -> FakeDevice { Unmanaged.fromOpaque(ud!).takeUnretainedValue() }

    /// From any thread; the log is main-thread state.
    private func post(_ line: String) {
        DispatchQueue.main.async { [weak self] in self?.append(line) }
    }

    private func append(_ line: String) {
        log.append(String(format: "%8.2f  ", Date().timeIntervalSince(launched)) + line)
        if log.count > 500 { log.removeFirst(log.count - 500) }
    }

    // MARK: - Self-test

    static func selfTest(settings: SecuritySettings) -> Bool {
        if let problem = rdmSelfTest() {
            print("  device rdm: \(problem)")
            return false
        }
        let d = FakeDevice(settings: settings)
        for run in 1...2 { // the second boot reloads the persisted Session-ID record
            d.start()
            RunLoop.main.run(until: Date().addingTimeInterval(1))
            // poll refuses with STATE exactly while the runtime task owns the device.
            let alive = d.ctx.map { signet_context_poll($0, 0) == SIGNET_ERR_STATE } ?? false
            let ok = d.running && alive
            if !ok { print("  device boot #\(run): \(d.status)\(d.running ? " (runtime not running)" : "")") }
            d.stop()
            if !ok { return false }
        }
        return true
    }

    /// Hand-built GET DEVICE_INFO → ACK, unknown PID → NACK, bad checksum → silence.
    private static func rdmSelfTest() -> String? {
        let me: [UInt8] = [0x7F, 0xF0, 0x80, 0x00, 0x00, 0x01], controller: [UInt8] = [0x7F, 0xF0, 0x12, 0x34, 0x56, 0x78]
        var r = DeviceRDMResponder(uid: me, label: "x", softwareLabel: "v1")
        func request(pid: (UInt8, UInt8)) -> [UInt8] {
            let body: [UInt8] = [0xCC, 0x01, 24] + me + controller + [0x07, 0x01, 0x00, 0x00, 0x00, 0x20, pid.0, pid.1, 0x00]
            let sum = body.reduce(0) { $0 + Int($1) }
            return body + [UInt8(sum >> 8 & 0xFF), UInt8(sum & 0xFF)]
        }
        guard let info = r.handle(request(pid: (0x00, 0x60))) else { return "no reply to GET DEVICE_INFO" }
        let sum = info.prefix(43).reduce(0) { $0 + Int($1) }
        guard info.count == 45, info[2] == 43, info[23] == 19 else { return "DEVICE_INFO length \(info.count)" }
        guard info[20] == 0x21, info[16] == 0x00, info[15] == 0x07 else { return "DEVICE_INFO CC/type/TN wrong" }
        guard Array(info[3..<9]) == controller, Array(info[9..<15]) == me else { return "DEVICE_INFO UIDs not swapped" }
        guard Int(info[43]) << 8 | Int(info[44]) == sum & 0xFFFF else { return "DEVICE_INFO checksum wrong" }
        guard let nack = r.handle(request(pid: (0x12, 0x34))), nack[16] == 0x02, nack.suffix(4).prefix(2) == [0, 0]
        else { return "unknown PID not NACKed UNKNOWN_PID" }
        var bad = request(pid: (0x00, 0x60))
        bad[bad.count - 1] &+= 1
        return r.handle(bad) == nil ? nil : "answered a frame with a bad checksum"
    }
}

private func bytes(_ p: UnsafePointer<UInt8>?, _ len: Int) -> [UInt8] {
    p.map { Array(UnsafeBufferPointer(start: $0, count: len)) } ?? []
}

private func networkText(_ cfg: UnsafePointer<signet_network_config_t>?) -> String {
    guard let c = cfg?.pointee else { return "(none)" }
    let address = withUnsafeBytes(of: c.address) { Array($0.prefix(c.family == 4 ? 4 : 16)) }
    let text = c.family == 4 ? address.map(String.init).joined(separator: ".") : Identity.hex(address)
    return "IPv\(c.family) mode \(c.mode) address \(text)"
}

// MARK: - View

/// Device: a fake fixture that external Managers find and configure, drawn as one instrument.
/// Main panel uses plain names; parameter codes and hex stay in Debug with the handler log.
struct DeviceView: View {
    @ObservedObject var device: FakeDevice
    @ObservedObject private var settings: SecuritySettings
    @State private var mode = "panel"

    init(device: FakeDevice) {
        self.device = device
        settings = device.settings
    }

    /// Ports on the display: the live ones while running, the configured count while stopped.
    private var portCount: Int { device.running ? device.live.count : min(8, max(1, device.endpointCount)) }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            controlStrip
            display
            HStack {
                ModeKeys(options: [("panel", "Panel"), ("debug", "Debug")], selection: $mode)
                Spacer()
            }
            ScrollView {
                Group {
                    if mode == "debug" { debug } else { panel }
                }
                .padding(.bottom, 12)
            }
        }
    }

    // MARK: Control strip and display

    private var statusText: String {
        guard device.running else { return device.status }
        let n = device.live.count
        return "Running · \(n) port\(n == 1 ? "" : "s") · \(settings.mode.rawValue) Mode · scope \(settings.scopeOrDefault)"
    }

    private var controlStrip: some View {
        HStack(spacing: 10) {
            if device.running {
                Button("Stop") { device.stop() }
                    .buttonStyle(SoftKeyStyle(lamp: .lampOnline))
                    .keyboardShortcut(.return, modifiers: .command)
            } else {
                Button("Start device") { device.start() }
                    .buttonStyle(SoftKeyStyle(prominent: true))
                    .keyboardShortcut(.return, modifiers: .command)
                    .disabled(!settings.ready)
                    .help(settings.ready ? "Start answering Managers on the network" : "Fix the passphrase first")
            }
            Text(statusText)
                .font(.system(size: 11.5))
                .foregroundStyle(device.running || device.status == "Stopped" ? Color.silk : Color.lampFault)
                .lineLimit(1).truncationMode(.middle)
                .textSelection(.enabled)
            Spacer()
        }
    }

    private var display: some View {
        HStack(alignment: .center, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text(device.modelName.isEmpty ? "Unnamed model" : device.modelName)
                    .font(.system(size: 22, weight: .semibold)).foregroundStyle(Color.ink)
                Text(device.label.isEmpty ? "No label" : device.label)
                    .font(.system(size: 13, weight: .medium)).foregroundStyle(Color.inkDim)
                HStack(spacing: 6) {
                    Silkscreen("Device ID")
                    Text(Identity.hex(device.tuid)).font(.system(size: 11.5, design: .monospaced)).foregroundStyle(Color.silk)
                        .textSelection(.enabled)
                }
            }
            Spacer()
            VStack(spacing: 5) {
                Lamp(color: device.running ? .lampOnline : nil, size: 10)
                Silkscreen("Running")
            }
            .frame(minWidth: 52)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(device.running ? "Running" : "Stopped")
            portLamps
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
        .background(
            RoundedRectangle(cornerRadius: 7, style: .continuous).fill(Color.readoutWindow)
                .overlay(RoundedRectangle(cornerRadius: 7, style: .continuous).strokeBorder(Color.black.opacity(0.7), lineWidth: 1))
                .overlay(alignment: .bottom) { Rectangle().fill(Color.brandStripe).frame(height: 2).padding(.horizontal, 1) }
                .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
        )
    }

    /// Two rows of lamps, one column per port: levels arriving, and identify from a Manager.
    private var portLamps: some View {
        Grid(horizontalSpacing: 12, verticalSpacing: 6) {
            GridRow {
                Silkscreen("Port").gridColumnAlignment(.trailing)
                ForEach(0..<portCount, id: \.self) { i in
                    Text("\(i + 1)").font(.system(size: 10.5, weight: .semibold, design: .monospaced)).foregroundStyle(Color.silk)
                }
            }
            GridRow {
                Silkscreen("Levels")
                ForEach(0..<portCount, id: \.self) { i in
                    let on = receiving(i)
                    Lamp(color: on ? .lampOnline : nil, size: 10)
                        .accessibilityHidden(false)
                        .accessibilityLabel("Port \(i + 1) levels: \(on ? "receiving" : "none")")
                }
            }
            GridRow {
                Silkscreen("Identify")
                ForEach(0..<portCount, id: \.self) { i in
                    let on = identifying(i)
                    IdentifyLamp(on: on)
                        .accessibilityLabel("Port \(i + 1) identify: \(on ? "on" : "off")")
                }
            }
        }
    }

    private func receiving(_ i: Int) -> Bool { device.live.indices.contains(i) && device.live[i].sources > 0 }
    private func identifying(_ i: Int) -> Bool { device.identifying.indices.contains(i) && device.identifying[i] }

    // MARK: Panel

    private var panel: some View {
        VStack(alignment: .leading, spacing: 12) {
            identity
            ports
            behaviour
        }
    }

    private var identity: some View {
        ModulePanel("Identity") {
            Button("Notify change") { device.notifyLabelChange() }
                .buttonStyle(.softKey)
                .disabled(!device.running)
                .help("Tell Managers the label changed so they read it again")
        } content: {
            ReadoutRow(label: "Model name", value: device.modelName.isEmpty ? nil : device.modelName,
                       set: .text(initial: device.modelName) { text, done in
                           guard !text.isEmpty else { return done(.refused("The model name can't be empty")) }
                           device.modelName = text
                           done(.latched)
                       },
                       enabled: !device.running)
            ReadoutRow(label: "Label", value: device.label.isEmpty ? nil : device.label,
                       set: .text(initial: device.label) { text, done in
                           guard device.running else { device.label = text; return done(.latched) }
                           guard !text.isEmpty else { return done(.refused("The label can't be empty while running")) }
                           device.label = text
                           done(device.applyLabel() ? .latched : .refused("The device refused this label"))
                       })
            ReadoutRow(label: "Firmware", value: device.firmwareLabel.isEmpty ? nil : device.firmwareLabel,
                       set: .text(initial: device.firmwareLabel) { text, done in
                           device.firmwareLabel = text
                           done(.latched)
                       },
                       enabled: !device.running)
            if device.running {
                note("Model name and firmware are fixed while running. Stop the device to change them.")
            }
        }
    }

    private var ports: some View {
        ModulePanel("Ports") {
            ReadoutRow(label: "Port count", value: "\(portCount)",
                       set: .choices((1...8).map(String.init)) { i, done in
                           device.endpointCount = i + 1
                           done(.latched)
                       },
                       enabled: !device.running)
            ForEach(0..<portCount, id: \.self) { i in
                Divider().overlay(Color.black.opacity(0.4)).padding(.vertical, 2)
                ReadoutRow(label: "Port \(i + 1) universe", value: "\(device.universes[i])",
                           set: .number(initial: "\(device.universes[i])", range: 1...63999) { text, done in
                               guard let u = Int(text.trimmingCharacters(in: .whitespaces)), (1...63999).contains(u)
                               else { return done(.refused("A universe is a number from 1 to 63999")) }
                               device.universes[i] = u
                               done(.latched)
                           },
                           enabled: !device.running)
                levelsRow(i)
            }
        }
    }

    private func levelsRow(_ i: Int) -> some View {
        let live = device.live.indices.contains(i) ? device.live[i] : nil
        return HStack(spacing: 8) {
            Text("Port \(i + 1) levels")
                .font(.system(size: 12.5, weight: .medium)).foregroundStyle(Color.inkDim)
                .frame(width: ReadoutRow.labelWidth, alignment: .leading)
            LevelStrip(levels: live?.levels ?? [])
                .accessibilityLabel("Port \(i + 1) levels, first 32 channels")
            VStack(alignment: .leading, spacing: 3) {
                miniReadout("Channels", live.map { "\($0.slots)" })
                miniReadout("Sources", live.map { "\($0.sources)" })
            }
            .frame(width: ReadoutRow.keyWidth * 2 + 8)
        }
        .frame(maxWidth: 860, alignment: .leading)
    }

    private func miniReadout(_ title: String, _ value: String?) -> some View {
        HStack(spacing: 4) {
            Silkscreen(title)
            Spacer(minLength: 2)
            Text(value ?? "—").font(.system(size: 12, weight: .medium, design: .monospaced))
                .foregroundStyle(value == nil ? Color.silk : Color.ink)
        }
        .accessibilityElement(children: .combine)
    }

    private var behaviour: some View {
        ModulePanel("Behaviour") {
            ReadoutRow(label: "Simulate fresh power-on", value: device.freshPowerOn ? "On" : "Off",
                       set: .choices(["Off", "On"]) { i, done in device.freshPowerOn = i == 1; done(.latched) },
                       enabled: !device.running)
            note("On: a Manager can offboard the device for 300 s after start, as after a real power-on.")
            ReadoutRow(label: "Accept network changes", value: device.acceptNetwork ? "On" : "Off",
                       set: .choices(["Off", "On"]) { i, done in device.acceptNetwork = i == 1; done(.latched) },
                       enabled: !device.running)
            note("On: address changes from a Manager are accepted and logged. This Mac's network is never touched.")
        }
    }

    private func note(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 11)).foregroundStyle(Color.silk)
            .padding(.leading, ReadoutRow.labelWidth + 8)
            .fixedSize(horizontal: false, vertical: true)
    }

    // MARK: Debug

    private var debug: some View {
        ModulePanel("Handler log") {
            Text("\(device.log.count)").font(.system(size: 11, design: .monospaced)).foregroundStyle(Color.silk)
            Button("Clear") { device.clearLog() }.buttonStyle(.softKey).disabled(device.log.isEmpty)
        } content: {
            if device.log.isEmpty {
                Text("No handler calls yet. Start the device and point a Manager at it.")
                    .font(.system(size: 12)).foregroundStyle(Color.silk)
            }
            LazyVStack(alignment: .leading, spacing: 2) {
                ForEach(Array(device.log.reversed().enumerated()), id: \.offset) { _, line in
                    Text(line).font(.system(size: 11, design: .monospaced)).foregroundStyle(Color.inkDim)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .accessibilityLabel("Handler log, newest first")
        }
    }
}

/// First 32 channels as teal bars in a recessed window.
private struct LevelStrip: View {
    let levels: [UInt8]

    var body: some View {
        HStack(alignment: .bottom, spacing: 2) {
            ForEach(0..<32, id: \.self) { i in
                let v = i < levels.count ? levels[i] : 0
                Rectangle()
                    .fill(v == 0 ? Color.silk.opacity(0.18) : Color.lampLatch)
                    .frame(maxWidth: .infinity)
                    .frame(height: max(1, 26 * CGFloat(v) / 255))
            }
        }
        .frame(height: 26, alignment: .bottom)
        .padding(.horizontal, 8).padding(.vertical, 5)
        .frame(maxWidth: .infinity)
        .background(
            RoundedRectangle(cornerRadius: 4, style: .continuous).fill(Color.readoutWindow)
                .overlay(RoundedRectangle(cornerRadius: 4, style: .continuous).strokeBorder(Color.black.opacity(0.7), lineWidth: 1))
                .shadow(color: .white.opacity(0.05), radius: 0, y: 1)
        )
        .accessibilityElement()
        .accessibilityValue(levels.isEmpty ? "no levels" : levels.map(String.init).joined(separator: ", "))
    }
}

/// Blinks teal while a Manager has identify on; holds steady under reduced motion.
private struct IdentifyLamp: View {
    let on: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Group {
            if on && !reduceMotion {
                TimelineView(.periodic(from: .now, by: 0.4)) { context in
                    let lit = Int(context.date.timeIntervalSinceReferenceDate / 0.4) % 2 == 0
                    Lamp(color: lit ? .lampLatch : nil, size: 10)
                }
            } else {
                Lamp(color: on ? .lampLatch : nil, size: 10)
            }
        }
        .accessibilityElement()
    }
}
