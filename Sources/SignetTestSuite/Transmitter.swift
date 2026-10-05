import CSignet
import Foundation

/// One standalone Sig-Net Sender (no discovery/management) transmitting
/// `count` consecutive governed universes from `universe` on endpoint 1. The
/// library runtime paces output; the UI only hands it the current levels.
final class Transmitter: ObservableObject {
    enum Pattern: String, CaseIterable, Identifiable {
        case off = "Off", chase = "Chase", ramp = "Ramp", random = "Random"
        var id: Self { self }
    }

    /// PF §11.2.5 rate codes 0x00–0x0A, in code order.
    static let timecodeRates = ["24", "25", "29.97 DF", "30", "48", "50", "59.94 DF", "60", "100", "119.88 DF", "120"]

    let settings: SecuritySettings
    @Published var universe = 1 // first (primary) universe
    @Published var count = 1 { didSet { selected = min(selected, count - 1) } }
    @Published var maxFps = 44
    /// Offset of the universe the fader bank edits; 0 = primary.
    @Published var selected = 0 { didSet { if selected != oldValue { levels = bank[selected] } } }
    /// Levels of the selected universe.
    @Published var levels = [UInt8](repeating: 0, count: 512) { didSet { bank[selected] = levels; push(selected) } }
    @Published var master: Double = 255 { didSet { pushAll() } }
    @Published var sendPriority = false { didSet { pushAll() } }
    @Published var priorities = [Int](repeating: 100, count: 16) { didSet { pushAll() } }
    @Published var sync = false { didSet { applySync() } }
    @Published var preview = false
    @Published var pattern = Pattern.off
    @Published var patternSpeed = 8.0 // steps per second
    @Published var tcStream = 1
    @Published var tcRate: UInt8 = 0x01
    @Published private(set) var tcRunning = false
    @Published private(set) var tcDisplay = "00:00:00:00"
    @Published private(set) var syncFps: UInt16 = 0
    @Published private(set) var running = false
    @Published private(set) var status = "Stopped"
    @Published private(set) var sendFailures: UInt64 = 0

    let tuid: [UInt8]
    private var bank = [[UInt8]](repeating: [UInt8](repeating: 0, count: 512), count: 16)
    private var device: OpaquePointer?
    private var sender: OpaquePointer?
    private var scopeC: UnsafeMutablePointer<CChar>?
    private var tickTimer: Timer?
    private var ticks = 0
    private var patternPhase = 0.0

    // Timecode generator state: touched only on tcQueue.
    private let tcQueue = DispatchQueue(label: "signet.timecode")
    private var tcTimer: DispatchSourceTimer?
    private var tcBase = 0 // frames counted before the current run
    private var tcStart: UInt64 = 0 // uptime ns at the current run's start
    private var tcLast = -1

    /// `role` picks the persisted TUID; distinct roles are distinct merge sources.
    init(settings: SecuritySettings, role: String = "sender") {
        self.settings = settings
        tuid = Identity.tuid(role)
    }

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
        let range = count == 1 ? "universe \(universe)" : "universes \(universe)–\(universe + count - 1)"
        status = "Transmitting \(range) · \(settings.mode.rawValue) Mode · scope \(settings.scopeOrDefault)"
        _ = signet_sender_synchronized_fps(sender, &syncFps)
        applySync()
        tickTimer = Timer(timeInterval: 1.0 / 30, repeats: true) { [weak self] _ in self?.tick() }
        RunLoop.main.add(tickTimer!, forMode: .common) // keep ticking while a fader is dragged
    }

    private func create() throws {
        let secure = settings.mode == .secure
        var k0 = try settings.rootKey()
        defer { wipe(&k0) }

        scopeC = strdup(settings.scopeOrDefault)
        var persistence = filePersistence
        var endpoint: UInt16 = 1
        let governed = (0..<count).map { signet_governed_universe_t(endpoint: 1, universe: UInt16(clamping: universe + $0)) }

        var cfg = signet_sender_config_t()
        cfg.struct_size = MemoryLayout<signet_sender_config_t>.size
        cfg.identity.struct_size = MemoryLayout<signet_identity_t>.size
        cfg.identity.tuid = Identity.tuple(tuid)
        cfg.identity.scope = UnsafePointer(scopeC)
        cfg.identity.security_mode = settings.mode.raw
        cfg.endpoint_count = 1
        cfg.governed_count = governed.count
        cfg.max_fps = UInt16(clamping: maxFps)

        let err = try settings.withInterface { nic in
            cfg.multicast_interface = nic
            return withUnsafePointer(to: &persistence) { persistencePtr in
                withUnsafePointer(to: &endpoint) { endpointPtr in
                    governed.withUnsafeBufferPointer { governedPtr in
                        k0.withUnsafeMutableBufferPointer { keyPtr in
                            cfg.endpoints = endpointPtr
                            cfg.governed = governedPtr.baseAddress
                            if secure {
                                cfg.persistence = persistencePtr // session-ID record, required in Secure Mode
                                cfg.root_key = keyPtr.baseAddress // wiped by signet_device_create
                                cfg.root_key_len = keyPtr.count
                            }
                            return withUnsafePointer(to: &cfg) { cfgPtr in
                                var deviceCfg = signet_device_config_t()
                                deviceCfg.struct_size = MemoryLayout<signet_device_config_t>.size
                                deviceCfg.roles = SIGNET_DEVICE_ROLE_SENDER.rawValue
                                deviceCfg.sender = cfgPtr
                                return signet_device_create(&deviceCfg, &device)
                            }
                        }
                    }
                }
            }
        }
        try check("Device creation", err)
        sender = signet_device_sender(device)
        pushAll() // first frames before the runtime starts pacing
        try check("Runtime start", signet_device_runtime_start(device))
    }

    func stop() {
        stopTimecode()
        tcQueue.sync {} // an in-flight timecode send finishes before the sender goes away
        tickTimer?.invalidate()
        tickTimer = nil
        if let device {
            _ = signet_device_runtime_stop(device)
            _ = signet_device_destroy(device)
        }
        device = nil
        sender = nil
        free(scopeC)
        scopeC = nil
        if running {
            status = "Stopped"
            settings.deviceStopped()
        }
        running = false
        sendFailures = 0
    }

    /// Sets every channel of the selected universe.
    func setAll(_ value: UInt8) {
        levels = [UInt8](repeating: value, count: levels.count)
    }

    private func output(_ i: Int) -> [UInt8] { bank[i].map { UInt8((Double($0) * master / 255).rounded()) } }

    private func push(_ i: Int) {
        guard let sender, i < count else { return }
        let out = output(i)
        let priority = sendPriority ? [UInt8(clamping: priorities[i])] : [] // empty = no TID_PRIORITY
        let err = signet_sender_set_levels(sender, 1, UInt16(clamping: universe + i), out, out.count,
                                           priority.isEmpty ? nil : priority, priority.count)
        if err != SIGNET_OK { status = SignetError("Set levels", err).description }
    }

    private func pushAll() { (0..<count).forEach(push) }

    private func applySync() {
        guard let sender else { return }
        let err = sync ? signet_sender_schedule_sync(sender, 1) : signet_sender_sync_release(sender, 1)
        if err != SIGNET_OK { status = SignetError("Sync", err).description }
    }

    /// 30 Hz main-thread tick: test pattern, preview at 10 Hz, stats at 1 Hz.
    private func tick() {
        guard let sender else { return }
        ticks += 1
        if pattern != .off {
            let before = Int(patternPhase)
            patternPhase += patternSpeed / 30
            let step = Int(patternPhase)
            if step != before {
                switch pattern {
                case .off: break
                case .chase: levels = (0..<512).map { $0 == step % 512 ? 255 : 0 }
                case .ramp: levels = [UInt8](repeating: UInt8(truncatingIfNeeded: step * 8), count: 512) // 32-step sawtooth
                case .random: levels = (0..<512).map { _ in .random(in: 0...255) }
                }
            }
        }
        if preview, ticks % 3 == 0 {
            let out = output(selected)
            let err = signet_sender_send_preview(sender, 1, UInt16(clamping: universe + selected), out, out.count)
            if err != SIGNET_OK { status = SignetError("Preview", err).description }
        }
        if ticks % 30 == 0 {
            var n: UInt64 = 0
            if signet_sender_send_failures(sender, &n) == SIGNET_OK, n != sendFailures { sendFailures = n }
        }
    }

    // MARK: - Timecode generator

    func startTimecode() {
        guard let sender, !tcRunning else { return }
        tcRunning = true
        let stream = UInt16(clamping: tcStream), rate = tcRate
        let millifps = UInt64(signet_timecode_rate_millifps(rate))
        tcQueue.async { [self] in
            tcStart = DispatchTime.now().uptimeNanoseconds
            tcLast = -1
            let timer = DispatchSource.makeTimerSource(queue: tcQueue)
            // Frame index comes from elapsed time, so timer jitter never accumulates.
            timer.schedule(deadline: .now(), repeating: .nanoseconds(Int(1_000_000_000_000 / millifps)), leeway: .microseconds(500))
            timer.setEventHandler { [self] in
                let n = tcBase + Int((DispatchTime.now().uptimeNanoseconds - tcStart) * millifps / 1_000_000_000_000)
                guard n != tcLast else { return }
                tcLast = n
                let tc = Self.timecode(frame: n, rate: rate)
                let err = signet_sender_send_timecode(sender, 1, stream, tc, tc.count)
                let text = Self.format(tc)
                DispatchQueue.main.async {
                    self.tcDisplay = text
                    if err != SIGNET_OK { self.status = SignetError("Timecode", err).description }
                }
            }
            tcTimer = timer
            timer.resume()
        }
    }

    func stopTimecode() {
        tcRunning = false
        tcQueue.async { [self] in
            tcTimer?.cancel()
            tcTimer = nil
            if tcLast >= 0 { tcBase = tcLast + 1 }
            tcLast = -1
        }
    }

    func resetTimecode() {
        tcQueue.async { [self] in
            tcBase = 0
            tcStart = DispatchTime.now().uptimeNanoseconds
            tcLast = -1
        }
        tcDisplay = "00:00:00:00"
    }

    /// PF §11.2.5 5-byte value for absolute frame `n` since 00:00:00:00.
    /// Labels per second are the rate maximum + 1 (29.97 counts 0–29); drop-frame
    /// rates skip 2/4/8 labels at each minute not divisible by ten (SMPTE 12M).
    static func timecode(frame n: Int, rate: UInt8) -> [UInt8] {
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

    private static func format(_ tc: [UInt8]) -> String {
        String(format: "%02d:%02d:%02d%@%02d", tc[0], tc[1], tc[2], [0x02, 0x06, 0x09].contains(tc[4]) ? ";" : ":", tc[3])
    }

    /// Frame-counter check for the coordinator's --selftest.
    static func selfTestTimecode() -> Bool {
        let cases: [(Int, UInt8, [UInt8])] = [
            (29, 0x03, [0, 0, 0, 29]), (30, 0x03, [0, 0, 1, 0]), (24 * 3600, 0x00, [1, 0, 0, 0]),
            (25 * 86400, 0x01, [0, 0, 0, 0]), // 24 h wrap
            (29, 0x02, [0, 0, 0, 29]), // fractional rate: frames 0–29
            (1799, 0x02, [0, 0, 59, 29]), (1800, 0x02, [0, 1, 0, 2]), // DF skips ;00 ;01
            (17982, 0x02, [0, 10, 0, 0]), // ...but not on the 10th minute
            (3600, 0x06, [0, 1, 0, 4]), (7200, 0x09, [0, 1, 0, 8]), (119, 0x0A, [0, 0, 0, 119]),
        ]
        return cases.allSatisfy { Array(timecode(frame: $0.0, rate: $0.1).prefix(4)) == $0.2 }
    }
}
