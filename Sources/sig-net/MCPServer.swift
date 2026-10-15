import Foundation
import SigNet

/// `sig-net --mcp`: a Model Context Protocol server on stdin/stdout (JSON-RPC 2.0, one message per line), so an AI
/// client can drive the suite: discover Nodes, GET/SET parameters and RDM through the Manager, send and receive levels,
/// run a virtual Node, read the packet logs, and run the self-test and probe.
///
/// Read-only unless started with --allow-set. --allow-dangerous also allows the SETs that can wipe, reboot or
/// re-address a device, and switching a Secure port to Art-Net/sACN: PF §11.7.11 wants the operator's confirmation,
/// and the launch flag is it. The passphrase comes from --passphrase or SIGNET_PASSPHRASE, never from a tool call.
///
/// Requests are handled one at a time on a reader thread. The engines stay on the main queue, as in the app, and the
/// reader waits for their callbacks. The engines never print, so stdout carries only protocol messages; the self-test
/// and probe do print, so they run as child processes.
enum MCPServer {
    static let settings = SecurityConfig()
    // Fresh TUIDs each run: two servers (two AI sessions) or the app sharing one would collide on the persisted session
    // counter and drop each other's packets as replays. What the engines save under them is removed at exit.
    static let manager = ManagerEngine(settings: settings, tuid: Identity.fresh())
    static let sender = TransmitterEngine(settings: settings, tuid: Identity.fresh())
    static let receiver = ReceiverEngine(settings: settings, tuid: Identity.fresh())
    static let node = DeviceEngine(settings: settings, tuid: Identity.fresh())
    static var allowSet = false, allowDangerous = false

    static func run(_ args: [String]) -> Never {
        func arg(_ name: String) -> String? { args.firstIndex(of: name).flatMap { $0 + 1 < args.count ? args[$0 + 1] : nil } }
        let passphrase = arg("--passphrase") ?? ProcessInfo.processInfo.environment["SIGNET_PASSPHRASE"].flatMap { $0.isEmpty ? nil : $0 }
        settings.mode = passphrase == nil ? .open : .secure
        settings.passphrase = passphrase ?? ""
        settings.scope = arg("--scope") ?? "local"
        settings.interface = arg("--interface") ?? ""
        allowDangerous = args.contains("--allow-dangerous")
        allowSet = allowDangerous || args.contains("--allow-set")
        guard settings.ready else {
            FileHandle.standardError.write(Data("sig-net --mcp: passphrase rejected: \(settings.passphraseProblem ?? "")\n".utf8))
            exit(2)
        }
        _ = (manager, sender, receiver, node) // made here, on main, where they run
        Thread { serve() }.start()
        _ = Timer.scheduledTimer(withTimeInterval: 3600, repeats: true) { _ in } // a source, so run() doesn't return at once
        RunLoop.main.run()
        exit(0)
    }

    // MARK: - JSON-RPC

    private static func serve() {
        while let line = readLine() {
            guard !line.allSatisfy(\.isWhitespace) else { continue }
            guard let parsed = try? JSONSerialization.jsonObject(with: Data(line.utf8)) else {
                send(["jsonrpc": "2.0", "id": NSNull(), "error": ["code": -32700, "message": "Parse error"] as [String: Any]])
                continue
            }
            guard let message = parsed as? [String: Any] else {
                send(["jsonrpc": "2.0", "id": NSNull(), "error": ["code": -32600, "message": "Invalid request: expected one JSON object"] as [String: Any]])
                continue
            }
            guard let id = message["id"] else { continue } // notifications (initialized, cancelled) get no answer
            let params = message["params"] as? [String: Any] ?? [:]
            var reply: [String: Any] = ["jsonrpc": "2.0", "id": id]
            guard let method = message["method"] as? String else {
                reply["error"] = ["code": -32600, "message": "Invalid request: no method"] as [String: Any]
                send(reply)
                continue
            }
            switch method {
            case "initialize":
                // Only tools are used, which every revision has: answer with the client's version when it is one of these.
                let asked = params["protocolVersion"] as? String ?? ""
                reply["result"] = [
                    "protocolVersion": ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"].contains(asked) ? asked : "2025-11-25",
                    "capabilities": ["tools": [String: Any]()],
                    "serverInfo": ["name": "sig-net", "version": suiteVersion],
                    "instructions": instructions,
                ] as [String: Any]
            case "ping":
                reply["result"] = [String: Any]()
            case "tools/list":
                reply["result"] = ["tools": tools.map(\.spec)]
            case "tools/call":
                let name = params["name"] as? String ?? ""
                if tools.contains(where: { $0.name == name }) {
                    reply["result"] = call(name, params["arguments"] as? [String: Any] ?? [:])
                } else {
                    reply["error"] = ["code": -32602, "message": "Unknown tool: \(name)"] as [String: Any]
                }
            case let method:
                reply["error"] = ["code": -32601, "message": "Method not found: \(method)"] as [String: Any]
            }
            send(reply)
        }
        onMain {
            manager.stop()
            sender.stop()
            receiver.stop()
            node.stop()
        }
        // This run's TUIDs are never used again: drop the session counters and Node state saved under them.
        let ours = [manager.tuid, sender.tuid, receiver.tuid, node.tuid].map(Identity.hex)
        let defaults = UserDefaults.standard
        for key in defaults.dictionaryRepresentation().keys where ours.contains(where: { key.contains($0) }) {
            defaults.removeObject(forKey: key)
        }
        exit(0)
    }

    private static func send(_ message: [String: Any]) {
        // A reply that won't encode still answers its id, or the client would wait on it forever.
        let fallback: [String: Any] = ["jsonrpc": "2.0", "id": message["id"] ?? NSNull(),
                                       "error": ["code": -32603, "message": "Internal error: the reply could not be encoded"] as [String: Any]]
        guard let data = (try? JSONSerialization.data(withJSONObject: message)) ?? (try? JSONSerialization.data(withJSONObject: fallback)) else { return }
        FileHandle.standardOutput.write(data + Data("\n".utf8))
    }

    private static func call(_ name: String, _ a: [String: Any]) -> [String: Any] {
        func result(_ text: String, error: Bool) -> [String: Any] { ["content": [["type": "text", "text": text]], "isError": error] }
        guard let tool = tools.first(where: { $0.name == name }) else { return result("No tool named \(name)", error: true) }
        if tool.writes, !allowSet {
            return result("\(name) changes devices or puts levels on the network, and this server was started read-only. Restart it with --allow-set.", error: true)
        }
        do {
            let out = try tool.run(a)
            return result(out as? String ?? json(out), error: false)
        } catch {
            return result("\(error)", error: true)
        }
    }

    private static func json(_ value: Any) -> String {
        guard let d = try? JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys]) else { return "\(value)" }
        return String(decoding: d, as: UTF8.self)
    }

    // MARK: - Tools

    private struct Tool {
        let name: String
        let description: String
        var params: [String: [String: Any]] = [:]
        var required: [String] = []
        var writes = false
        let run: ([String: Any]) throws -> Any

        var spec: [String: Any] {
            var schema: [String: Any] = ["type": "object", "properties": params]
            if !required.isEmpty { schema["required"] = required }
            return ["name": name, "description": description, "inputSchema": schema, "annotations": ["readOnlyHint": !writes]]
        }
    }

    private static let instructions = """
        Sig-Net protocol test suite. Start with `status`, then `discover`. Devices are addressed by the 12-hex-digit TUID \
        that `discover` returns; endpoint 0 is a device's root and 1…n its ports. `list_tids` is the \
        parameter catalogue. With no hardware, `virtual_device` start puts a test Node on the network for the other tools. \
        `logs` shows the packets each part sent and received. A device that refuses or doesn't answer comes back as \
        "ok": false with the reason; isError means the request itself was wrong or not allowed. Requests run one at a \
        time, and `probe` takes about 2.5 minutes.
        """

    private static func p(_ type: String, _ description: String) -> [String: Any] { ["type": type, "description": description] }
    private static let deviceParam = p("string", "Device TUID, 12 hex digits (from discover)")
    private static let endpointParam = p("integer", "0 = the device root (default), 1…n = a port. 65535 addresses every port, but only the first port to answer is reported")
    private static let tidParam = p("string", "TID by name (RT_DEVICE_LABEL) or hex (0x0605)")

    private static let tools: [Tool] = [
        Tool(name: "status",
             description: "Security mode, scope, interface, which write flags the server was started with, and what each part (Manager, transmitter, receiver, virtual device) is doing.") { _ in
            onMain { [
                "mode": settings.mode.rawValue, "scope": settings.scopeOrDefault,
                "interface": settings.interface.isEmpty ? "OS default" : settings.interface,
                "allow_set": allowSet, "allow_dangerous": allowDangerous,
                "manager": ["running": manager.running, "status": manager.status, "tuid": Identity.hex(manager.tuid), "devices": manager.devices.count] as [String: Any],
                "transmitter": ["running": sender.running, "status": sender.status] as [String: Any],
                "receiver": ["running": receiver.running, "status": receiver.status] as [String: Any],
                "virtual_device": ["running": node.running, "status": node.status, "tuid": Identity.hex(node.tuid)] as [String: Any],
            ] as [String: Any] }
        },

        Tool(name: "list_tids",
             description: "The Sig-Net parameter (TID) catalogue: hex, name, family, whether GET and SET apply, root (R) or data-endpoint (D) scope, the value layout, and whether a SET is dangerous.",
             params: ["family": p("string", "Only this family, e.g. Root, Endpoint, Network, RDM")]) { a in
            let family = (a["family"] as? String)?.lowercased()
            return ManagerTID.all.filter { family == nil || $0.family.lowercased() == family }.map { t -> [String: Any] in
                ["tid": t.hex, "name": t.name, "family": t.family, "get": t.get, "set": t.set, "scope": t.scope,
                 "layout": t.layout, "dangerous": ManagerTID.dangerous(t.tid)]
            }
        },

        Tool(name: "discover",
             description: "Polls for Sig-Net Nodes (TID_POLL) and lists every device the Manager has seen since the server started, with TUID, IP, model, label, roles, authentication, change count, state (Lost when it stopped answering) and last-seen time. Starts the Manager if needed.",
             params: ["seconds": p("number", "How long to wait for replies (default 2, max 30)"),
                      "ip": p("string", "Poll this IPv4 address directly instead of the multicast group")]) { a in
            try startManager()
            let ip = a["ip"] as? String
            onMain { manager.poll(level: 2, ep: 0xFFFF, to: ip) }
            Thread.sleep(forTimeInterval: min(max(number(a["seconds"]) ?? 2, 0.5), 30))
            return onMain { manager.devices.values.sorted { $0.id < $1.id }.map(deviceInfo) }
        },

        Tool(name: "get_parameters",
             description: "GETs one or more TIDs from a device endpoint and returns each value decoded, with its raw hex.",
             params: ["device": deviceParam, "endpoint": endpointParam,
                      "tids": ["type": "array", "items": tidParam, "description": "The TIDs to read"]],
             required: ["device", "tids"]) { a in
            let target = try bytes(a, "device", count: 6), ep = try endpoint(a)
            guard let list = a["tids"] as? [Any], !list.isEmpty else { throw SigNetError("tids: one or more TIDs") }
            let tids = try list.map(tid)
            try startManager()
            let r: ManagerResult = try answer { manager.get(target, ep: ep, tids: tids, done: $0) }
            var out = outcome(r)
            // A Node skips TIDs it doesn't support (§10.1), so say which ones didn't come back.
            let missing = tids.filter { t in !r.tlvs.contains { $0.tid == t } }
            if r.ok, !missing.isEmpty { out["not_returned"] = missing.map(ManagerTID.name) }
            return out
        },

        Tool(name: "set_parameter",
             description: "SETs one TID on a device endpoint. The value is text: a label as plain text, numbers in decimal or 0x hex, IPv4 dotted, anything else hex; prefix hex: to force raw bytes. Needs --allow-set. RT_OFFBOARD, RT_REBOOT, network address changes and, in Secure mode, switching a port to Art-Net or sACN also need --allow-dangerous.",
             params: ["device": deviceParam, "endpoint": endpointParam, "tid": tidParam,
                      "value": p("string", "The new value, as described above")],
             required: ["device", "tid", "value"], writes: true) { a in
            let target = try bytes(a, "device", count: 6), ep = try endpoint(a), t = try tid(a["tid"])
            // Catalogue TIDs that aren't SETs (POLL, RDM_COMMAND…) stay out: RDM goes through rdm_set and its checks.
            if let info = ManagerTID.byTID[t], !info.set { throw SigNetError("\(info.name) can't be SET") }
            // An empty value would go out as a GET (an empty TLV), not a SET.
            guard let v = ManagerTID.parse(t, a["value"].map { "\($0)" } ?? ""), !v.isEmpty else {
                throw SigNetError("Not a valid value for \(ManagerTID.name(t)) (\(ManagerTID.byTID[t]?.layout ?? "hex bytes"))")
            }
            if !allowDangerous {
                if ManagerTID.dangerous(t) {
                    throw SigNetError("\(ManagerTID.name(t)) can wipe, reboot or re-address the device. Restart the server with --allow-dangerous to send it.")
                }
                if t == 0x090B, v.contains(where: { $0 != 0 }), settings.mode == .secure {
                    throw SigNetError("PF §11.7.11: switching a Secure port to Art-Net or sACN removes authentication from its level data. Restart the server with --allow-dangerous to send it.")
                }
            }
            try startManager()
            let r: ManagerResult = try answer { manager.set(target, ep: ep, tlvs: [ManagerTLV(tid: t, value: v)], done: $0) }
            return outcome(r)
        },

        Tool(name: "rdm_devices",
             description: "Asks one port of a device for its RDM table of devices (TOD_CONTROL 0x00) and lists the fixture UIDs it reports.",
             params: ["device": deviceParam, "endpoint": p("integer", "The port, 1…n")],
             required: ["device", "endpoint"]) { a in
            let target = try bytes(a, "device", count: 6), ep = try endpoint(a)
            try startManager()
            let r: ManagerResult = try answer { manager.requestToD(target, ep: ep, done: $0) }
            var out = outcome(r)
            out["uids"] = onMain { manager.devices[Identity.hex(target)]?.tod[ep]?.map(Identity.hex) ?? [] }
            return out
        },

        rdmTool(set: false),
        rdmTool(set: true),

        Tool(name: "logs",
             description: "The newest log entries of one part. manager: every Sig-Net packet it sent or received (direction, peer, URI, sender, security mode, session/seq lane, authentication result, TLVs; raw bytes with packets=true). receiver: its log, drop counters by PF §8.6 reason and the headers of rejected packets. device: the virtual Node's log.",
             params: ["source": ["type": "string", "enum": ["manager", "receiver", "device"]],
                      "limit": p("integer", "How many of the newest entries (default 50)"),
                      "packets": p("boolean", "manager: include each packet's raw hex")],
             required: ["source"]) { a in
            let limit = max(1, Int(number(a["limit"]) ?? 50))
            switch a["source"] as? String {
            case "manager":
                let raw = a["packets"] as? Bool ?? false
                return onMain {
                    manager.log.suffix(limit).map { e -> [String: Any] in
                        var d: [String: Any] = ["time": iso.string(from: e.time), "direction": e.tx ? "tx" : "rx", "peer": e.peer,
                                                "uri": e.uri, "sender": e.sender, "mode": e.mode, "lane": e.lane, "auth": e.auth, "tlvs": e.tlvs]
                        if raw { d["hex"] = e.hex }
                        return d
                    }
                }
            case "receiver":
                return onMain { () -> [String: Any] in
                    receiver.refreshDiagnostics()
                    return diagnostics(limit)
                }
            case "device":
                return onMain { Array(node.log.suffix(limit)) }
            default:
                throw SigNetError("source: manager, receiver or device")
            }
        },

        Tool(name: "receive",
             description: "Listens to Sig-Net level data for a few seconds as a Node would, then reports one universe's 512 levels with its source count and frame rate, the timecode heard, and drop counters by PF §8.6 reason with the headers of rejected packets.",
             params: ["universes": p("string", "Universes to join, e.g. 1 or 1-4,10 (default 1)"),
                      "universe": p("integer", "Which of them to report levels for (default the first)"),
                      "seconds": p("number", "How long to listen (default 2, max 30)"),
                      "preview": p("string", "Preview universes to join as well (optional)")]) { a in
            try onMain {
                receiver.stop()
                receiver.universesText = a["universes"].map { "\($0)" } ?? "1"
                receiver.previewText = a["preview"].map { "\($0)" } ?? ""
                receiver.selected = number(a["universe"]).map { Int($0) } ?? 0 // 0 isn't a universe, so start() picks the first
                receiver.start()
                guard receiver.running else { throw SigNetError(receiver.status) }
            }
            Thread.sleep(forTimeInterval: min(max(number(a["seconds"]) ?? 2, 0.2), 30))
            return onMain { () -> [String: Any] in
                receiver.refreshDiagnostics()
                var out = diagnostics(20)
                out["universe"] = receiver.selected
                out["fps"] = receiver.fps.isFinite ? receiver.fps : 0
                out["sources"] = receiver.frame?.sourceCount ?? 0
                out["slots"] = receiver.frame?.slotCount ?? 0
                out["levels"] = receiver.frame == nil ? [] : receiver.levels.map(Int.init) // nothing heard: not last run's levels
                out["timecode"] = Dictionary(uniqueKeysWithValues: receiver.timecodes.map { s, t in
                    ("\(s)", t.lost ? "lost" : t.value.prefix(4).map { String(format: "%02d", Int($0)) }.joined(separator: ":"))
                })
                out["previews"] = Dictionary(uniqueKeysWithValues: receiver.previews.map { u, f in
                    ("\(u)", ["sources": f.frame.sourceCount, "levels": f.levels.map(Int.init)] as [String: Any])
                })
                receiver.stop()
                return out
            }
        },

        Tool(name: "transmit",
             description: "Sends Sig-Net level data as a sender and keeps sending until stopped: set channel levels, fill a universe, or run a test pattern. Each call changes only what it names. Needs --allow-set, since real fixtures follow these levels.",
             params: ["universe": p("integer", "First universe to send (default 1)"),
                      "count": p("integer", "How many consecutive universes, 1-16 (default 1)"),
                      "target": p("integer", "The universe that levels and all apply to (default the first)"),
                      "levels": ["type": "object", "description": "Levels 0-255 by channel, e.g. {\"1\": 255, \"5\": 128}. An array from channel 1 also works"],
                      "all": p("integer", "Set every channel of the target universe to this level"),
                      "pattern": ["type": "string", "enum": ["off", "chase", "ramp", "random"]],
                      "master": p("integer", "Master level 0-255 (default 255)"),
                      "stop": p("boolean", "Stop sending")],
             writes: true) { a in
            try onMain { () -> [String: Any] in
                if a["stop"] as? Bool == true {
                    sender.stop()
                    return ["running": sender.running, "status": sender.status]
                }
                let first = number(a["universe"]).map { Int($0) } ?? sender.universe
                let count = number(a["count"]).map { Int($0) } ?? sender.count
                guard (1...63999).contains(first), (1...16).contains(count) else { throw SigNetError("universe 1-63999, count 1-16") }
                let target = number(a["target"]).map { Int($0) } ?? first
                guard (first..<first + count).contains(target) else { throw SigNetError("target must be one of the universes sent") }
                if sender.running, first != sender.universe || count != sender.count { sender.stop() }
                if first != sender.universe {
                    // Levels are banked by offset from the first universe: moving it would carry them to other universes.
                    for i in 0..<16 { sender.selected = i; sender.setAll(0) }
                }
                sender.universe = first
                sender.count = count
                sender.selected = target - first
                if let m = number(a["master"]) { sender.master = min(max(m, 0), 255) }
                if let name = a["pattern"] as? String {
                    guard let pattern = TransmitterEngine.Pattern.allCases.first(where: { $0.rawValue.lowercased() == name.lowercased() }) else {
                        throw SigNetError("pattern: off, chase, ramp or random")
                    }
                    sender.pattern = pattern
                }
                if let all = number(a["all"]) { sender.setAll(UInt8(clamping: Int(all))) }
                if let given = a["levels"] {
                    var levels = sender.levels
                    if let list = given as? [Any] {
                        for (i, v) in list.prefix(512).enumerated() { if let n = number(v) { levels[i] = UInt8(clamping: Int(n)) } }
                    } else if let map = given as? [String: Any] {
                        for (k, v) in map {
                            guard let ch = Int(k), (1...512).contains(ch), let n = number(v) else { throw SigNetError("levels: channel 1-512 → level 0-255") }
                            levels[ch - 1] = UInt8(clamping: Int(n))
                        }
                    }
                    sender.levels = levels
                }
                if !sender.running { sender.start() }
                guard sender.running else { throw SigNetError(sender.status) }
                return ["running": true, "status": sender.status, "universe": first, "count": count, "target": target,
                        "pattern": sender.pattern.rawValue, "master": Int(sender.master), "send_failures": Int(clamping: sender.sendFailures),
                        "levels": sender.levels.map(Int.init)]
            }
        },

        Tool(name: "virtual_device",
             description: "Runs the suite's built-in Sig-Net Node (the app's Device tab) inside the server, so the other tools can be tried without hardware. It answers discovery, GET/SET and RDM like a real Node.",
             params: ["action": ["type": "string", "enum": ["start", "stop", "status"]],
                      "label": p("string", "Device label to start with"),
                      "ports": p("integer", "Number of ports, 1-8 (default 2)")],
             required: ["action"]) { a in
            try onMain { () -> [String: Any] in
                switch a["action"] as? String {
                case "start":
                    // The Node reads its label and port count when it starts, so a change restarts it.
                    if node.running, a["label"] != nil || a["ports"] != nil { node.stop() }
                    if let label = a["label"] as? String { node.label = label }
                    if let n = number(a["ports"]) { node.endpointCount = min(8, max(1, Int(n))) }
                    if !node.running { node.start() }
                    guard node.running else { throw SigNetError(node.status) }
                case "stop": node.stop()
                case "status": break
                default: throw SigNetError("action: start, stop or status")
                }
                return ["running": node.running, "status": node.status, "tuid": Identity.hex(node.tuid), "label": node.label,
                        "ports": node.endpointCount, "log": Array(node.log.suffix(10))]
            }
        },

        Tool(name: "selftest",
             description: "Runs the suite's self-test: spec vectors, parsers, RDM and fixture profiles, plus with offline=false the Manager, sender, receiver and device loops over the network (needs --allow-set, since they send levels). Returns its PASS/FAIL lines.",
             params: ["offline": p("boolean", "Skip the network loops (default true; the full run takes about 30 s)")]) { a in
            var args = ["--selftest"]
            if a["offline"] as? Bool ?? true {
                args.append("--offline")
            } else if !allowSet {
                // The network loops send levels and run a Manager and a Node on the live network, Open and Secure.
                throw SigNetError("offline=false puts levels and a test Manager and Node on the network. Restart the server with --allow-set.")
            }
            if !settings.interface.isEmpty { args += ["--interface", settings.interface] }
            return try child(args)
        },

        Tool(name: "probe",
             description: "Runs the conformance probe against one Node: every discovery shape and query level, a GET of every catalogue TID, SET round-trips (each restored; never RT_OFFBOARD, RT_REBOOT or network SETs) and RDM. Returns its report; takes about 2.5 minutes. Needs --allow-set, and in Secure Mode --allow-dangerous, because one round-trip switches port 1 to Art-Net and back.",
             params: ["device": deviceParam, "ip": p("string", "The Node's IPv4 address"),
                      "rdm_uid": p("string", "The fixture UID behind port 1 for the RDM part. Without it the probe uses its built-in default, 21A43DA458B0, so pass one from rdm_devices")],
             required: ["device", "ip"], writes: true) { a in
            let target = try bytes(a, "device", count: 6)
            // Checked, since both go on the child's command line.
            guard let ip = a["ip"] as? String, ip.split(separator: ".", omittingEmptySubsequences: false).count == 4,
                  ip.split(separator: ".", omittingEmptySubsequences: false).allSatisfy({ UInt8($0) != nil }) else {
                throw SigNetError("ip: the Node's IPv4 address, e.g. 192.168.1.20")
            }
            // Its SET round-trips include EP_PROTOCOL → Art-Net on port 1, which PF §11.7.11 makes a confirmed change on a Secure Node.
            if settings.mode == .secure, !allowDangerous {
                throw SigNetError("In Secure Mode the probe switches port 1 to Art-Net and back (PF §11.7.11). Restart the server with --allow-dangerous to run it.")
            }
            var args = ["--probe", "--node", Identity.hex(target), "--ip", ip, "--scope", settings.scopeOrDefault]
            if !settings.interface.isEmpty { args += ["--interface", settings.interface] }
            // ponytail: the passphrase rides on the child's argv, visible to local `ps` while the probe runs; give
            // --probe an environment variable if that matters.
            if settings.mode == .secure { args += ["--passphrase", settings.passphrase] }
            if a["rdm_uid"] != nil { args += ["--rdm-uid", Identity.hex(try bytes(a, "rdm_uid", count: 6))] }
            return try child(args)
        },
    ]

    private static func rdmTool(set: Bool) -> Tool {
        Tool(name: set ? "rdm_set" : "rdm_get",
             description: set ? "Sends an RDM SET to a fixture through one port of a device. Needs --allow-set; RESET_DEVICE, FACTORY_DEFAULTS and the E1.37-2 network PIDs also need --allow-dangerous."
                              : "Sends an RDM GET to a fixture through one port of a device and returns its response.",
             params: ["device": deviceParam, "endpoint": p("integer", "The port, 1…n"),
                      "uid": p("string", "The fixture's RDM UID, 12 hex digits"),
                      "pid": p("string", "RDM parameter ID in hex, e.g. 0x0060 (a JSON number is read as decimal)"),
                      "data": p("string", "Parameter data as hex (optional)")],
             required: ["device", "endpoint", "uid", "pid"], writes: set) { a in
            let target = try bytes(a, "device", count: 6), ep = try endpoint(a), uid = try bytes(a, "uid", count: 6)
            let pid = try hex16(a["pid"], "pid")
            // RDM's own reboot, wipe and re-address: RESET_DEVICE, FACTORY_DEFAULTS and the E1.37-2 network PIDs.
            if set, !allowDangerous, pid == 0x1001 || pid == 0x0090 || (0x0700...0x070D).contains(pid) {
                throw SigNetError(String(format: "RDM PID 0x%04X can reset, wipe or re-address the fixture. Restart the server with --allow-dangerous to send it.", pid))
            }
            let digits = (a["data"] as? String ?? "").filter(\.isHexDigit)
            guard let data = digits.isEmpty ? [] : mgrBytes(hex: digits) else { throw SigNetError("data: hex bytes") }
            try startManager()
            let r: ManagerResult = try answer { manager.rdm(target, ep: ep, dest: uid, set: set, pid: pid, pd: data, done: $0) }
            return outcome(r)
        }
    }

    // MARK: - Helpers

    private static let iso = ISO8601DateFormatter()

    private static func onMain<T>(_ work: () throws -> T) rethrows -> T { try DispatchQueue.main.sync(execute: work) }

    /// Starts `begin` on the main queue and waits for the result it hands to its callback.
    private static func answer<T>(_ begin: @escaping (@escaping (T) -> Void) -> Void) throws -> T {
        let done = DispatchSemaphore(value: 0), box = Box<T>()
        DispatchQueue.main.async { begin { box.value = $0; done.signal() } }
        guard done.wait(timeout: .now() + 15) == .success, let value = box.value else {
            // Still pending (an RDM ACK_TIMER can run for minutes) would make every later request "Busy": drop it.
            // The next request starts the Manager again.
            onMain { manager.stop() }
            throw SigNetError("No answer within 15 s; the Manager was restarted")
        }
        return value
    }

    private static func startManager() throws {
        try onMain {
            if !manager.running { manager.start() }
            guard manager.running else { throw SigNetError("The Manager didn't start: \(manager.status)") }
        }
    }

    /// Runs this binary with `args` and returns what it printed: the self-test and probe print, and stdout here is the protocol.
    private static func child(_ args: [String]) throws -> [String: Any] {
        let process = Process(), pipe = Pipe()
        process.executableURL = Bundle.main.executableURL ?? URL(fileURLWithPath: CommandLine.arguments[0])
        process.arguments = args
        process.standardInput = FileHandle.nullDevice // stdin is the protocol too
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        let output = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return ["exit_code": Int(process.terminationStatus), "passed": process.terminationStatus == 0,
                "output": String(decoding: output, as: UTF8.self)]
    }

    /// A JSON number or numeric string; nil for anything Int() would trap on (NaN, infinity, 1e19).
    private static func number(_ v: Any?) -> Double? {
        var d: Double?
        if let n = v as? Int { d = Double(n) } else if let x = v as? Double { d = x } else if let n = v as? NSNumber { d = n.doubleValue } else if let s = v as? String { d = Double(s) }
        guard let d, d.isFinite, abs(d) <= 1e9 else { return nil }
        return d
    }

    /// 0 when absent. Anything else that isn't a whole 0-65535 is an error: clamping would retarget a SET to the root
    /// or to every port.
    private static func endpoint(_ a: [String: Any]) throws -> UInt16 {
        guard let v = a["endpoint"] else { return 0 }
        guard let n = number(v), let e = UInt16(exactly: n) else { throw SigNetError("endpoint: a whole number, 0 (root) to 65535") }
        return e
    }

    private static func bytes(_ a: [String: Any], _ key: String, count: Int) throws -> [UInt8] {
        let digits = (a[key] as? String ?? "").filter(\.isHexDigit)
        guard let b = mgrBytes(hex: digits), b.count == count else { throw SigNetError("\(key): \(count * 2) hex digits") }
        return b
    }

    /// A hex string (0x optional) or a JSON number.
    private static func hex16(_ v: Any?, _ what: String) throws -> UInt16 {
        if let s = v as? String {
            let digits = s.lowercased().hasPrefix("0x") ? String(s.dropFirst(2)) : s
            if let n = UInt16(digits, radix: 16) { return n }
        } else if let n = number(v), let t = UInt16(exactly: n) {
            return t
        }
        throw SigNetError("\(what): hex like 0x0605, or a number")
    }

    /// A catalogue name (RT_DEVICE_LABEL) or hex16.
    private static func tid(_ v: Any?) throws -> UInt16 {
        if let s = v as? String, let t = ManagerTID.all.first(where: { $0.name.caseInsensitiveCompare(s) == .orderedSame }) { return t.tid }
        return try hex16(v, "tid")
    }

    private static func deviceInfo(_ d: ManagerDevice) -> [String: Any] {
        ["tuid": d.id, "ip": d.ip, "model": d.model, "label": d.label, "roles": d.roles, "state": d.state, "auth": d.auth,
         "anomaly": d.anomaly, "change_count": d.changeCount.map { Int($0) as Any } ?? NSNull(),
         "endpoints": d.root(0x0602).map { Int(mgrU16($0)) as Any } ?? NSNull(), "last_seen": iso.string(from: d.lastSeen)]
    }

    private static func outcome(_ r: ManagerResult) -> [String: Any] {
        var out: [String: Any] = ["ok": r.ok, "text": r.text]
        if !r.tlvs.isEmpty {
            out["values"] = r.tlvs.map { t -> [String: Any] in
                ["tid": String(format: "0x%04X", t.tid), "name": ManagerTID.name(t.tid), "value": ManagerLabels.value(t.tid, t.value),
                 "decoded": ManagerTID.describe(t.tid, t.value), "hex": mgrHex(t.value)]
            }
        }
        if !r.frame.isEmpty { out["rdm_frame"] = mgrHex(r.frame) }
        return out
    }

    /// Receiver counters and rejections; call refreshDiagnostics() first.
    private static func diagnostics(_ limit: Int) -> [String: Any] {
        let c = receiver.counters
        return ["status": receiver.status, "accepted": Int(clamping: c.accepted), "beacons": Int(clamping: c.beacons),
                "drops_total": Int(clamping: c.dropsTotal),
                "drops": Dictionary(uniqueKeysWithValues: DropReason.allCases.filter { c.drops[$0.rawValue] > 0 }.map { ($0.name, Int(clamping: c.drops[$0.rawValue])) }),
                "merge_saturations": Int(clamping: c.mergeSaturations), "flood_dropped": Int(clamping: c.floodDropped),
                "rejections": receiver.rejections.suffix(limit).map { ["reason": $0.reason.name, "length": $0.length, "header": mgrHex($0.header)] as [String: Any] },
                "log": Array(receiver.log.suffix(limit))]
    }
}

private final class Box<T> { var value: T? }
