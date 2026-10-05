import Foundation

/// Test-only ANSI E1.37-4-2026 Responder, written from the standard (not from the controller), on a virtual millisecond
/// clock: each request costs 1 ms and the controller's `sleep` advances `now`. It answers as a strict fixture would and
/// judges the controller: everything the standard forbids the controller to do is counted in `violations`, the last one
/// described in `lastViolation`. Fault knobs simulate line damage, slow fixtures and refusals.
final class FTCResponder {
    struct File {
        var id: UInt8, caps: UInt32
        var size: UInt32 = 0        // upload capacity (GET:FTC_INITIATE File Size, §13.1.2)
        var data: [UInt8] = []      // download content
        var description = "", suffix = "", key: [UInt8] = []
    }
    var files: [File]
    var uid: [UInt8] = [0x12, 0x34, 0, 0, 0, 1], newUID: [UInt8]?

    // Declarations (§8.6) and the times this fixture needs.
    var block: UInt8 = 32, initialDelay: UInt32 = 0, interPacket: UInt16 = 0, accCount: UInt32 = 0, accDelay: UInt16 = 0
    var validationDelay: UInt16 = 0, commitTime: UInt32 = 0, switchDelay: UInt32 = 0

    // Fault injection.
    var damagePacket = -1, damageTimes = 0          // upload packet n arrives damaged k times (PACKET_CRC_ERROR)
    var busyPacket = -1, busyMs: UInt32 = 0         // upload packet n answered IN_PROGRESS (once)
    var validationExtra: UInt32 = 0                 // validation runs this long past the declared Validation Delay
    var validationFails = false, refuseCommit: UInt8?
    var damageDownload = -1, badFileCRCOnce = false // download packet n sent with a bad PacketCRC once; wrong FileCRC once
    var onRequest: ((UInt8, UInt16, [UInt8]) -> Void)?

    // Judgement and counters.
    private(set) var violations = 0, lastViolation = ""
    private(set) var requests: [(cc: UInt8, pid: UInt16, pd: [UInt8])] = []
    private(set) var commits = 0, saved = false, switches = 0, cancels = 0, fileCRCRequests = 0, downloadInitiates = 0
    private(set) var received: [UInt8] = []
    var now: UInt64 = 0

    // Session state.
    private(set) var session: UInt8 = 0
    private var file = File(id: 0, caps: 0), flags: UInt16 = 0, size: UInt32 = 0, fileCRC: UInt16 = 0, head: [UInt8] = []
    private var complete = false, next: UInt32 = 0, last: UInt32 = 0, attempts = 0, accBytes: UInt32 = 0, busyAt: UInt32?
    private var validatedAt: UInt64 = 0, crcGate: UInt64 = 0, lastReply: UInt64 = 0, inBootloader = false
    private var gate: (until: UInt64, pids: Set<UInt16>, why: String) = (0, [], "")
    private var offline: (until: UInt64, why: String) = (0, "")
    private var listPage = 0
    private var download: Bool { flags & FTC.TF.download != 0 }

    init(_ files: [File]) { self.files = files }

    func sent(_ cc: UInt8, _ pid: UInt16) -> [[UInt8]] { requests.filter { $0.cc == cc && $0.pid == pid }.map(\.pd) }

    private func violate(_ s: String) { violations += 1; lastViolation = "t=\(now) \(s)" }
    private static func name(_ cc: UInt8, _ pid: UInt16) -> String {
        let n = [0x1200: "INITIATE", 0x1201: "TRANSFER_UPLOAD", 0x1202: "COMMIT", 0x1203: "CANCEL", 0x1204: "FILELIST",
                 0x1205: "TRANSFER_DOWNLOAD"][Int(pid)] ?? String(format: "PID 0x%04X", pid)
        return (cc == FTC.getCommand ? "GET:FTC_" : "SET:FTC_") + n
    }
    private func end() { session = 0; complete = false; gate = (0, [], ""); busyAt = nil }
    private func ack(_ cc: UInt8, _ pid: UInt16, _ pd: [UInt8], type: Int32 = FTC.ack) -> FirmwareUpdate.Reply {
        .init(type: type, cc: cc + 1, pid: pid, pd: pd)
    }
    private func nack(_ cc: UInt8, _ pid: UInt16, _ reason: UInt16, _ why: String?) -> FirmwareUpdate.Reply {
        if let why { violate(why) }
        return ack(cc, pid, mgrBE16(reason), type: FTC.nack)
    }
    private static func pad(_ b: some Collection<UInt8>, _ n: Int) -> [UInt8] { Array(b.prefix(n)) + [UInt8](repeating: 0, count: max(0, n - b.count)) }

    func handle(_ cc: UInt8, _ pid: UInt16, _ pd: [UInt8]) -> FirmwareUpdate.Reply? {
        requests.append((cc, pid, pd)); onRequest?(cc, pid, pd)
        let t = now, what = Self.name(cc, pid)
        now += 1
        defer { lastReply = now }
        if t < offline.until { violate("\(what) during the \(offline.why), \(offline.until - t) ms early"); return nil }
        if gate.pids.contains(pid), pid != FTC.PID.cancel, t < gate.until { // FTC_CANCEL may come at any stage (§5.6)
            violate("\(what) \(gate.until - t) ms before the \(gate.why) elapsed")
        }
        if session != 0, t > max(lastReply, gate.until) + 600_000 { end(); inBootloader = false } // §8.5 failsafe
        if accCount > 0, t >= lastReply + UInt64(interPacket) + UInt64(accDelay) { accBytes = 0 } // delay was applied (§8.6.5)
        let get = cc == FTC.getCommand
        guard get || cc == FTC.setCommand else { return nack(cc, pid, 0x0005, "\(what): command class 0x\(String(cc, radix: 16))") }
        switch pid {
        case FTC.PID.initiate: return get ? getInitiate(cc, pd) : setInitiate(cc, pd)
        case FTC.PID.transferUpload: return upload(cc, pd, get: get)
        case FTC.PID.commit: return commit(cc, pd, get: get)
        case FTC.PID.cancel: return get ? nack(cc, pid, 0x0005, "GET:FTC_CANCEL (SET only, §13)") : cancel(cc, pd)
        case FTC.PID.fileList: return get ? fileList(cc, pd) : nack(cc, pid, 0x0005, "SET:FTC_FILELIST (GET only, §13)")
        case FTC.PID.transferDownload:
            return get ? downloadPacket(cc, pd, t) : nack(cc, pid, 0x0005, "SET:FTC_TRANSFER_DOWNLOAD (GET only, §13)")
        default: return nack(cc, pid, 0x0000, nil) // NR_UNKNOWN_PID: not ours to judge
        }
    }

    // MARK: FTC_INITIATE (§13.1)

    /// The 38-byte GET/SET:FTC_INITIATE response (field table of §13.1.2; the printed PDL 0x22 does not add up).
    private func declarations(_ st: UInt8, _ data: UInt32, _ s: UInt8, _ id: UInt8, size: UInt32, caps: UInt32,
                              offset: UInt32 = 0, dl: Bool) -> [UInt8] {
        var b: [UInt8] = [st] + mgrBE32(data) + [s, id] + mgrBE16(FTC.version) + mgrBE32(size) + mgrBE32(caps)
        b += mgrBE32(offset) + [block] + mgrBE32(initialDelay) + mgrBE16(interPacket)
        b += mgrBE32(dl ? 0 : accCount) + mgrBE16(dl ? 0 : accDelay) + mgrBE16(validationDelay)
        return b + mgrBE16(0) // no ALL_DEVICES_ID support: Max Inter-Packet Delay 0 (§8.6.8)
    }
    private var supportedID: UInt8 { files.count == 1 ? files[0].id : FTC.DEF.multipleFileID }

    private func getInitiate(_ cc: UInt8, _ pd: [UInt8]) -> FirmwareUpdate.Reply {
        guard pd.count == 6 else { return nack(cc, FTC.PID.initiate, 0x0001, "GET:FTC_INITIATE PDL \(pd.count), not 6") }
        let s = pd[0], id = pd[1], dl = mgrU16(pd[4...]) & FTC.TF.download != 0
        func r(_ st: UInt8, _ data: UInt32 = 0, _ rid: UInt8 = 0, size: UInt32 = 0, caps: UInt32 = 0, off: UInt32 = 0) -> FirmwareUpdate.Reply {
            ack(cc, FTC.PID.initiate, declarations(st, data, session, rid, size: size, caps: caps, offset: off, dl: dl))
        }
        if mgrU16(pd[2...]) != FTC.version { violate("GET:FTC_INITIATE FTCVersion 0x\(String(mgrU16(pd[2...]), radix: 16))"); return r(FTC.RS.ftcVersionError, 0x0001_0000) }
        if s != FTC.DEF.noSessionIDOffered { violate("GET:FTC_INITIATE SessionID \(s), must be 0 (§13.1.1)"); return r(FTC.RS.sessionIDMismatch, UInt32(s) << 16) }
        if session != 0 { return r(FTC.RS.statusOK, 0, file.id, size: size, caps: file.caps, off: download ? last : next) }
        if id == FTC.DEF.noFileIDOffered && files.count > 1 {
            return r(FTC.RS.statusOK, 0, FTC.DEF.multipleFileID, caps: files.reduce(0) { $0 | $1.caps })
        }
        guard let f = id == 0 ? files.first : files.first(where: { $0.id == id }) else {
            return r(FTC.RS.unsupportedFileID, UInt32(id) << 16 | UInt32(supportedID))
        }
        return r(FTC.RS.statusOK, 0, f.id, size: dl ? UInt32(f.data.count) : f.size, caps: f.caps)
    }

    private func setInitiate(_ cc: UInt8, _ pd: [UInt8]) -> FirmwareUpdate.Reply {
        guard pd.count == 30 else { return nack(cc, FTC.PID.initiate, 0x0001, "SET:FTC_INITIATE PDL \(pd.count), not 30") }
        let s = pd[0], id = pd[1], tf = mgrU16(pd[4...]), sz = mgrU32(pd[6...]), h = Array(pd[10..<26])
        let fcrc = mgrU16(pd[26...]), pcrc = mgrU16(pd[28...]), dl = tf & FTC.TF.download != 0
        func r(_ st: UInt8, _ data: UInt32 = 0, _ rid: UInt8, size: UInt32 = 0, caps: UInt32 = 0) -> FirmwareUpdate.Reply {
            ack(cc, FTC.PID.initiate, declarations(st, data, s, rid, size: size, caps: caps, dl: dl))
        }
        end() // a new Initiate replaces any session
        if FTC.crc(pd[..<28]) != pcrc { violate("SET:FTC_INITIATE PacketCRC"); return r(FTC.RS.packetCRCError, UInt32(pcrc) << 16 | UInt32(FTC.crc(pd[..<28])), supportedID) }
        if !(1...0xFE).contains(s) { violate("SET:FTC_INITIATE SessionID \(s), must be 1-254 (§11.1)"); return r(FTC.RS.sessionIDMismatch, UInt32(s) << 16, supportedID) }
        if mgrU16(pd[2...]) != FTC.version { violate("SET:FTC_INITIATE FTCVersion"); return r(FTC.RS.ftcVersionError, 0x0001_0000, supportedID) }
        if tf & 0x07FC != 0 { violate("SET:FTC_INITIATE reserved TransferFlags 0x\(String(tf, radix: 16))") }
        if dl && tf & FTC.TF.testMode != 0 { violate("FTC_TF_TESTMODE on a download (upload only, §13.1.3)") }
        if dl && (sz != 0 || fcrc != 0) { violate("download SET:FTC_INITIATE File Size/FileCRC not 0 (§13.1.3)") }
        if id == FTC.DEF.noFileIDOffered && files.count > 1 { return r(FTC.RS.statusOK, 0, FTC.DEF.multipleFileID) } // §13.1.4
        guard let f = id == 0 ? files.first : files.first(where: { $0.id == id }) else {
            return r(FTC.RS.unsupportedFileID, UInt32(id) << 16 | UInt32(supportedID), supportedID)
        }
        if f.caps & (dl ? FTC.Cap.acceptDownload : FTC.Cap.acceptUpload) == 0 { return r(FTC.RS.invalidDirection, 0, f.id) }
        if !dl && f.size != 0 && sz > f.size { return r(FTC.RS.fileSizeError, f.size, f.id) }
        if tf & FTC.TF.testMode != 0 && f.caps & FTC.Cap.testModeSupported == 0 { return r(FTC.RS.unresolvedError, 0, f.id) }
        if dl && f.caps & FTC.Cap.downloadKey != 0 && h != Self.pad(f.key, 16) { return r(FTC.RS.downloadKeyRequired, 0, f.id) }
        if dl && f.caps & FTC.Cap.downloadKey == 0 && h.contains(where: { $0 != 0 }) { violate("Download Key field not zero (§13.1.3)") }
        if f.caps & FTC.Cap.bootloaderSwitch != 0 && !inBootloader { // §12.1.5: offline for the switch, then re-Initiate
            inBootloader = true; switches += 1; offline = (now + UInt64(switchDelay), "bootloader switch")
            return r(FTC.RS.switchToBootloader, switchDelay, 0) // the other fields are to be ignored
        }
        session = s; file = f; flags = tf; fileCRC = fcrc; head = h; received = []; next = 0; last = 0; attempts = 0; accBytes = 0
        size = dl ? UInt32(f.data.count) : sz
        if dl { downloadInitiates += 1 }
        gate = (now + UInt64(initialDelay), [FTC.PID.transferUpload, FTC.PID.transferDownload], "Initial Delay")
        return r(dl ? FTC.RS.initOKDL : FTC.RS.initOKUL, 0, f.id, size: size, caps: f.caps)
    }

    // MARK: FTC_TRANSFER_UPLOAD (§13.2)

    private func upload(_ cc: UInt8, _ pd: [UInt8], get: Bool) -> FirmwareUpdate.Reply {
        func r(_ st: UInt8, _ data: UInt32 = 0, _ off: UInt32? = nil) -> FirmwareUpdate.Reply {
            ack(cc, FTC.PID.transferUpload, [st] + mgrBE32(data) + mgrBE32(off ?? next))
        }
        let what = get ? "GET:FTC_TRANSFER_UPLOAD" : "SET:FTC_TRANSFER_UPLOAD"
        guard get ? pd.count == 1 : (7...231).contains(pd.count) else { return nack(cc, FTC.PID.transferUpload, 0x0001, "\(what) PDL \(pd.count)") }
        guard session != 0, !download else { violate("\(what) with no upload session (§13.2)"); return r(FTC.RS.modalError) }
        if pd[0] != session { violate("\(what) SessionID \(pd[0]), session is \(session)"); return r(FTC.RS.sessionIDMismatch, UInt32(pd[0]) << 16 | UInt32(session)) }
        if get { return r(complete ? FTC.RS.transferComplete : FTC.RS.statusOK) }
        let off = mgrU32(pd[1...]), data = Array(pd[5..<(pd.count - 2)]), crc = mgrU16(pd[(pd.count - 2)...])
        let calc = FTC.crc(pd.dropLast(2)), n = UInt32(data.count), index = Int(off) / Int(block)
        gate = (now + UInt64(interPacket), [FTC.PID.transferUpload], "Inter-Packet Delay")
        if crc != calc { violate("\(what) PacketCRC 0x\(String(crc, radix: 16)), should be 0x\(String(calc, radix: 16))"); return r(FTC.RS.packetCRCError, UInt32(crc) << 16 | UInt32(calc)) }
        if complete { violate("\(what) after TRANSFER_COMPLETE"); return r(FTC.RS.modalError) }
        if let b = busyAt, off == b, off + n == next, Array(received[Int(b)...]) == data { // re-sent after IN_PROGRESS: harmless
            busyAt = nil; return r(next == size ? FTC.RS.transferComplete : FTC.RS.statusOK)
        }
        if off != next { violate("\(what) DataOffset \(off), expected \(next)"); return r(FTC.RS.offsetError, next) }
        if off + n > size { violate("\(what) data beyond File Size \(size)"); return r(FTC.RS.fileSizeError, size) }
        if n > block || (n < block && off + n != size) { violate("\(what) \(n) bytes at \(off), TransferBlock Size \(block) (§13.2.1)"); return r(FTC.RS.unresolvedError) }
        attempts += 1
        if attempts > 4 { violate("packet \(index) sent \(attempts) times, resends limited to 3 (§13.2.2)") }
        if index == damagePacket && damageTimes > 0 { damageTimes -= 1; return r(FTC.RS.packetCRCError, UInt32(crc) << 16 | UInt32(~crc)) }
        received += data; next += n; attempts = 0; busyAt = nil; accBytes += n
        if next == size {
            complete = true; validatedAt = now + UInt64(validationDelay) + UInt64(validationExtra)
            gate = (now + UInt64(validationDelay), [FTC.PID.commit], "Validation Delay")
            if Self.pad(received, 16) != head { violate("SET:FTC_INITIATE File Data is not the file's first 16 bytes") }
            if FTC.crc(received) != fileCRC { violate("SET:FTC_INITIATE FileCRC 0x\(String(fileCRC, radix: 16)), file's is 0x\(String(FTC.crc(received), radix: 16))") }
            return r(FTC.RS.transferComplete)
        }
        if index == busyPacket { // §13.2.2: processing not complete; DataOffset not incremented
            busyPacket = -1; busyAt = off; gate = (now + UInt64(busyMs), [FTC.PID.transferUpload], "IN_PROGRESS delay")
            return r(FTC.RS.statusInProgress, busyMs, off)
        }
        if accCount > 0 && accBytes >= accCount {
            gate = (now + UInt64(interPacket) + UInt64(accDelay), [FTC.PID.transferUpload], "Inter-Packet + Accumulated Byte Delay")
        }
        return r(FTC.RS.statusOK)
    }

    // MARK: FTC_COMMIT (§13.3)

    private func commit(_ cc: UInt8, _ pd: [UInt8], get: Bool) -> FirmwareUpdate.Reply {
        guard pd.count == 3 else { return nack(cc, FTC.PID.commit, 0x0001, "FTC_COMMIT PDL \(pd.count), not 3") }
        let s = pd[0], cf = mgrU16(pd[1...]), test = flags & FTC.TF.testMode != 0, what = get ? "GET:FTC_COMMIT" : "SET:FTC_COMMIT"
        let calc = file.caps & FTC.Cap.processFileCRC != 0 ? FTC.crc(received) : 0
        let expected = test ? uid : newUID ?? uid
        func r(_ st: UInt8, _ data: UInt32 = 0) -> FirmwareUpdate.Reply {
            ack(cc, FTC.PID.commit, [st] + mgrBE32(data) + mgrBE16(cf) + mgrBE16(calc) + expected)
        }
        if s == FTC.DEF.sessionIDAll { violate("\(what) with FTC_DEF_SESSIONID_ALL (§13.3.1)") }
        guard session != 0, !download else { violate("\(what) with no upload session"); return r(FTC.RS.modalError) }
        if s != session { violate("\(what) SessionID \(s), session is \(session)"); return r(FTC.RS.sessionIDMismatch, UInt32(s) << 16 | UInt32(session)) }
        if cf != flags { violate("\(what) CommitFlags 0x\(String(cf, radix: 16)) != TransferFlags 0x\(String(flags, radix: 16))"); return r(FTC.RS.modalError) }
        if !complete { violate("\(what) before TRANSFER_COMPLETE (§13.3)"); return r(FTC.RS.modalError) }
        if now < validatedAt {
            let left = UInt32(validatedAt - now)
            gate = (now + UInt64(left), [FTC.PID.commit], "IN_PROGRESS delay")
            return r(FTC.RS.statusInProgress, left)
        }
        if calc != 0 && calc != fileCRC { return r(FTC.RS.fileCRCError, UInt32(fileCRC) << 16 | UInt32(calc)) }
        if validationFails { return r(FTC.RS.validationError, 0x42) }
        if get { return r(FTC.RS.statusOK, commitTime) }
        if let st = refuseCommit { return r(st) }
        let reply = r(FTC.RS.statusOK, commitTime)
        commits += 1; end()
        if !test { // §13.3: test mode reports the Commit Time but does not execute it
            saved = true; inBootloader = false; uid = expected
            offline = (now + UInt64(commitTime), "Commit Time")
        }
        return reply
    }

    // MARK: FTC_CANCEL (§13.4)

    private func cancel(_ cc: UInt8, _ pd: [UInt8]) -> FirmwareUpdate.Reply {
        guard pd.count == 1 else { return nack(cc, FTC.PID.cancel, 0x0001, "SET:FTC_CANCEL PDL \(pd.count), not 1") }
        func r(_ st: UInt8, _ data: UInt32 = 0) -> FirmwareUpdate.Reply { ack(cc, FTC.PID.cancel, [st] + mgrBE32(data)) }
        let s = pd[0]
        if session == 0 && s != FTC.DEF.sessionIDAll { return r(FTC.RS.modalError) } // §12.1.7: nothing to cancel
        if s != FTC.DEF.sessionIDAll && s != session { violate("SET:FTC_CANCEL SessionID \(s), session is \(session)"); return r(FTC.RS.sessionIDMismatch, UInt32(s) << 16 | UInt32(session)) }
        cancels += 1; end(); inBootloader = false
        return r(FTC.RS.statusOK)
    }

    // MARK: FTC_FILELIST (§13.5): five 43-byte entries per reply, ACK_OVERFLOW for the rest

    private func fileList(_ cc: UInt8, _ pd: [UInt8]) -> FirmwareUpdate.Reply {
        guard pd.isEmpty else { return nack(cc, FTC.PID.fileList, 0x0001, "GET:FTC_FILELIST PDL \(pd.count), not 0") }
        let page = files.dropFirst(listPage * 5).prefix(5), more = (listPage + 1) * 5 < files.count
        listPage = more ? listPage + 1 : 0
        return ack(cc, FTC.PID.fileList, page.flatMap {
            [$0.id] + mgrBE32($0.caps) + Self.pad(Array($0.description.utf8), 32) + Self.pad(Array($0.suffix.utf8), 6)
        }, type: more ? FTC.ackOverflow : FTC.ack)
    }

    // MARK: FTC_TRANSFER_DOWNLOAD (§13.6)

    private func downloadPacket(_ cc: UInt8, _ pd: [UInt8], _ t: UInt64) -> FirmwareUpdate.Reply {
        func r(_ st: UInt8, _ data: UInt32 = 0, _ bytes: [UInt8] = [], bad: Bool = false) -> FirmwareUpdate.Reply {
            let b = [st] + mgrBE32(data) + [session] + bytes, c = file.caps & FTC.Cap.generatePacketCRC != 0 ? FTC.crc(b) : 0
            return ack(cc, FTC.PID.transferDownload, b + mgrBE16(bad ? ~c : c))
        }
        guard pd.count == 6 else { return nack(cc, FTC.PID.transferDownload, 0x0001, "GET:FTC_TRANSFER_DOWNLOAD PDL \(pd.count), not 6") }
        let s = pd[0], cmd = pd[1]
        guard session != 0, download else { violate("GET:FTC_TRANSFER_DOWNLOAD with no download session (§13.6)"); return r(FTC.RS.modalError) }
        if s != session { violate("GET:FTC_TRANSFER_DOWNLOAD SessionID \(s), session is \(session)"); return r(FTC.RS.sessionIDMismatch, UInt32(s) << 16 | UInt32(session)) }
        if mgrU32(pd[2...]) != 0 { violate("GET:FTC_TRANSFER_DOWNLOAD DataOffset not 0 (§13.6.1)") }
        switch cmd {
        case FTC.TD.getNextPacket, FTC.TD.resendLastPacket:
            if cmd == FTC.TD.getNextPacket {
                if complete { violate("FTC_TD_GET_NEXT_PACKET after TRANSFER_COMPLETE"); return r(FTC.RS.modalError) }
                last = next; attempts = 0
            } else {
                attempts += 1
                if attempts > 3 { violate("packet at \(last) re-requested \(attempts) times, limit 3 (§13.6.1)") }
            }
            let chunk = Array(file.data[Int(last)..<min(Int(last) + Int(block), file.data.count)])
            let index = Int(last) / Int(block), bad = index == damageDownload
            if bad { damageDownload = -1 }
            next = last + UInt32(chunk.count)
            gate = (now + UInt64(interPacket), [FTC.PID.transferDownload], "Inter-Packet Delay")
            if next == size { complete = true; crcGate = now + UInt64(validationDelay) }
            return r(next == size ? FTC.RS.transferComplete : FTC.RS.statusOK, 0, chunk, bad: bad)
        case FTC.TD.getFileCRC:
            if !complete { violate("FTC_TD_GET_FILE_CRC before TRANSFER_COMPLETE"); return r(FTC.RS.modalError) }
            if t < crcGate { violate("FTC_TD_GET_FILE_CRC \(crcGate - t) ms before the Validation Delay elapsed (§8.6.6)") }
            if file.caps & FTC.Cap.generateFileCRC == 0 { return r(FTC.RS.fileCRCNotSupported) }
            fileCRCRequests += 1
            var c = FTC.crc(file.data)
            if badFileCRCOnce { badFileCRCOnce = false; c ^= 0x5A5A }
            let reply = r(FTC.RS.downloadFileCRC, UInt32(c))
            end() // the session closes with the FileCRC (§9 download figure: FILE CRC → IDLE)
            return reply
        default:
            violate("GET:FTC_TRANSFER_DOWNLOAD command 0x\(String(cmd, radix: 16))")
            return r(FTC.RS.downloadCommandError, UInt32(cmd))
        }
    }
}

extension FirmwareUpdate {
    /// Drives the controller against `FTCResponder`. Prints one line per failed check; true when all pass.
    public static func selfTestFTC() -> Bool {
        var ok = true
        func check(_ name: String, _ cond: Bool, _ detail: @autoclosure () -> String = "") {
            if !cond { ok = false; print("  FTC \(name): FAIL \(detail())") }
        }
        func rig(_ r: FTCResponder) -> FirmwareUpdate {
            FirmwareUpdate(transport: { r.handle($0, $1, $2) }, sleep: { r.now += UInt64($0) })
        }
        func why(_ o: Outcome, _ r: FTCResponder, _ fu: FirmwareUpdate) -> String {
            "code \(o.code) status 0x\(String(o.result.status, radix: 16)) cancelled \(o.cancelled) | \(fu.lastLog) | violations \(r.violations): \(r.lastViolation)"
        }
        let set = FTC.setCommand, get = FTC.getCommand
        let upCaps = FTC.Cap.acceptUpload | FTC.Cap.processFileCRC | FTC.Cap.processPacketCRC | FTC.Cap.testModeSupported
        let dlCaps = FTC.Cap.acceptDownload | FTC.Cap.generateFileCRC | FTC.Cap.generatePacketCRC
        let image = (0..<1000).map { UInt8(truncatingIfNeeded: $0 &* 37 &+ $0 >> 3) }
        func uploader(_ caps: UInt32 = upCaps) -> FTCResponder {
            let r = FTCResponder([.init(id: 1, caps: caps, size: 4096)])
            r.block = 64; r.initialDelay = 50; r.interPacket = 3; r.accCount = 200; r.accDelay = 20
            r.validationDelay = 100; r.commitTime = 500
            return r
        }

        // Appendix D golden vector.
        let file: [UInt8] = [0xEC, 0xEF, 0x7B, 0xF0, 0x00, 0x00, 0x00, 0x03, 0x04, 0x6E, 0xD8, 0xCF, 0x05, 0xF0, 0xE0, 0xCF]
        let golden: [UInt8] = [0x7D, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10] + file + [0xB3, 0xDD, 0xCA, 0xB0]
        check("appendix D", FTC.crc(Array("123456789".utf8)) == 0x374B && FTC.crc(file) == 0xB3DD // MODBUS 0x4B37, low byte first
            && initiatePD(session: 0x7D, fileID: 1, flags: 0, size: 16, head: file, fileCRC: FTC.crc(file)) == golden)

        // Normal upload with every delay non-zero, Accumulated Byte Count not a multiple of the block, UID change.
        do {
            let r = uploader(); r.newUID = [0x12, 0x34, 0, 0, 0, 2]
            let fu = rig(r)
            var phases: [Phase] = []
            fu.progress = { p, _ in if !phases.contains(p) { phases.append(p) } }
            let o = fu.run(file: image, testMode: false)
            check("upload", o.ok && r.violations == 0, why(o, r, fu))
            check("upload phases", Array(phases.prefix(6)) == [.initiate, .waiting, .transferring, .validating, .committing, .rebooting], "\(phases)")
            check("upload CRC", r.received == image && o.result.fileCRC == FTC.crc(image) && o.result.responderCRC == o.result.fileCRC,
                  "ours 0x\(String(o.result.fileCRC, radix: 16)) fixture 0x\(String(o.result.responderCRC, radix: 16))")
            check("upload commit", r.commits == 1 && r.saved && r.sent(set, FTC.PID.commit).count == 1, "commits \(r.commits)")
            check("upload ExpectedUID", o.result.expectedUID == [0x12, 0x34, 0, 0, 0, 2] && o.result.commitTime == 500, "\(o.result.expectedUID)")
            // run() returns once the Commit Time is over (§9.4): the fixture answers again at once.
            let back = r.handle(get, FTC.PID.initiate, [0, 0] + mgrBE16(FTC.version) + [0, 0])
            check("upload Commit Time", back != nil && r.violations == 0, r.lastViolation)
        }

        // Example B-3: the fixture needs more time for a packet and for validation (IN_PROGRESS).
        do {
            let r = uploader(); r.busyPacket = 4; r.busyMs = 250; r.validationExtra = 300
            let fu = rig(r)
            let o = fu.run(file: image, testMode: false)
            check("upload IN_PROGRESS", o.ok && r.violations == 0 && r.received == image && r.commits == 1, why(o, r, fu))
        }

        // Test mode.
        do {
            let r = uploader(), fu = rig(r)
            let o = fu.run(file: image, testMode: true)
            let tf = r.sent(set, FTC.PID.initiate).first.map { mgrU16($0[4...]) } ?? 0
            let cf = r.sent(set, FTC.PID.commit).first.map { mgrU16($0[1...]) } ?? 0
            check("test mode", o.ok && r.violations == 0 && tf & FTC.TF.testMode != 0 && cf == tf && r.commits == 1 && !r.saved,
                  "flags 0x\(String(tf, radix: 16))/0x\(String(cf, radix: 16)) " + why(o, r, fu))
        }

        // One damaged packet: one resend.
        do {
            let r = uploader(); r.damagePacket = 3; r.damageTimes = 1
            let fu = rig(r)
            let o = fu.run(file: image, testMode: false)
            check("one damaged packet", o.ok && o.result.resends == 1 && r.received == image && r.violations == 0, "resends \(o.result.resends) " + why(o, r, fu))
        }

        // A packet damaged on every try: three resends (§13.2.2), then cancel.
        do {
            let r = uploader(); r.damagePacket = 3; r.damageTimes = 99
            let fu = rig(r)
            let o = fu.run(file: image, testMode: false)
            check("too many resends", o.code == .tooManyResends && r.sent(set, FTC.PID.cancel).count == 1 && r.session == 0
                  && r.commits == 0 && r.violations == 0, why(o, r, fu))
        }

        // Cancel mid-transfer.
        do {
            let r = uploader(), fu = rig(r)
            r.onRequest = { cc, pid, _ in if cc == set && pid == FTC.PID.transferUpload && r.sent(set, pid).count == 5 { fu.cancel() } }
            let o = fu.run(file: image, testMode: false)
            check("cancel mid-transfer", o.cancelled && r.sent(set, FTC.PID.cancel).count == 1 && r.cancels == 1 && r.commits == 0
                  && r.session == 0 && r.violations == 0, why(o, r, fu))
        }

        // Cancel just before commit.
        do {
            let r = uploader(), fu = rig(r)
            r.onRequest = { cc, pid, _ in if cc == get && pid == FTC.PID.commit { fu.cancel() } }
            let o = fu.run(file: image, testMode: false)
            check("cancel before commit", !r.sent(get, FTC.PID.commit).isEmpty && o.cancelled && r.sent(set, FTC.PID.commit).isEmpty
                  && r.sent(set, FTC.PID.cancel).count == 1 && r.commits == 0 && r.violations == 0,
                  "GET/SET:FTC_COMMIT \(r.sent(get, FTC.PID.commit).count)/\(r.sent(set, FTC.PID.commit).count) cancels \(r.sent(set, FTC.PID.cancel).count)/\(r.cancels) session \(r.session) " + why(o, r, fu))
        }

        // Validation failure, and a refused commit: the status is reported and the session abandoned (§7.2, §13.4).
        for (name, refuse) in [("validation error", nil), ("commit refused", FTC.RS.writeProtect)] as [(String, UInt8?)] {
            let r = uploader(); r.validationFails = refuse == nil; r.refuseCommit = refuse
            let fu = rig(r)
            let o = fu.run(file: image, testMode: false)
            check(name, o.code == .status && o.result.status == (refuse ?? FTC.RS.validationError) && r.commits == 0
                  && r.sent(set, FTC.PID.cancel).count == 1 && r.session == 0 && r.violations == 0, why(o, r, fu))
        }

        // Single-file fixture: wrong FileID, file too big, test mode not supported.
        do {
            let r = uploader(), fu = rig(r)
            let o = fu.run(file: image, testMode: false, fileID: 9)
            check("unsupported FileID", !o.ok && r.commits == 0 && r.violations == 0, why(o, r, fu))
        }
        do {
            let r = uploader(), fu = rig(r)
            let o = fu.run(file: [UInt8](repeating: 1, count: 5000), testMode: false)
            check("too big", o.code == .tooBig && r.sent(set, FTC.PID.initiate).isEmpty && r.violations == 0, why(o, r, fu))
        }
        do {
            let r = uploader(upCaps & ~FTC.Cap.testModeSupported), fu = rig(r)
            let o = fu.run(file: image, testMode: true)
            check("no test mode", o.code == .noTestMode && r.sent(set, FTC.PID.initiate).isEmpty && r.violations == 0, why(o, r, fu))
        }

        // Multi-file fixture: 7 files (two FTC_FILELIST replies), a bootloader file, download files.
        let dlData = (0..<700).map { UInt8(truncatingIfNeeded: $0 &* 13 &+ 5) }
        func multi() -> FTCResponder {
            let r = FTCResponder([
                .init(id: 1, caps: upCaps, size: 4096, description: "Main firmware", suffix: "bin"),
                .init(id: 2, caps: upCaps | FTC.Cap.acceptDownload, size: 300, data: Array(dlData.prefix(300)), description: "Config", suffix: "cfg"),
                .init(id: 3, caps: dlCaps, data: dlData, description: "Event log", suffix: "log"),
                .init(id: 4, caps: dlCaps | FTC.Cap.downloadKey, data: dlData, description: "Calibration", suffix: "cal", key: [1, 2, 3]),
                .init(id: 5, caps: FTC.Cap.acceptDownload | FTC.Cap.generatePacketCRC, data: dlData, description: "No FileCRC", suffix: "raw"),
                .init(id: 6, caps: upCaps | FTC.Cap.bootloaderSwitch | FTC.Cap.failMayBrick, size: 8192, description: "Bootloader image, 32 chars long", suffix: "fwimg1"),
                .init(id: 0x20, caps: FTC.Cap.acceptUpload, size: 64, description: "Curve", suffix: "crv"),
            ])
            r.block = 100; r.initialDelay = 20; r.interPacket = 5; r.validationDelay = 30; r.commitTime = 200; r.switchDelay = 300
            return r
        }
        do {
            let r = multi(), fu = rig(r)
            let list = fu.fileList() ?? []
            let want = r.files.map { FixtureFile(id: $0.id, capabilities: $0.caps, size: $0.caps & FTC.Cap.acceptUpload != 0 ? $0.size : UInt32($0.data.count),
                                                 description: $0.description, suffix: $0.suffix) }
            check("file list", list == want && r.sent(get, FTC.PID.fileList).count == 2 && r.violations == 0,
                  "got \(list.map { "\($0.id) \($0.size) '\($0.description)'.\($0.suffix)" }) | \(fu.lastLog) | \(r.lastViolation)")
        }
        do {
            let r = multi(), fu = rig(r)
            let o = fu.run(file: image, testMode: false)
            check("FileID 0 on multi-file", o.code == .multipleFiles && r.sent(set, FTC.PID.initiate).isEmpty && r.violations == 0, why(o, r, fu))
        }
        do {
            let r = multi(), fu = rig(r)
            let o = fu.run(file: image, testMode: false, fileID: 6)
            let ids = (r.sent(set, FTC.PID.initiate) + r.sent(get, FTC.PID.initiate)).map { $0[1] }
            check("bootloader switch", o.ok && r.switches == 1 && o.result.bootloaderSwitches == 1 && r.received == image
                  && r.sent(set, FTC.PID.initiate).count == 2 && ids.allSatisfy { $0 == 6 } && r.violations == 0, "FileIDs \(ids) " + why(o, r, fu))
        }

        // Downloads.
        func down(_ name: String, _ id: UInt8 = 3, setup: (FTCResponder, FirmwareUpdate) -> Void = { _, _ in },
                  _ expect: (Outcome, [UInt8], FTCResponder, FirmwareUpdate) -> Bool) {
            let r = multi(), fu = rig(r)
            setup(r, fu)
            let (o, bytes) = fu.download(fileID: id)
            check(name, expect(o, bytes, r, fu) && r.violations == 0, "\(bytes.count) bytes " + why(o, r, fu))
        }
        down("download") { o, b, r, _ in o.ok && b == dlData && o.result.responderCRC == FTC.crc(dlData) && o.result.fileCRC == FTC.crc(dlData) && r.fileCRCRequests == 1 }
        down("download damaged packet", setup: { r, _ in r.damageDownload = 2 }) { o, b, _, _ in o.ok && b == dlData && o.result.resends == 1 }
        down("download FileCRC mismatch", setup: { r, _ in r.badFileCRCOnce = true }) { o, b, r, _ in o.ok && b == dlData && r.downloadInitiates == 2 }
        down("download strict", setup: { _, fu in fu.strict = true }) { o, b, _, fu in o.ok && b == dlData && fu.strictAbort == nil }
        down("download no FileCRC", 5) { o, b, r, _ in o.ok && b == dlData && r.fileCRCRequests == 0 }
        down("download cancel", setup: { r, fu in
            r.onRequest = { cc, pid, _ in if pid == FTC.PID.transferDownload && r.sent(cc, pid).count == 3 { fu.cancel() } }
        }) { o, _, r, _ in o.cancelled && r.sent(set, FTC.PID.cancel).count == 1 && r.session == 0 }
        down("download needs key", 4) { o, _, r, _ in o.code == .needKey && r.downloadInitiates == 0 }
        down("download upload-only file", 1) { o, _, r, _ in o.code == .noDownload && r.downloadInitiates == 0 }
        return ok
    }
}
