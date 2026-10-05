import Foundation

/// RDM file transfer (ANSI E1.37-4-2026 File Transfer Control) controller: upload, download and FTC_FILELIST.
/// `run`, `download` and `fileList` are synchronous: call them off the main queue. The transport sends one RDM request
/// to the fixture's root (§5.8) and returns the reply (nil = no reply); `sleep` waits real or virtual milliseconds.
/// The app passes `managerTransport`, the self-test an emulator; everything else is the same code path.
///
/// Cancel: `cancel()` makes the next request or delay slice stop the transfer, which then sends SET:FTC_CANCEL if a
/// session is open (§13.4). Once SET:FTC_COMMIT is sent, cancel is ignored.
public final class FirmwareUpdate {
    public struct Reply {
        var type: Int32, cc: UInt8, pid: UInt16, pd: [UInt8]
        init(type: Int32, cc: UInt8, pid: UInt16, pd: [UInt8]) { self.type = type; self.cc = cc; self.pid = pid; self.pd = pd }
    }
    public typealias Transport = (_ cc: UInt8, _ pid: UInt16, _ pd: [UInt8]) -> Reply?

    public enum Phase: String { case initiate = "Initiate", waiting = "Waiting", transferring = "Transferring",
                         validating = "Validating", committing = "Committing", rebooting = "Rebooting", checking = "Checking" }

    enum Code: Error {
        case ok, cancelled, noReply, nack, ackTimer, badReply, status, multipleFiles, noUpload, noTestMode, tooBig
        case badDeclaration, tooManyResends, noTransferComplete, tooManyPolls, noDownload, needKey, fileCRCMismatch
    }

    public struct Result {
        /// Last ResponseStatus / ResponseData the fixture sent (FTC_CANCEL's excluded).
        var status: UInt8 = 0
        var data: UInt32 = 0
        /// The SET:FTC_INITIATE declarations of the (last) session.
        public var declared = FTC.Declarations()
        /// Ours over the file sent or received; the fixture's (CalculatedFileCRC on upload, FileCRC on download).
        public var fileCRC: UInt16 = 0
        public var responderCRC: UInt16 = 0
        var resends = 0
        var bootloaderSwitches = 0
        var commitTime: UInt32 = 0
        var expectedUID: [UInt8] = []
    }

    public struct Outcome {
        var code: Code
        public var result: Result
        var cancelled: Bool
        public var ok: Bool { code == .ok && !cancelled }
    }

    /// One file the fixture offers (FTC_FILELIST entry, size from GET:FTC_INITIATE for it).
    public struct FixtureFile: Hashable {
        public var id: UInt8
        public var capabilities: UInt32
        public var size: UInt32
        public var description: String
        public var suffix: String
        public var acceptsUpload: Bool { capabilities & FTC.Cap.acceptUpload != 0 }
        public var testModeOK: Bool { capabilities & FTC.Cap.testModeSupported != 0 }
        public var acceptsDownload: Bool { capabilities & FTC.Cap.acceptDownload != 0 }
        public var needsKey: Bool { capabilities & FTC.Cap.downloadKey != 0 }
        var hasFileCRC: Bool { capabilities & FTC.Cap.generateFileCRC != 0 }
    }

    /// Main queue only: one transfer (upload or download) at a time, app-wide. The Manager holds back other RDM meanwhile.
    public static var active = false

    /// Bounds on IN_PROGRESS polls per step, PacketCRC resends per packet (§13.2.2, §13.6.1), bootloader switches.
    static let maxPolls = 1000, maxResends = 3, maxSwitches = 3

    private let transport: Transport
    private let sleep: (UInt32) -> Void
    /// Phase and bytes the fixture has confirmed, called on the thread running the transfer.
    public var progress: (Phase, UInt32) -> Void = { _, _ in }
    /// Every request sent, for tests (cc, pid, pd).
    var sentLog: ((UInt8, UInt16, [UInt8]) -> Void)?
    private(set) var lastLog = ""
    /// Abort (and cancel) on any surprise: NACK or another non-ACK reply, SWITCH_TO_BOOTLOADER or MODAL_ERROR.
    /// For a first download from a real fixture, where the safe reaction to a surprise is to stop.
    var strict = false
    private(set) var strictAbort: String?

    private let lock = NSLock()
    private var cancelFlag = false, commitSent = false
    private var session: UInt8 = 0, flags: UInt16 = 0, sessionOpen = false
    private var result = Result()

    public init(transport: @escaping Transport, sleep: @escaping (UInt32) -> Void) {
        self.transport = transport
        self.sleep = sleep
    }

    public func cancel() { lock.lock(); cancelFlag = true; lock.unlock() }
    private var stopping: Bool { lock.lock(); defer { lock.unlock() }; return cancelFlag && !commitSent }

    // MARK: - Upload

    /// Upload `file` to FileID `fileID` (0 = the fixture's only file).
    public func run(file: [UInt8], testMode: Bool, fileID: UInt8 = 0, session: UInt8 = .random(in: 1...0xFE)) -> Outcome {
        transfer(session, flags: testMode ? FTC.TF.testMode : 0) {
            progress(.initiate, 0)
            let g = try declarations(fileID, flags)
            guard g.fileID != FTC.DEF.multipleFileID else { throw Code.multipleFiles }
            guard g.capabilities & FTC.Cap.acceptUpload != 0 else { throw Code.noUpload }
            guard !testMode || g.capabilities & FTC.Cap.testModeSupported != 0 else { throw Code.noTestMode }
            guard let size = UInt32(exactly: file.count), g.fileSize == 0 || size <= g.fileSize else { throw Code.tooBig }
            result.fileCRC = FTC.crc(file)
            let d = try initiate(fileID == 0 ? g.fileID : fileID, size: size, head: Array(file.prefix(16)), fileCRC: result.fileCRC)
            guard (1...FTC.maxUploadBlock).contains(d.blockSize) else { throw fail(.badDeclaration, "block size \(d.blockSize)") }

            progress(.waiting, 0)
            try wait(d.initialDelay)
            progress(.transferring, 0)
            var offset = 0, accumulated: UInt32 = 0, resends = 0
            send: while true {
                let chunk = file[offset..<min(offset + Int(d.blockSize), file.count)]
                var pd = [session] + mgrBE32(UInt32(offset)) + chunk
                pd += mgrBE16(FTC.crc(pd))
                // IN_PROGRESS: wait, then ask GET:FTC_TRANSFER_UPLOAD how the packet went (§13.2.2, §13.2.3).
                let r = try poll(FTC.setCommand, FTC.PID.transferUpload, pd, min: 9, next: (FTC.getCommand, [session]))
                switch r[0] {
                case FTC.RS.packetCRCError:
                    resends += 1; result.resends += 1
                    guard resends <= Self.maxResends else { throw fail(.tooManyResends, "packet at \(offset)") }
                    try wait(UInt32(d.interPacketDelay))
                case FTC.RS.statusOK, FTC.RS.transferComplete:
                    resends = 0
                    offset += chunk.count
                    progress(.transferring, UInt32(offset))
                    if r[0] == FTC.RS.transferComplete { break send } // §9.2: that's the end, whatever we think is left
                    guard offset < file.count else { throw fail(.noTransferComplete, "all \(offset) bytes sent") }
                    try wait(UInt32(d.interPacketDelay))
                    // §8.6.4/§8.6.5: counts file bytes the fixture accepted; the counter restarts at 0 after each delay.
                    accumulated += UInt32(chunk.count)
                    if d.accumulatedByteCount > 0, d.accumulatedByteDelay > 0, accumulated >= d.accumulatedByteCount {
                        accumulated = 0
                        try wait(UInt32(d.accumulatedByteDelay))
                    }
                default: throw fail(.status, "SET:FTC_TRANSFER_UPLOAD at \(offset)")
                }
            }

            progress(.validating, UInt32(file.count))
            try wait(UInt32(d.validationDelay))
            let commitPD = [session] + mgrBE16(flags)
            // GET:FTC_COMMIT first, so a failed validation can still be cancelled before anything is saved (§9.4).
            var c = try poll(FTC.getCommand, FTC.PID.commit, commitPD, min: 15)
            guard c[0] == FTC.RS.statusOK else { throw fail(.status, "GET:FTC_COMMIT") }
            progress(.committing, UInt32(file.count))
            c = try poll(FTC.setCommand, FTC.PID.commit, commitPD, min: 15)
            guard c[0] == FTC.RS.statusOK else { sessionOpen = true; throw fail(.status, "SET:FTC_COMMIT") }
            result.commitTime = result.data
            result.responderCRC = mgrU16(c[7...])
            result.expectedUID = Array(c[9..<15]) // recorded for the caller; the transport can't rediscover (§13.3.4)
            progress(.rebooting, UInt32(file.count))
            // §9.4: no traffic during Commit Time, not sliced. §13.3: test mode reports it but doesn't execute it.
            if !testMode { sleep(min(result.commitTime, FTC.maxDelay)) }
        }
    }

    // MARK: - Download

    /// Download FileID `fileID` (0 = the fixture's only file). Returns the outcome and the bytes received; on success
    /// `result.fileCRC` is our CRC of them, equal to `result.responderCRC` when the fixture generates a FileCRC.
    public func download(fileID: UInt8, maxSize: UInt32 = 16 << 20, session: UInt8 = .random(in: 1...0xFE)) -> (Outcome, [UInt8]) {
        var data: [UInt8] = []
        let o = transfer(session, flags: FTC.TF.download) {
            progress(.initiate, 0)
            let g = try declarations(fileID, flags)
            guard g.fileID != FTC.DEF.multipleFileID else { throw Code.multipleFiles }
            guard g.capabilities & FTC.Cap.acceptDownload != 0 else { throw Code.noDownload }
            guard g.capabilities & FTC.Cap.downloadKey == 0 else { throw Code.needKey } // §9.6: no keys here
            guard g.fileSize <= maxSize else { throw Code.tooBig }
            for _ in 0..<3 { // §13.6.1: at most three restarts of a file whose FileCRC mismatches
                data = []
                let d = try initiate(fileID == 0 ? g.fileID : fileID, size: 0, head: [], fileCRC: 0)
                guard (1...FTC.maxDownloadBlock).contains(d.blockSize) else { throw fail(.badDeclaration, "block size \(d.blockSize)") }
                guard d.fileSize <= maxSize else { throw Code.tooBig }
                progress(.waiting, 0)
                try wait(d.initialDelay)
                progress(.transferring, 0)
                var command = FTC.TD.getNextPacket, resends = 0
                while true {
                    // IN_PROGRESS gave no data, so the same command goes again after the wait (§13.6.2).
                    let r = try poll(FTC.getCommand, FTC.PID.transferDownload, [session, command, 0, 0, 0, 0], min: 8)
                    guard r[0] == FTC.RS.statusOK || r[0] == FTC.RS.transferComplete else { throw fail(.status, "GET:FTC_TRANSFER_DOWNLOAD") }
                    guard r[5] == session else { throw fail(.badReply, "download reply for session \(r[5])") }
                    if d.capabilities & FTC.Cap.generatePacketCRC != 0, FTC.crc(r.dropLast(2)) != mgrU16(r.suffix(2)) {
                        resends += 1; result.resends += 1
                        guard resends <= Self.maxResends else { throw fail(.tooManyResends, "packet after \(data.count)") }
                        command = FTC.TD.resendLastPacket
                        try wait(UInt32(d.interPacketDelay))
                        continue
                    }
                    resends = 0
                    command = FTC.TD.getNextPacket
                    data += r[6..<(r.count - 2)]
                    guard data.count <= maxSize else { throw Code.tooBig }
                    progress(.transferring, UInt32(data.count))
                    if r[0] == FTC.RS.transferComplete { break }
                    try wait(UInt32(d.interPacketDelay))
                }
                result.fileCRC = FTC.crc(data)
                guard d.capabilities & FTC.Cap.generateFileCRC != 0 else { sessionOpen = false; return }
                progress(.checking, UInt32(data.count))
                try wait(UInt32(d.validationDelay))
                let c = try poll(FTC.getCommand, FTC.PID.transferDownload, [session, FTC.TD.getFileCRC, 0, 0, 0, 0], min: 8)
                guard c[0] == FTC.RS.downloadFileCRC else { throw fail(.status, "FTC_TD_GET_FILE_CRC") }
                sessionOpen = false // the fixture is idle again after the FileCRC (§9 download figure)
                result.responderCRC = UInt16(truncatingIfNeeded: result.data)
                if result.responderCRC == result.fileCRC { return }
            }
            throw fail(.fileCRCMismatch, "FileCRC ours 0x\(String(result.fileCRC, radix: 16)) fixture 0x\(String(result.responderCRC, radix: 16))")
        }
        return (o, o.ok ? data : [])
    }

    // MARK: - File list

    /// FTC_FILELIST (with each file's size), or the single file when the fixture has no list. nil = no answer.
    public func fileList() -> [FixtureFile]? {
        guard let g = try? declarations(FTC.DEF.noFileIDOffered, 0) else { return nil }
        var files = [FixtureFile(id: g.fileID, capabilities: g.capabilities, size: 0, description: "", suffix: "")]
        if g.fileID == FTC.DEF.multipleFileID {
            var list: [UInt8] = []
            for _ in 0..<64 { // ACK_OVERFLOW: the same GET again until the plain ACK ([RDM] ACK_OVERFLOW)
                guard let r = try? ask(FTC.getCommand, FTC.PID.fileList, [], min: 0) else { return nil }
                list += r.pd
                if r.type == FTC.ack { break }
            }
            let text = { (b: ArraySlice<UInt8>) in String(decoding: b.prefix { $0 != 0 }, as: UTF8.self).trimmingCharacters(in: .whitespaces) }
            files = stride(from: 0, to: list.count - 42, by: 43).map { i in // §13.5.2: 43-byte entries
                FixtureFile(id: list[i], capabilities: mgrU32(list[(i + 1)...]), size: 0,
                            description: text(list[(i + 5)..<(i + 37)]), suffix: text(list[(i + 37)..<(i + 43)]))
            }
        }
        // Size: a download's File Size is the file's; an upload's is what the fixture can take (§13.1.2).
        return files.map { f in
            var f = f
            f.size = (try? declarations(f.id, f.acceptsDownload ? FTC.TF.download : 0))?.fileSize ?? 0
            return f
        }
    }

    // MARK: - Steps

    /// Runs one transfer: fresh state, errors to the outcome, SET:FTC_CANCEL if a session is still open (§13.2.2, §13.4).
    private func transfer(_ session: UInt8, flags: UInt16, _ body: () throws -> Void) -> Outcome {
        self.session = session
        self.flags = flags
        result = Result()
        sessionOpen = false
        var code = Code.ok
        do { try body() } catch let c as Code { code = c } catch { code = .badReply }
        let cancelled = stopping
        if code != .ok || cancelled, sessionOpen { sendCancel() }
        return Outcome(code: code, result: result, cancelled: cancelled)
    }

    /// GET:FTC_INITIATE for `fileID` in direction `flags`, no session (§13.1.1).
    private func declarations(_ fileID: UInt8, _ flags: UInt16) throws -> FTC.Declarations {
        let r = try ask(FTC.getCommand, FTC.PID.initiate, [FTC.DEF.noSessionIDOffered, fileID] + mgrBE16(FTC.version) + mgrBE16(flags)).pd
        guard r[0] == FTC.RS.statusOK else { throw fail(.status, "GET:FTC_INITIATE") }
        guard let d = FTC.Declarations(r) else { throw fail(.badReply, "GET:FTC_INITIATE \(r.count) bytes") }
        return d
    }

    /// SET:FTC_INITIATE (§13.1.3), again after each bootloader switch with the same SessionID (§12.1.5). Opens the session.
    private func initiate(_ fileID: UInt8, size: UInt32, head: [UInt8], fileCRC: UInt16) throws -> FTC.Declarations {
        let pd = Self.initiatePD(session: session, fileID: fileID, flags: flags, size: size, head: head, fileCRC: fileCRC)
        let ok = flags & FTC.TF.download != 0 ? FTC.RS.initOKDL : FTC.RS.initOKUL
        while true {
            sessionOpen = true
            let r = try ask(FTC.setCommand, FTC.PID.initiate, pd).pd
            if r[0] == FTC.RS.switchToBootloader { // everything else in this reply is ignored (§12.1.5)
                guard result.data <= FTC.maxDelay else { throw fail(.badDeclaration, "bootloader delay \(result.data)") }
                guard result.bootloaderSwitches < Self.maxSwitches else { throw fail(.status, "bootloader switch again") }
                result.bootloaderSwitches += 1
                progress(.waiting, 0)
                try wait(result.data)
                progress(.initiate, 0)
                continue
            }
            if r[0] == FTC.RS.statusOK, r.count > 6, r[6] == FTC.DEF.multipleFileID { throw Code.multipleFiles }
            guard r[0] == ok else { throw fail(.status, "SET:FTC_INITIATE") }
            guard let d = FTC.Declarations(r), d.session == session else { throw fail(.badReply, "SET:FTC_INITIATE reply") }
            guard d.initialDelay <= FTC.maxDelay else { throw fail(.badDeclaration, "initial delay \(d.initialDelay)") } // §8.6.2: cancel
            result.declared = d
            return d
        }
    }

    /// SET:FTC_INITIATE parameter data (§13.1.3): file head zero-padded to 16 bytes, PacketCRC over the rest (§10.4).
    static func initiatePD(session: UInt8, fileID: UInt8, flags: UInt16, size: UInt32, head: [UInt8], fileCRC: UInt16) -> [UInt8] {
        var pd = [session, fileID] + mgrBE16(FTC.version) + mgrBE16(flags) + mgrBE32(size)
        pd += head.prefix(16) + [UInt8](repeating: 0, count: 16 - min(head.count, 16)) + mgrBE16(fileCRC)
        return pd + mgrBE16(FTC.crc(pd))
    }

    /// Sends a request; while the reply is IN_PROGRESS waits the time it asks for (§12.1.4) and sends `next`
    /// (default: the same request again).
    private func poll(_ cc: UInt8, _ pid: UInt16, _ pd: [UInt8], min: Int, next: (UInt8, [UInt8])? = nil) throws -> [UInt8] {
        var r = try ask(cc, pid, pd, min: min).pd
        var n = 0
        while r[0] == FTC.RS.statusInProgress {
            n += 1
            guard result.data <= FTC.maxDelay else { throw fail(.badDeclaration, "IN_PROGRESS \(result.data) ms") } // §12.1.4: cancel
            guard n <= Self.maxPolls else { throw fail(.tooManyPolls, "PID 0x\(String(pid, radix: 16))") }
            try wait(result.data)
            r = try ask(next?.0 ?? cc, pid, next?.1 ?? pd, min: min).pd
        }
        return r
    }

    /// One request. Only an ACK (or ACK_OVERFLOW for FTC_FILELIST) to the same PID with at least `min` bytes gets through.
    /// ACK_TIMER is the transport's job ([RDM] proxies, §5.5); here it ends the transfer.
    private func ask(_ cc: UInt8, _ pid: UInt16, _ pd: [UInt8], min: Int = 5) throws -> Reply {
        if stopping { throw Code.cancelled }
        // Once SET:FTC_COMMIT is on its way, only a refusal reopens the session for a cancel (§9.5).
        if cc == FTC.setCommand, pid == FTC.PID.commit { lock.lock(); commitSent = true; lock.unlock(); sessionOpen = false }
        sentLog?(cc, pid, pd)
        let what = "\(cc == FTC.setCommand ? "SET" : "GET") PID 0x\(String(pid, radix: 16))"
        guard let r = transport(cc, pid, pd) else { throw fail(.noReply, "no reply to \(what)") }
        guard r.type == FTC.ack || r.type == FTC.ackOverflow && pid == FTC.PID.fileList else {
            if strict { strictAbort = "NACK or unexpected response type \(r.type) to \(what)" }
            throw fail(r.type == FTC.nack ? .nack : r.type == FTC.ackTimer ? .ackTimer : .badReply, "response type \(r.type) to \(what)")
        }
        guard r.cc == cc + 1, r.pid == pid, r.pd.count >= min else { throw fail(.badReply, "malformed reply to \(what)") }
        guard pid != FTC.PID.fileList else { return r }
        result.status = r.pd[0]
        result.data = mgrU32(r.pd[1...])
        if strict, r.pd[0] == FTC.RS.switchToBootloader || r.pd[0] == FTC.RS.modalError {
            strictAbort = "status 0x\(String(r.pd[0], radix: 16)) to \(what)"
            throw fail(.status, strictAbort!)
        }
        return r
    }

    /// SET:FTC_CANCEL for our session (§13.4.1). An IN_PROGRESS reply isn't waited on: nothing follows it.
    private func sendCancel() {
        sessionOpen = false
        sentLog?(FTC.setCommand, FTC.PID.cancel, [session])
        _ = transport(FTC.setCommand, FTC.PID.cancel, [session])
    }

    /// Waits in 50 ms slices so a cancel doesn't sit out a long declared delay.
    private func wait(_ ms: UInt32) throws {
        var left = ms
        while left > 0 {
            if stopping { throw Code.cancelled }
            let slice = min(left, 50)
            sleep(slice)
            left -= slice
        }
    }

    private func fail(_ c: Code, _ why: String) -> Code {
        lastLog = "\(c): \(why) (status 0x\(String(result.status, radix: 16)), data 0x\(String(result.data, radix: 16)))"
        return c
    }

    // MARK: - App transport

    /// One tunnelled RDM request per call, through the app's Manager on the main queue; the worker blocks until the reply.
    /// The Manager follows ACK_TIMER itself (waits, then takes the late reply), so the controller only ever sees ACK,
    /// ACK_OVERFLOW or NACK here. Requests are marked `upload`, so they still go out while the Manager holds everything else back.
    /// `busySeconds`: how long to keep retrying while another panel holds the Manager.
    public static func managerTransport(_ manager: ManagerEngine, node: [UInt8], ep: UInt16, dest: [UInt8], busySeconds: Double = 2) -> Transport {
        { cc, pid, pd in
            for _ in 0..<max(1, Int(busySeconds / 0.05)) {
                var out: ManagerResult?
                let done = DispatchSemaphore(value: 0)
                DispatchQueue.main.async {
                    manager.rdm(node, ep: ep, dest: dest, set: cc == FTC.setCommand, pid: pid, pd: pd, upload: true) { r in out = r; done.signal() }
                }
                guard done.wait(timeout: .now() + 30) == .success, let r = out else { return nil }
                if r.text.hasPrefix("Busy") { Thread.sleep(forTimeInterval: 0.05); continue }
                let f = r.frame
                guard ManagerRDM.valid(f), f[20] & 1 == 1 else { return nil }
                return Reply(type: Int32(f[16]), cc: f[20], pid: mgrU16(f[21...]), pd: Array(f[24..<24 + Int(f[23])]))
            }
            return nil
        }
    }

    public static func realSleep(_ ms: UInt32) { Thread.sleep(forTimeInterval: Double(ms) / 1000) }

    // MARK: - Plain words

    /// What went wrong, for the main panel.
    public static func reason(_ o: Outcome) -> String {
        if o.cancelled { return "Cancelled. The fixture was told to end the transfer." }
        switch o.code {
        case .ok: return "Complete"
        case .cancelled: return "Cancelled."
        case .noReply: return "The fixture stopped answering."
        case .nack: return "The fixture refused a file-transfer request."
        case .ackTimer: return "The fixture asked for more time and never answered."
        case .badReply: return "The fixture sent an answer that didn't make sense."
        case .status: return statusText(o.result.status)
        case .multipleFiles: return "The fixture offers several files; choose one first."
        case .noUpload: return "The fixture doesn't accept uploads of this file."
        case .noTestMode: return "The fixture doesn't support test mode for this file."
        case .tooBig: return "The file is bigger than the fixture accepts."
        case .badDeclaration: return "The fixture asked for a block size or delay outside the standard's limits."
        case .tooManyResends: return "Packets kept arriving damaged, so the transfer was abandoned."
        case .noTransferComplete: return "All data was sent but the fixture never confirmed the transfer."
        case .tooManyPolls: return "The fixture stayed busy for too long."
        case .noDownload: return "The fixture doesn't offer this file for download."
        case .needKey: return "This file needs a download key, which this app can't send yet."
        case .fileCRCMismatch: return "The file kept arriving damaged (checksum mismatch after 3 tries)."
        }
    }

    public static func statusText(_ s: UInt8) -> String {
        switch s {
        case FTC.RS.modalError: return "The fixture wasn't ready for that step."
        case FTC.RS.sessionIDMismatch: return "The fixture is busy with another transfer."
        case FTC.RS.unsupportedFileID: return "The fixture doesn't accept this kind of file."
        case FTC.RS.fileNotCompatible: return "The fixture says this file isn't for it."
        case FTC.RS.fileNotAvailable: return "The fixture can't provide this file right now."
        case FTC.RS.packetCRCError: return "A packet arrived damaged."
        case FTC.RS.fileCRCError: return "The file arrived damaged (checksum mismatch)."
        case FTC.RS.validationError: return "The fixture checked the file and rejected it."
        case FTC.RS.e137LockActive, FTC.RS.otherLockActive: return "The fixture is locked against updates."
        case FTC.RS.writeProtect: return "The fixture's memory is write-protected."
        case FTC.RS.invalidDirection: return "The fixture doesn't accept uploads of this file."
        case FTC.RS.offsetError: return "The fixture lost its place in the file."
        case FTC.RS.fileSizeError: return "The file is bigger than the fixture accepts."
        case FTC.RS.ftcVersionError: return "The fixture uses a different version of the file-transfer standard."
        case FTC.RS.fileCRCNotSupported: return "The fixture can't check file checksums."
        case FTC.RS.downloadKeyRequired: return "This file needs a download key, which this app can't send yet."
        case FTC.RS.switchToBootloader: return "The fixture kept restarting into its loader."
        default: return "The fixture reported an error it didn't explain (status \(s))."
        }
    }
}
