import CFTC
import Foundation

/// RDM firmware upload (ANSI E1.37-4 File Transfer Control) through a tested controller (ftc.h, ftc_download.h).
/// `run` and `fileList` are synchronous: call them off the main queue. The transport sends one RDM request and returns
/// the reply (nil = no reply); `sleep` waits real or virtual milliseconds. The app passes `managerTransport`, the
/// self-test passes the in-process emulator; everything else is the same code path.
///
/// Cancel: `cancel()` makes every later request fail locally except FTC_CANCEL, so ftc_upload takes its own error
/// path and sends SET:FTC_CANCEL itself. Where it can't (a session open but the error came before ftc.h cancels,
/// e.g. on the way into SET:FTC_COMMIT) `run` calls ftc.h's `ftc_cancel`. Once SET:FTC_COMMIT is sent, cancel is ignored.
final class FirmwareUpdate {
    struct Reply { var type: Int32; var cc: UInt8; var pid: UInt16; var pd: [UInt8] }
    typealias Transport = (_ cc: UInt8, _ pid: UInt16, _ pd: [UInt8]) -> Reply?

    enum Phase: String { case initiate = "Initiate", waiting = "Waiting", transferring = "Transferring",
                         validating = "Validating", committing = "Committing", rebooting = "Rebooting", checking = "Checking" }

    struct Outcome {
        var code: Int
        var result: ftc_result
        var cancelled: Bool
        var ok: Bool { code == FTC_RESULT_OK && !cancelled }
    }

    /// One file the fixture offers (FTC_FILELIST entry, size from GET:FTC_INITIATE for it).
    struct FixtureFile: Hashable {
        var id: UInt8
        var capabilities: UInt32
        var size: UInt32
        var description: String
        var suffix: String
        var acceptsUpload: Bool { capabilities & UInt32(FTC_ACCEPT_UPLOAD) != 0 }
        var testModeOK: Bool { capabilities & UInt32(FTC_TESTMODE_SUPPORTED) != 0 }
        var acceptsDownload: Bool { capabilities & UInt32(FTC_ACCEPT_DOWNLOAD) != 0 }
        var needsKey: Bool { capabilities & UInt32(FTC_DOWNLOAD_KEY) != 0 }
        var hasFileCRC: Bool { capabilities & UInt32(FTC_GENERATE_FILECRC) != 0 }
    }

    /// Main queue only: one transfer (upload or download) at a time, app-wide. The Manager holds back other RDM meanwhile.
    static var active = false

    private let transport: Transport
    private let sleep: (UInt32) -> Void
    /// Phase and bytes the fixture has confirmed, called on the thread running `run`.
    var progress: (Phase, UInt32) -> Void = { _, _ in }
    /// Every request sent, for tests (cc, pid, pd).
    var sentLog: ((UInt8, UInt16, [UInt8]) -> Void)?
    private(set) var lastLog = ""

    private let lock = NSLock()
    private var cancelFlag = false
    private var file: [UInt8] = []
    private var sessionOpen = false, cancelSent = false, commitSent = false
    private var downloading = false, received: [UInt8] = []
    /// Abort (and cancel) on any reply outside the plain download flow: bootloader switch, MODAL_ERROR, NACK.
    /// For a first download from a real fixture, where the safe reaction to a surprise is to stop.
    var strict = false
    private(set) var strictAbort: String?

    init(transport: @escaping Transport, sleep: @escaping (UInt32) -> Void) {
        self.transport = transport
        self.sleep = sleep
    }

    func cancel() { lock.lock(); cancelFlag = true; lock.unlock() }
    private var stopping: Bool { lock.lock(); defer { lock.unlock() }; return cancelFlag && !commitSent }

    private func io() -> ftc_io {
        ftc_io(
            transaction: { ctx, cc, pid, pd, pdl, rpd, rpdl, rcc, rpid in
                FirmwareUpdate.me(ctx).txn(cc, pid, Array(UnsafeBufferPointer(start: pd, count: Int(pdl))), rpd!, rpdl!, rcc!, rpid!)
            },
            wait_ms: { ctx, ms in FirmwareUpdate.me(ctx).wait(ms) },
            log: { ctx, format, a, b in FirmwareUpdate.me(ctx).lastLog = "\(String(cString: format!)) [\(a), 0x\(String(b, radix: 16))]" },
            read_file: { ctx, offset, buffer, length in
                let me = FirmwareUpdate.me(ctx)
                for i in 0..<Int(length) { buffer![i] = me.file[Int(offset) + i] }
            },
            progress: { ctx, stage, bytes in FirmwareUpdate.me(ctx).stage(stage, bytes) },
            context: Unmanaged.passUnretained(self).toOpaque(),
            write_file: { ctx, offset, data, length in
                let me = FirmwareUpdate.me(ctx)
                if offset == 0 { me.received.removeAll() } // offset 0 again: the download restarted
                me.received += UnsafeBufferPointer(start: data, count: Int(length))
            })
    }

    private static func me(_ ctx: UnsafeMutableRawPointer?) -> FirmwareUpdate { Unmanaged.fromOpaque(ctx!).takeUnretainedValue() }

    /// Upload `file` to FileID `fileID` (0 = the fixture's only file).
    func run(file: [UInt8], testMode: Bool, fileID: UInt8 = 0, session: UInt8 = .random(in: 1...0xFE)) -> Outcome {
        self.file = file
        var io = io()
        var res = ftc_result()
        let code = withExtendedLifetime(self) {
            ftc_upload(&io, UInt32(file.count), fileID, session, UInt16(testMode ? FTC_TF_TESTMODE : 0), &res)
        }
        let cancelled = stopping
        if cancelled, sessionOpen, !cancelSent { ftc_cancel(&io, session) }
        return Outcome(code: Int(code), result: res, cancelled: cancelled)
    }

    /// Download FileID `fileID` (0 = the fixture's only file). Returns the outcome and the bytes received; on success
    /// `result.file_crc` is our CRC of them, equal to `result.responder_crc` when the fixture generates a FileCRC.
    func download(fileID: UInt8, maxSize: UInt32 = 16 << 20, session: UInt8 = .random(in: 1...0xFE)) -> (Outcome, [UInt8]) {
        downloading = true
        received = []
        var io = io()
        var res = ftc_result(), size: UInt32 = 0
        let code = withExtendedLifetime(self) { ftc_download(&io, fileID, session, nil, maxSize, &size, &res) }
        let cancelled = stopping
        if cancelled, sessionOpen, !cancelSent { ftc_cancel(&io, session) }
        return (Outcome(code: Int(code), result: res, cancelled: cancelled), code == FTC_RESULT_OK ? Array(received.prefix(Int(size))) : [])
    }

    /// FTC_FILELIST (with each file's size), or the single file when the fixture has no list. nil = no answer.
    func fileList() -> [FixtureFile]? {
        var io = io()
        var files = [ftc_file](repeating: ftc_file(), count: 80), multiple: Int32 = 0
        let n = withExtendedLifetime(self) { ftc_file_list(&io, &files, Int32(files.count), &multiple) }
        guard n >= 0 else { return nil }
        return files.prefix(Int(n)).map { f in
            var f = f
            let text = { (p: UnsafeRawPointer) in String(cString: p.assumingMemoryBound(to: CChar.self)) }
            return FixtureFile(id: f.file_id, capabilities: f.capabilities, size: f.size,
                               description: withUnsafeBytes(of: &f.description) { text($0.baseAddress!) },
                               suffix: withUnsafeBytes(of: &f.suffix) { text($0.baseAddress!) })
        }
    }

    private func stage(_ s: ftc_stage, _ bytes: UInt32) {
        let phase: Phase
        if downloading {
            switch Int(s.rawValue) {
            case Int(FTC_DOWNLOAD_STAGE_DECLARATIONS.rawValue), Int(FTC_DOWNLOAD_STAGE_INITIATE.rawValue): phase = .initiate
            case Int(FTC_DOWNLOAD_STAGE_BOOTLOADER_SWITCH.rawValue), Int(FTC_DOWNLOAD_STAGE_INITIAL_DELAY.rawValue): phase = .waiting
            case Int(FTC_DOWNLOAD_STAGE_TRANSFER.rawValue): phase = .transferring
            case Int(FTC_DOWNLOAD_STAGE_FILE_CRC.rawValue): phase = .checking
            default: return
            }
            return progress(phase, bytes)
        }
        switch s {
        case FTC_STAGE_FILE_CHECK, FTC_STAGE_DECLARATIONS, FTC_STAGE_INITIATE: phase = .initiate
        case FTC_STAGE_BOOTLOADER_SWITCH, FTC_STAGE_INITIAL_DELAY: phase = .waiting
        case FTC_STAGE_TRANSFER: phase = .transferring
        case FTC_STAGE_VALIDATION: phase = .validating
        case FTC_STAGE_COMMIT: phase = .committing
        case FTC_STAGE_COMMIT_TIME: phase = .rebooting
        default: return // FTC_STAGE_CANCELLED: the txn hook already saw the FTC_CANCEL
        }
        progress(phase, bytes)
    }

    private func txn(_ cc: UInt8, _ pid: UInt16, _ pd: [UInt8], _ rpd: UnsafeMutablePointer<UInt8>, _ rpdl: UnsafeMutablePointer<UInt8>,
                     _ rcc: UnsafeMutablePointer<UInt8>, _ rpid: UnsafeMutablePointer<UInt16>) -> Int32 {
        let ftcPID = Int32(pid), set = Int32(cc) == RDM_SET_COMMAND
        if ftcPID == FTC_CANCEL { cancelSent = true } else if stopping { return -1 }
        if ftcPID == FTC_COMMIT, set { lock.lock(); commitSent = true; lock.unlock() }
        sentLog?(cc, pid, pd)
        guard let r = transport(cc, pid, pd) else { return -1 }
        let n = min(r.pd.count, Int(RDM_PD_MAX))
        for i in 0..<n { rpd[i] = r.pd[i] }
        rpdl.pointee = UInt8(n); rcc.pointee = r.cc; rpid.pointee = r.pid
        if r.type == RDM_ACK, r.pid == pid, n >= 1, set {
            switch ftcPID {
            case FTC_INITIATE where Int32(r.pd[0]) == FTC_RS_INITOK_UL || Int32(r.pd[0]) == FTC_RS_INITOK_DL: sessionOpen = true
            case FTC_COMMIT where Int32(r.pd[0]) == FTC_RS_STATUS_OK, FTC_CANCEL: sessionOpen = false
            default: break
            }
        }
        if strict, ftcPID & Int32(FTC_PID_MASK) == FTC_INITIATE, ftcPID != FTC_CANCEL, ftcPID != FTC_FILELIST {
            let st = n >= 1 ? Int32(r.pd[0]) : -1
            if r.type != RDM_ACK && r.type != RDM_ACK_OVERFLOW { strictAbort = "NACK or unexpected response type \(r.type) to PID \(pid)" }
            else if st == FTC_RS_SWITCH_TO_BOOTLOADER || st == FTC_RS_MODAL_ERROR { strictAbort = "status \(String(cString: ftc_status_name(UInt32(st)))) to PID \(pid)" }
            if strictAbort != nil { cancel() } // the next request fails locally, so ftc.h cancels the session itself
        }
        return r.type
    }

    /// Waits in slices so a cancel doesn't sit out a long declared delay (but never during Commit Time).
    private func wait(_ ms: UInt32) {
        var left = ms
        while left > 0, !stopping {
            let slice = min(left, 50)
            sleep(slice)
            left -= slice
        }
    }

    // MARK: - App transport

    /// One tunnelled RDM request per call, through the app's Manager on the main queue; the worker blocks until the reply.
    /// The Manager follows ACK_TIMER itself (waits, then takes the late reply), so ftc.h only ever sees ACK, ACK_OVERFLOW
    /// or NACK here. Requests are marked `upload`, so they still go out while the Manager holds everything else back.
    /// `busySeconds`: how long to keep retrying while another panel holds the Manager.
    static func managerTransport(_ manager: Manager, node: [UInt8], ep: UInt16, dest: [UInt8], busySeconds: Double = 2) -> Transport {
        { cc, pid, pd in
            for _ in 0..<max(1, Int(busySeconds / 0.05)) {
                var out: ManagerResult?
                let done = DispatchSemaphore(value: 0)
                DispatchQueue.main.async {
                    manager.rdm(node, ep: ep, dest: dest, set: Int32(cc) == RDM_SET_COMMAND, pid: pid, pd: pd, upload: true) { r in out = r; done.signal() }
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

    static func realSleep(_ ms: UInt32) { Thread.sleep(forTimeInterval: Double(ms) / 1000) }

    // MARK: - Plain words

    /// What went wrong, for the main panel.
    static func reason(_ o: Outcome) -> String {
        if o.cancelled { return "Cancelled. The fixture was told to end the transfer." }
        switch o.code {
        case FTC_RESULT_OK: return "Complete"
        case FTC_RESULT_NO_REPLY: return "The fixture stopped answering."
        case FTC_RESULT_NACK: return "The fixture refused a file-transfer request."
        case FTC_RESULT_ACK_TIMER: return "The fixture asked for more time and never answered."
        case FTC_RESULT_BAD_REPLY: return "The fixture sent an answer that didn't make sense."
        case FTC_RESULT_STATUS: return statusText(Int32(o.result.status))
        case FTC_RESULT_MULTIPLE_FILES: return "The fixture offers several files; choose one first."
        case FTC_RESULT_NO_UPLOAD: return "The fixture doesn't accept uploads of this file."
        case FTC_RESULT_NO_TESTMODE: return "The fixture doesn't support test mode for this file."
        case FTC_RESULT_TOO_BIG: return "The file is bigger than the fixture accepts."
        case FTC_RESULT_BAD_DECLARATION: return "The fixture asked for a block size or delay outside the standard's limits."
        case FTC_RESULT_TOO_MANY_RESENDS: return "Packets kept arriving damaged, so the transfer was abandoned."
        case FTC_RESULT_NO_TRANSFER_COMPLETE: return "All data was sent but the fixture never confirmed the transfer."
        case FTC_RESULT_TOO_MANY_POLLS: return "The fixture stayed busy for too long."
        case FTC_RESULT_NO_DOWNLOAD: return "The fixture doesn't offer this file for download."
        case FTC_RESULT_NEED_KEY: return "This file needs a download key, which this app can't send yet."
        case FTC_RESULT_FILE_CRC_MISMATCH: return "The file kept arriving damaged (checksum mismatch after 3 tries)."
        default: return "Upload failed (code \(o.code))."
        }
    }

    static func statusText(_ s: Int32) -> String {
        switch s {
        case FTC_RS_MODAL_ERROR: return "The fixture wasn't ready for that step."
        case FTC_RS_SESSIONID_MISMATCH: return "The fixture is busy with another transfer."
        case FTC_RS_UNSUPPORTED_FILEID: return "The fixture doesn't accept this kind of file."
        case FTC_RS_FILE_NOT_COMPATIBLE: return "The fixture says this file isn't for it."
        case FTC_RS_PACKET_CRC_ERROR: return "A packet arrived damaged."
        case FTC_RS_FILE_CRC_ERROR: return "The file arrived damaged (checksum mismatch)."
        case FTC_RS_VALIDATION_ERROR: return "The fixture checked the file and rejected it."
        case FTC_RS_E137_LOCKACTIVE, FTC_RS_OTHER_LOCKACTIVE: return "The fixture is locked against updates."
        case FTC_RS_WRITE_PROTECT: return "The fixture's memory is write-protected."
        case FTC_RS_INVALID_DIRECTION: return "The fixture doesn't accept uploads of this file."
        case FTC_RS_OFFSET_ERROR: return "The fixture lost its place in the file."
        case FTC_RS_FILESIZE_ERROR: return "The file is bigger than the fixture accepts."
        case FTC_RS_FTCVERSION_ERROR: return "The fixture uses a different version of the file-transfer standard."
        case FTC_RS_FILE_CRC_NOT_SUPPORTED: return "The fixture can't check file checksums."
        default: return "The fixture reported an error it didn't explain (status \(s))."
        }
    }
}
