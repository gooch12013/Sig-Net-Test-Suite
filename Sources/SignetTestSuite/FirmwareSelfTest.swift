import CFTC
import Foundation

extension FirmwareUpdate {
    /// Runs FirmwareUpdate.run / fileList (the app's bridge) against a strict E1.37-4 Responder emulator,
    /// in process, on a virtual millisecond clock. The emulator judges the controller too (delays, offsets, CRCs,
    /// commit silence).
    static func selfTestFTC() -> Bool {
        let target: [UInt8] = [0x7F, 0xF0, 0, 0, 0, 2]
        let file = (0..<3000).map { i in UInt8(truncatingIfNeeded: i * 37 + (i >> 7)) }
        var allOK = true

        /// The bridge wired to a fresh emulator. `onSend` sees each request before the emulator does.
        func bench(_ setup: (inout ftc_emulator) -> Void, onSend: ((FirmwareUpdate, UInt8, UInt16) -> Void)? = nil)
            -> (FirmwareUpdate, UnsafeMutablePointer<ftc_emulator>) {
            let e = UnsafeMutablePointer<ftc_emulator>.allocate(capacity: 1)
            target.withUnsafeBufferPointer { emulator_init(e, $0.baseAddress) }
            setup(&e.pointee)
            var now: UInt32 = 0
            weak var me: FirmwareUpdate?
            let fw = FirmwareUpdate(transport: { cc, pid, pd in
                if let me { onSend?(me, cc, pid) }
                now += 1 // each transaction costs 1 ms, like the emulator's own host tests
                var r = [UInt8](repeating: 0, count: 231), rn: UInt8 = 0, rcc: UInt8 = 0, rpid: UInt16 = 0
                let t = target.withUnsafeBufferPointer { dest in
                    pd.withUnsafeBufferPointer { emulator_request(e, now, dest.baseAddress, 0, cc, pid, $0.baseAddress, UInt8(pd.count), &r, &rn, &rcc, &rpid) }
                }
                return t < 0 ? nil : Reply(type: t, cc: rcc, pid: rpid, pd: Array(r.prefix(Int(rn))))
            }, sleep: { now += $0 })
            me = fw
            return (fw, e)
        }

        /// One upload; `hook` sees each progress report (and may cancel).
        func upload(_ name: String, _ data: [UInt8], testMode: Bool = false, fileID: UInt8 = 0, session: UInt8 = 0x5A,
                    setup: (inout ftc_emulator) -> Void = { _ in }, onSend: ((FirmwareUpdate, UInt8, UInt16) -> Void)? = nil,
                    hook: ((FirmwareUpdate, FirmwareUpdate.Phase, UInt32) -> Void)? = nil,
                    check: (Outcome, ftc_emulator, [FirmwareUpdate.Phase], [[UInt8]]) -> Bool) {
            let (fw, e) = bench(setup, onSend: onSend)
            defer { e.deallocate() }
            var phases: [FirmwareUpdate.Phase] = [], initiates: [[UInt8]] = []
            fw.progress = { p, n in
                if phases.last != p { phases.append(p) }
                hook?(fw, p, n)
            }
            fw.sentLog = { cc, pid, pd in if Int32(pid) == FTC_INITIATE && Int32(cc) == RDM_SET_COMMAND { initiates.append(pd) } }
            let o = fw.run(file: data, testMode: testMode, fileID: fileID, session: session)
            let ok = check(o, e.pointee, phases, initiates)
            if !ok {
                let why = e.pointee.last_violation.map { String(cString: $0) } ?? ""
                print("    ftc \(name): code \(o.code) cancelled \(o.cancelled) violations \(e.pointee.violations) \(why) cancels \(e.pointee.cancels) "
                      + "commits \(e.pointee.commits) phases \(phases.map(\.rawValue)) last log: \(fw.lastLog)")
            }
            allOK = allOK && ok
        }

        // Appendix D golden vector: a 16-byte file, SessionID 0x7D, FileID 1 → the standard's 30 printed bytes.
        let f16: [UInt8] = [0xEC, 0xEF, 0x7B, 0xF0, 0, 0, 0, 3, 4, 0x6E, 0xD8, 0xCF, 5, 0xF0, 0xE0, 0xCF]
        let want: [UInt8] = [0x7D, 1, 1, 0, 0, 0, 0, 0, 0, 0x10] + f16 + [0xB3, 0xDD, 0xCA, 0xB0]
        allOK = allOK && f16.withUnsafeBufferPointer { ftc_crc($0.baseAddress, 16) } == 0xB3DD
        upload("Appendix D", f16, fileID: 1, session: 0x7D) { o, _, _, ini in o.ok && ini == [want] }

        // Normal upload: every phase in order, the Responder's CRC matches, committed once, no violations.
        upload("normal", file, setup: {
            $0.block_size = 50; $0.initial_delay_ms = 100; $0.inter_packet_delay_ms = 5; $0.accumulated_byte_count = 512
            $0.accumulated_byte_delay_ms = 30; $0.validation_delay_ms = 200; $0.commit_time_ms = 1500
        }) { o, e, ph, _ in
            o.ok && e.violations == 0 && e.commits == 1 && o.result.responder_crc == o.result.file_crc
                && ph == [.initiate, .waiting, .transferring, .validating, .committing, .rebooting]
        }
        // Test mode: TransferFlags and CommitFlags carry TESTMODE.
        upload("test mode", file, testMode: true) { o, e, _, _ in o.ok && e.violations == 0 && Int32(e.flags) & FTC_TF_TESTMODE != 0 && e.commits == 1 }
        // One damaged packet: resent, then finishes.
        upload("CRC error then recover", file, setup: { $0.crc_error_packet = 3 }) { o, e, _, _ in o.ok && e.violations == 0 && o.result.resends == 1 }
        // Proxy (ACK_TIMER then GET QUEUED_MESSAGE) passes through the bridge untouched.
        upload("proxy ACK_TIMER", file, setup: { $0.proxy_every = 1; $0.proxy_delay_ms = 250 }) { o, e, _, _ in o.ok && e.violations == 0 && e.ack_timers > 10 }
        // Cancel mid-transfer: ftc.h sends SET:FTC_CANCEL, nothing is committed, the Responder is idle again.
        upload("cancel", file, setup: { $0.block_size = 100 }, hook: { fw, p, n in if p == .transferring && n >= 1000 { fw.cancel() } }) { o, e, _, _ in
            o.cancelled && !o.ok && e.cancels == 1 && e.commits == 0 && e.phase == UInt8(PHASE_IDLE) && e.violations == 0
        }
        // Cancel arriving with GET:FTC_COMMIT (validation passed): ftc.h won't cancel on the way into SET:FTC_COMMIT,
        // so the bridge sends ftc_cancel itself. Never committed.
        upload("cancel before commit", file, setup: { $0.validation_delay_ms = 500 },
               onSend: { fw, cc, pid in if Int32(pid) == FTC_COMMIT && Int32(cc) == RDM_GET_COMMAND { fw.cancel() } }) { o, e, _, _ in
            o.cancelled && e.cancels == 1 && e.commits == 0 && e.violations == 0
        }

        // Several FileIDs (like a multi-file fixture): FTC_FILELIST over two replies (ACK_OVERFLOW past five), each size from
        // GET:FTC_INITIATE, then an upload to the chosen FileID through the bootloader switch. FileID 0 is refused.
        let up = UInt32(FTC_ACCEPT_UPLOAD | FTC_PROCESS_FILECRC | FTC_PROCESS_PACKETCRC)
        let down = UInt32(FTC_ACCEPT_DOWNLOAD | FTC_GENERATE_FILECRC | FTC_GENERATE_PACKETCRC)
        let settings = (0..<532).map { UInt8(truncatingIfNeeded: $0 * 7 + 3) }, log = (0..<4000).map { UInt8(truncatingIfNeeded: $0 ^ ($0 >> 3)) }
        let settingsData = UnsafeMutablePointer<UInt8>.allocate(capacity: settings.count), logData = UnsafeMutablePointer<UInt8>.allocate(capacity: log.count)
        settingsData.initialize(from: settings, count: settings.count); logData.initialize(from: log, count: log.count)
        defer { settingsData.deallocate(); logData.deallocate() }
        let table: [(id: UInt8, caps: UInt32, text: String, suffix: String, size: UInt32, boot: UInt32, data: UnsafeMutablePointer<UInt8>?)] = [
            (1, up | UInt32(FTC_BOOTLOADER_SWITCH | FTC_TESTMODE_SUPPORTED | FTC_FAIL_MAY_BRICK), "Application firmware", "bin", 120_000, 300, nil),
            (2, up | down | UInt32(FTC_TESTMODE_SUPPORTED), "Settings", "set", 532, 0, settingsData),
            (3, up, "Show file", "show", 4096, 0, nil), (4, up, "Four", "4", 10, 0, nil),
            (5, down, "Service log", "log", 4000, 0, logData), (6, up, "Six", "6", 30, 0, nil),
        ]
        let files = UnsafeMutablePointer<emulator_file>.allocate(capacity: table.count)
        defer { files.deallocate() }
        for (i, t) in table.enumerated() {
            files[i] = emulator_file(file_id: t.id, capabilities: t.caps, description: UnsafePointer(strdup(t.text)), suffix: UnsafePointer(strdup(t.suffix)),
                                     data: UnsafePointer(t.data), size: t.size, store: nil, key: nil, bootloader_ms: t.boot, max_upload: 0, upload_block: 128,
                                     check_start: nil, check_file: nil)
        }
        let withFiles: (inout ftc_emulator) -> Void = { $0.files = UnsafePointer(files); $0.file_count = UInt8(table.count) }
        do {
            let (fw, e) = bench(withFiles)
            defer { e.deallocate() }
            let list = fw.fileList() ?? []
            let ok = list.map(\.id) == table.map(\.id) && list.map(\.size) == table.map(\.size)
                && list.first?.description == "Application firmware" && list.first?.suffix == "bin"
                && list.first?.testModeOK == true && list.dropFirst(2).first?.testModeOK == false && e.pointee.violations == 0
            if !ok { print("    ftc file list: \(list) violations \(e.pointee.violations) last log: \(fw.lastLog)") }
            allOK = allOK && ok
        }
        upload("several files, FileID 0", file, setup: withFiles) { o, e, _, ini in o.code == FTC_RESULT_MULTIPLE_FILES && ini.isEmpty && e.violations == 0 }
        upload("several files, FileID 1 in test mode", file, testMode: true, fileID: 1, setup: withFiles) { o, e, ph, ini in
            o.ok && e.violations == 0 && e.commits == 1 && o.result.bootloader_switches == 1
                && !ini.isEmpty && ini.allSatisfy { $0[1] == 1 } && ph.contains(.waiting)
        }

        // Downloads through the same bridge: bytes and FileCRC checked, a damaged packet re-requested, strict mode
        // (used for a first real download) doesn't abort a normal flow, and a cancel ends the session.
        func download(_ name: String, _ id: UInt8, strict: Bool = false, setup: (inout ftc_emulator) -> Void = { _ in },
                      hook: ((FirmwareUpdate, FirmwareUpdate.Phase, UInt32) -> Void)? = nil,
                      check: (Outcome, [UInt8], ftc_emulator, FirmwareUpdate) -> Bool) {
            let (fw, e) = bench { withFiles(&$0); setup(&$0) }
            defer { e.deallocate() }
            fw.strict = strict
            fw.progress = { p, n in hook?(fw, p, n) }
            let (o, data) = fw.download(fileID: id)
            let ok = check(o, data, e.pointee, fw)
            if !ok {
                print("    ftc \(name): code \(o.code) cancelled \(o.cancelled) bytes \(data.count) violations \(e.pointee.violations) "
                      + "\(e.pointee.last_violation.map { String(cString: $0) } ?? "") cancels \(e.pointee.cancels) strict \(fw.strictAbort ?? "-") last log: \(fw.lastLog)")
            }
            allOK = allOK && ok
        }
        download("download settings", 2) { o, d, e, _ in o.ok && d == settings && o.result.responder_crc == o.result.file_crc && e.violations == 0 && e.phase == UInt8(PHASE_IDLE) }
        download("download, bad PacketCRC once", 5, setup: { $0.download_crc_error_packet = 2; $0.download_crc_error_count = 1 }) { o, d, e, _ in o.ok && d == log && o.result.resends == 1 && e.violations == 0 }
        download("download, strict, normal flow", 5, strict: true) { o, d, e, fw in o.ok && d == log && fw.strictAbort == nil && e.violations == 0 }
        download("download, upload-only file", 3) { o, d, e, _ in o.code == FTC_RESULT_NO_DOWNLOAD && d.isEmpty && e.violations == 0 }
        download("download cancel", 5, hook: { fw, p, n in if p == .transferring && n >= 1000 { fw.cancel() } }) { o, d, e, _ in
            o.cancelled && d.isEmpty && e.cancels == 1 && e.phase == UInt8(PHASE_IDLE) && e.violations == 0
        }
        return allOK
    }
}
