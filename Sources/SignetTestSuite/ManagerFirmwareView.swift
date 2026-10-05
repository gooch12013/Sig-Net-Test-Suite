import AppKit
import SwiftUI

/// Firmware and files of one RDM fixture (ANSI E1.37-4), shown when the fixture lists FTC_INITIATE.
/// Capabilities come from GET:FTC_INITIATE with SessionID 0, the files from GET:FTC_FILELIST (plus GET:FTC_INITIATE
/// per file for its size); both only read and open no session. A selected file can be downloaded (reads only) or
/// replaced by an upload (test mode on by default, behind a confirmation).
struct ManagerFirmwarePanel: View {
    @ObservedObject var manager: Manager
    let device: ManagerDevice
    let port: UInt16
    let uid: String
    let name: String

    enum Kind { case upload, download }

    @State private var decl: FTC.Declarations?
    @State private var capsNote: String?
    @State private var files: [FirmwareUpdate.FixtureFile]?
    @State private var filesNote: String?
    @State private var target: FirmwareUpdate.FixtureFile?
    @State private var fileURL: URL?
    @State private var file: [UInt8] = []
    @State private var testMode = 1
    @State private var confirming = false
    @State private var job: FirmwareUpdate?
    @State private var kind = Kind.upload
    @State private var total = 0
    @State private var phase = FirmwareUpdate.Phase.initiate
    @State private var sent: UInt32 = 0
    @State private var outcome: (ok: Bool, text: String)?

    /// Last capabilities and file list per fixture UID, so they survive tab switches. Main queue only.
    private static var known: [String: FTC.Declarations] = [:]
    private static var knownFiles: [String: [FirmwareUpdate.FixtureFile]] = [:]

    private var running: Bool { job != nil }
    private var idle: Bool { manager.running && !manager.busy && !FirmwareUpdate.active && !running }
    /// Test mode for the selected fixture file (its own capabilities), else what the fixture declares overall.
    private var testModeOK: Bool { target?.testModeOK ?? decl.map { $0.capabilities & FTC.Cap.testModeSupported != 0 } ?? false }
    private var testOn: Bool { testMode == 1 && testModeOK }
    private var canStart: Bool {
        idle && fileURL != nil && decl?.status == 0 && target?.acceptsUpload == true
    }
    private var canDownload: Bool { idle && decl?.status == 0 && target.map { $0.acceptsDownload && !$0.needsKey } == true }

    var body: some View {
        ModulePanel("Firmware & files") {
            if running { Lamp(color: .lampPending, pulsing: true) }
        } content: {
            capabilityRows
            fileList
            fileRow
            HStack(spacing: 8) {
                label("Test mode")
                ModeKeys(options: [(0, "Off"), (1, "On")], selection: Binding(get: { testModeOK ? testMode : 0 }, set: { testMode = $0 }))
                    .disabled(!testModeOK || running)
                Text(testOn ? "Checks the file, keeps its firmware." : "Installs the file and restarts.")
                    .font(.system(size: 11.5)).foregroundStyle(Color.silk)
            }
            if running || outcome != nil { progressRow }
            HStack(spacing: 8) {
                Spacer().frame(width: ReadoutRow.labelWidth)
                if running {
                    Button("Cancel") { job?.cancel() }.buttonStyle(.softKey)
                        .disabled(phase == .committing || phase == .rebooting)
                        .help("Stop the transfer and tell the fixture to end it")
                } else {
                    Button("Start upload") { confirming = true }.buttonStyle(SoftKeyStyle(prominent: true)).disabled(!canStart)
                        .help(FirmwareUpdate.active ? "Another transfer is running" : "Replace the selected file on the fixture")
                    Button("Download…", action: chooseSave).buttonStyle(.softKey).disabled(!canDownload)
                        .help("Copy the selected file from the fixture to this Mac")
                    if let hint { Text(hint).font(.system(size: 11.5)).foregroundStyle(Color.silk) }
                }
            }
        }
        .confirmationDialog("Update \(name)?", isPresented: $confirming) {
            Button(testOn ? "Upload in test mode" : "Upload and install", role: .destructive, action: startUpload)
            Button("Cancel", role: .cancel) {}.keyboardShortcut(.defaultAction)
        } message: {
            Text("\(fileURL?.lastPathComponent ?? "") (\(size(file.count))) goes to \(name), \(ManagerRDM.uid(mgrBytes(hex: uid) ?? [0, 0, 0, 0, 0, 0])), "
                 + "replacing its \(target.map(title) ?? "file") (file \(target?.id ?? 0)). "
                 + (testOn ? "Test mode is on: the fixture checks the file without installing it."
                           : "Test mode is off: the fixture installs this file. A bad file or an interrupted update can leave it unusable."))
        }
        .onAppear {
            if let d = Self.known[uid] { show(d); files = Self.knownFiles[uid]; pickSingle() } else { readCaps() }
        }
    }

    private var hint: String? {
        guard let target else { return files?.isEmpty == false ? "Select a file on the fixture." : nil }
        if target.needsKey { return "This file needs a download key, which this app can't send yet." }
        if !target.acceptsUpload && fileURL != nil { return "This file can only be downloaded." }
        return nil
    }

    private func label(_ text: String) -> some View {
        Text(text).font(.system(size: 12.5, weight: .medium)).foregroundStyle(Color.inkDim)
            .frame(width: ReadoutRow.labelWidth, alignment: .leading)
    }

    // MARK: - Capabilities

    @ViewBuilder private var capabilityRows: some View {
        let d = decl
        let get: (@escaping (Signal) -> Void) -> Void = { readCaps(done: $0) }
        let on = idle
        ReadoutRow(label: "Transfer version", value: capsNote ?? d.map { "\($0.version >> 8).\(String(format: "%02d", $0.version & 0xFF))" }, get: get, enabled: on)
        ReadoutRow(label: "Accepts upload", value: d.map { $0.capabilities & FTC.Cap.acceptUpload != 0 ? "Yes" : "No" }, get: get, enabled: on)
        ReadoutRow(label: "Test mode", value: d.map { $0.capabilities & FTC.Cap.testModeSupported != 0 ? "Supported" : "Not supported" }, get: get, enabled: on)
        ReadoutRow(label: "Largest file", value: d.map { $0.fileSize == 0 ? "No limit given" : size(Int($0.fileSize)) }, get: get, enabled: on)
        ReadoutRow(label: "Block size", value: d.map { "\($0.blockSize) bytes" }, get: get, enabled: on)
        ReadoutRow(label: "Start delay", value: d.map { "\($0.initialDelay) ms" }, get: get, enabled: on)
        ReadoutRow(label: "Packet delay", value: d.map { $0.accumulatedByteCount == 0 ? "\($0.interPacketDelay) ms"
            : "\($0.interPacketDelay) ms, +\($0.accumulatedByteDelay) ms per \($0.accumulatedByteCount) bytes" }, get: get, enabled: on)
        ReadoutRow(label: "Check delay", value: d.map { "\($0.validationDelay) ms" }, get: get, enabled: on)
        ReadoutRow(label: "If interrupted", value: d.map { $0.capabilities & FTC.Cap.failMayBrick != 0 ? "May stop working" : "No risk declared" }, get: get, enabled: on)
    }

    /// GET:FTC_INITIATE, SessionID 0, FileID 0: declarations only. Retries while another panel holds the Manager.
    private func readCaps(attempt: Int = 0, done: @escaping (Signal) -> Void = { _ in }) {
        guard manager.running, let dest = mgrBytes(hex: uid) else { return done(.silent("The Manager isn't running")) }
        let pd: [UInt8] = [FTC.DEF.noSessionIDOffered, FTC.DEF.noFileIDOffered] + mgrBE16(FTC.version) + [0, 0]
        manager.rdm(device.tuid, ep: port, dest: dest, set: false, pid: FTC.PID.initiate, pd: pd) { r in
            if r.text.hasPrefix("Busy"), attempt < 600 { // up to 5 min: Read all (or a transfer) can hold the Manager that long
                return DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { readCaps(attempt: attempt + 1, done: done) }
            }
            let f = r.frame
            guard r.ok, ManagerRDM.valid(f), f[16] == 0 else { return done(.silent("No answer from the fixture")) }
            let rpd = Array(f[24..<24 + Int(f[23])])
            guard let d = FTC.Declarations(rpd) else {
                return done(.refused("The fixture's answer didn't make sense"))
            }
            Self.known[uid] = d
            show(d)
            done(.latched)
            if d.status == 0, files == nil { readFiles() }
        }
    }

    private func show(_ d: FTC.Declarations) {
        decl = d
        capsNote = d.status == 0 ? nil : FirmwareUpdate.statusText(d.status)
    }

    // MARK: - Files on the fixture

    /// FTC_FILELIST through the same bridge a transfer uses (requests marked upload), off the main queue.
    private func readFiles() {
        guard manager.running, !FirmwareUpdate.active, let dest = mgrBytes(hex: uid) else { return }
        filesNote = "Reading the file list…"
        let reader = FirmwareUpdate(transport: FirmwareUpdate.managerTransport(manager, node: device.tuid, ep: port, dest: dest, busySeconds: 300),
                                    sleep: FirmwareUpdate.realSleep)
        let fixture = uid
        DispatchQueue.global(qos: .userInitiated).async {
            let list = reader.fileList()
            DispatchQueue.main.async {
                if let list { Self.knownFiles[fixture] = list }
                guard fixture == uid else { return }
                files = list ?? files
                filesNote = list == nil ? "The fixture didn't list its files." : nil
                if let t = target, list?.contains(t) != true { target = nil }
                pickSingle()
            }
        }
    }

    /// A fixture with one file needs no choice.
    private func pickSingle() {
        if target == nil, let files, files.count == 1 { select(files[0]) }
    }

    private func select(_ f: FirmwareUpdate.FixtureFile) {
        target = f
        testMode = f.testModeOK ? 1 : 0 // test mode on by default wherever the file allows it
    }

    private func title(_ f: FirmwareUpdate.FixtureFile) -> String { f.description.isEmpty ? "File \(f.id)" : f.description }

    /// "file 1 · .bin · 88 KB · upload, download, test mode · may stop working if interrupted"
    private func details(_ f: FirmwareUpdate.FixtureFile) -> String {
        var ways: [String] = []
        if f.acceptsUpload { ways.append("upload") }
        if f.acceptsDownload { ways.append(f.needsKey ? "download with a key" : "download") }
        if f.testModeOK { ways.append("test mode") }
        var parts = ["file \(f.id)"]
        if !f.suffix.isEmpty { parts.append(".\(f.suffix)") }
        parts.append(f.size == 0 ? "size not given" : size(Int(f.size)))
        parts.append(ways.isEmpty ? "no transfers" : ways.joined(separator: ", "))
        if f.capabilities & FTC.Cap.bootloaderSwitch != 0 { parts.append("restarts to load") }
        if f.capabilities & FTC.Cap.failMayBrick != 0 { parts.append("may stop working if interrupted") }
        return parts.joined(separator: " · ")
    }

    private var fileList: some View {
        HStack(alignment: .top, spacing: 8) {
            VStack(alignment: .leading, spacing: 0) {
                label("Files on fixture")
                Text(files.map { "\($0.count) offered" } ?? "").font(.system(size: 11, design: .monospaced)).foregroundStyle(Color.silk)
            }
            VStack(alignment: .leading, spacing: 4) {
                if let files, !files.isEmpty {
                    ForEach(files, id: \.self) { f in
                        Button { select(f) } label: { fileListRow(f) }.buttonStyle(.plain).disabled(running)
                            .accessibilityAddTraits(f == target ? .isSelected : [])
                    }
                } else {
                    ReadoutWindow { Text(filesNote ?? (files == nil ? "—" : "None")).font(.system(size: 12)).foregroundStyle(Color.silk) }
                }
            }
            .frame(maxWidth: 560)
            Button("Read list") { readFiles() }.buttonStyle(.softKey).disabled(!idle || decl?.status != 0)
                .help("Ask the fixture which files it offers")
        }
        .frame(maxWidth: 860, alignment: .leading)
    }

    private func fileListRow(_ f: FirmwareUpdate.FixtureFile) -> some View {
        HStack(alignment: .top, spacing: 9) {
            Lamp(color: f == target ? .lampLatch : nil).padding(.top, 4)
            VStack(alignment: .leading, spacing: 2) {
                Text(title(f)).font(.system(size: 13, weight: .semibold)).foregroundStyle(Color.ink)
                Text(details(f)).font(.system(size: 10.5, design: .monospaced)).foregroundStyle(Color.silk)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 10).padding(.vertical, 6)
        .background(RoundedRectangle(cornerRadius: 4, style: .continuous).fill(Color.readoutWindow)
            .overlay(RoundedRectangle(cornerRadius: 4, style: .continuous)
                .strokeBorder(f == target ? Color.lampLatch.opacity(0.7) : Color.black.opacity(0.7), lineWidth: 1)))
        .contentShape(Rectangle())
    }

    // MARK: - Upload and download

    private var fileRow: some View {
        HStack(spacing: 8) {
            label("File to upload")
            ReadoutWindow {
                Text(fileURL.map { "\($0.lastPathComponent) · \(size(file.count))" } ?? "—")
                    .font(.system(size: 13, weight: fileURL == nil ? .regular : .medium, design: .monospaced))
                    .foregroundStyle(fileURL == nil ? Color.silk : Color.ink).lineLimit(1).truncationMode(.middle)
            }
            Button("Choose file…", action: chooseOpen).buttonStyle(.softKey).disabled(running)
        }
        .frame(maxWidth: 860, alignment: .leading)
    }

    private var progressRow: some View {
        let shown = max(total, Int(sent), 1)
        let fraction = min(Double(sent) / Double(shown), 1)
        let verb = kind == .upload ? "Upload" : "Download"
        return VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                HStack(spacing: 7) {
                    Lamp(color: running ? .lampPending : outcome?.ok == true ? .lampLatch : .lampFault, pulsing: running)
                    Text(running ? "\(verb): \(phase.rawValue)" : outcome?.ok == true ? "Complete" : "Stopped")
                        .font(.system(size: 12.5, weight: .medium)).foregroundStyle(Color.inkDim)
                }
                .frame(width: ReadoutRow.labelWidth, alignment: .leading)
                ReadoutWindow(signal: running ? .pending : outcome?.ok == true ? .latched : .refused("")) {
                    GeometryReader { g in
                        RoundedRectangle(cornerRadius: 2, style: .continuous).fill(Color.lampLatch.opacity(0.75))
                            .frame(width: g.size.width * fraction, height: 10).frame(maxHeight: .infinity)
                    }
                    .frame(height: 28)
                }
                Text("\(sent) / \(total == 0 ? "?" : "\(total)") bytes").font(.system(size: 11.5, design: .monospaced)).foregroundStyle(Color.silk).fixedSize()
            }
            .frame(maxWidth: 860, alignment: .leading)
            if let outcome, !running {
                Text(outcome.text).font(.system(size: 11.5)).foregroundStyle(outcome.ok ? Color.lampLatch : Color.lampFault)
                    .padding(.leading, ReadoutRow.labelWidth + 8)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(verb) \(running ? phase.rawValue : outcome?.text ?? ""), \(sent) of \(total) bytes")
    }

    private func chooseOpen() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url, let data = try? Data(contentsOf: url) else { return }
        fileURL = url
        file = [UInt8](data)
        outcome = nil
        sent = 0
    }

    private func chooseSave() {
        guard let t = target else { return }
        let panel = NSSavePanel()
        let base = title(t).replacingOccurrences(of: "/", with: "-").replacingOccurrences(of: ":", with: "-")
        panel.nameFieldStringValue = t.suffix.isEmpty ? base : "\(base).\(t.suffix)"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        startDownload(t, to: url)
    }

    /// The bridge on a worker; progress and the end state come back on the main queue. Holds the app-wide transfer lock.
    private func begin(_ k: Kind, total t: Int, work: @escaping (FirmwareUpdate) -> (ok: Bool, text: String)) {
        // Hard guard, checked again at the moment of starting.
        guard idle, let dest = mgrBytes(hex: uid) else { return }
        let fw = FirmwareUpdate(transport: FirmwareUpdate.managerTransport(manager, node: device.tuid, ep: port, dest: dest),
                                sleep: FirmwareUpdate.realSleep)
        fw.progress = { p, n in DispatchQueue.main.async { phase = p; sent = n } }
        FirmwareUpdate.active = true
        job = fw
        kind = k
        total = t
        outcome = nil
        sent = 0
        phase = .initiate
        DispatchQueue.global(qos: .userInitiated).async {
            let result = work(fw)
            DispatchQueue.main.async {
                FirmwareUpdate.active = false
                job = nil
                outcome = result
            }
        }
    }

    private func startUpload() {
        guard canStart, let t = target else { return }
        let data = file, test = testOn
        begin(.upload, total: data.count) { fw in
            let o = fw.run(file: data, testMode: test, fileID: t.id)
            return (o.ok, o.ok ? (test ? "Complete. The fixture accepted the file in test mode and kept its firmware."
                                       : "Complete. The fixture installed the file and restarted.")
                               : FirmwareUpdate.reason(o))
        }
    }

    private func startDownload(_ t: FirmwareUpdate.FixtureFile, to url: URL) {
        guard canDownload else { return }
        begin(.download, total: Int(t.size)) { fw in
            let (o, data) = fw.download(fileID: t.id)
            guard o.ok else { return (false, FirmwareUpdate.reason(o)) }
            do { try Data(data).write(to: url, options: .atomic) } catch {
                return (false, "Downloaded, but couldn't save to \(url.lastPathComponent): \(error.localizedDescription)")
            }
            let checked = o.result.declared.capabilities & FTC.Cap.generateFileCRC != 0 && o.result.responderCRC == o.result.fileCRC
            let check = checked ? "The checksum matches the fixture's." : "The fixture gives no checksum for this file, so it couldn't be checked."
            return (true, "Saved \(data.count) bytes as \(url.lastPathComponent). \(check)")
        }
    }

    private func size(_ n: Int) -> String { ByteCountFormatter.string(fromByteCount: Int64(n), countStyle: .file) }
}
