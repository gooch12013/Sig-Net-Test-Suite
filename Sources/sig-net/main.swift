import Foundation
import SigNet

/// `sig-net --selftest`: the portable checks, both security modes. Exit status 0 = all passed.
/// `sig-net --probe …`: Manager probe of a real Node (see ManagerProbe.swift).
func selfTest() -> Int32 {
    var failed = false
    func report(_ label: String, _ why: String?) {
        print("\(why == nil ? "PASS" : "FAIL") \(label)\(why.map { ": \($0)" } ?? "")")
        failed = failed || why != nil
    }
    report("timecode counter", Timecode.selfTest() ? nil : "wrong frame label")
    report("rdm firmware upload (emulator)", FirmwareUpdate.selfTestFTC() ? nil : "see above")
    report("manager spec vectors", ManagerEngine.knownAnswers())
    report("sender spec vectors", TransmitterEngine.knownAnswers())
    let interface = CommandLine.arguments.firstIndex(of: "--interface").flatMap { CommandLine.arguments.dropFirst($0 + 1).first } ?? ""
    for mode in SecurityMode.allCases {
        let s = SecurityConfig()
        s.mode = mode
        s.passphrase = "Sig-Net-Test-9"
        s.interface = interface
        report("manager loop \(mode.rawValue.lowercased())", ManagerEngine.loopTest(settings: s))
        report("sender loop \(mode.rawValue.lowercased())", TransmitterEngine.loopTest(settings: s))
    }
    return failed ? 1 : 0
}

if CommandLine.arguments.contains("--selftest") { exit(selfTest()) }
if CommandLine.arguments.contains("--probe") { exit(ManagerEngine.probe(CommandLine.arguments)) }
print("usage: sig-net --selftest [--interface <local IPv4>] | --probe --node <TUID> --ip <addr> [...]")
exit(2)
