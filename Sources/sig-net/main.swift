import Foundation
import SigNet

// `sig-net --selftest [--offline] [--interface <ip>]`: see SelfTest.swift. Exit status 0 = all passed.
// `sig-net --probe …`: Manager probe of a real Node (see ManagerProbe.swift).
if CommandLine.arguments.contains("--selftest") { exit(SelfTest.run(CommandLine.arguments)) }
if CommandLine.arguments.contains("--probe") { exit(ManagerEngine.probe(CommandLine.arguments)) }
print("usage: sig-net --selftest [--offline] [--interface <local IPv4>] | --probe --node <TUID> --ip <addr> [...]")
exit(2)
