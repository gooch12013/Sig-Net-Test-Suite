import Foundation
import SigNet

// `sig-net --selftest [--offline] [--interface <ip>]`: see SelfTest.swift. Exit status 0 = all passed.
// `sig-net --probe …`: Manager probe of a real Node (see ManagerProbe.swift).
if CommandLine.arguments.contains("--selftest") { exit(SelfTest.run(CommandLine.arguments)) }
if CommandLine.arguments.contains("--probe") { exit(ManagerEngine.probe(CommandLine.arguments)) }
// `sig-net --mcp …`: Model Context Protocol server on stdin/stdout for AI clients (see MCPServer.swift).
if CommandLine.arguments.contains("--mcp") { MCPServer.run(CommandLine.arguments) }
print("usage: sig-net --selftest [--offline] [--interface <local IPv4>] | --probe --node <TUID> --ip <addr> [...]")
print("       sig-net --mcp [--passphrase <p>] [--scope <s>] [--interface <local IPv4>] [--allow-set] [--allow-dangerous]")
exit(2)
