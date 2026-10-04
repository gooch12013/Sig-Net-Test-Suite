# Sig-Net test suite for macOS

![Sig-Net](Sources/SignetTestSuite/Resources/SigNetLogo.png)

A SwiftUI app for testing Sig-Net® equipment from a Mac. It can transmit,
receive, act as a discoverable fixture, and act as a Manager, in Open or Secure
Mode, so it can test consoles, fixtures and other Managers.

| Tab | Role | What it does |
| --- | --- | --- |
| Transmit | Sender | Up to 16 universes with faders, universe priority, sync, timecode generator (all 11 rates), preview, test patterns (chase, ramp, random) |
| Receive | Node (data plane) | Live 512-slot view per universe, merge source count, frame age and rate, timecode streams, preview frames, diagnostics counters, drops by reason, the last 32 rejected packets, library log |
| Device | Complete Node | A fake fixture that Managers can discover and configure: parameter store with transactions, two proprietary TIDs, a virtual RDM responder per endpoint, offboard and network-change handlers that only log |
| Manager | Manager | Discovery (broadcast, range, targeted polls), device list, GET/SET editor for every TID, RDM commands and Table of Devices, packet log with authentication results |

Transmit, Receive and Device use the Sig-Net C library. The library has no
Manager role, so the Manager is written in Swift from the spec, using CryptoKit
for HMAC-SHA256 and HKDF. Its packets were checked byte for byte against the
spec's test vectors and against the library's own decoder.

SNOW (over-the-wire onboarding) is not implemented. See `docs/snow-summary.md`.

## Build and run

You need macOS 13 or later, Swift 5.10 or later, CMake 3.29 or later, and a copy
of the Sig-Net desktop library source (`signet-desktop-src-0.1.0`).

Build the library into `vendor/signet` once:

```sh
scripts/build-signet.sh /path/to/signet-desktop-src-0.1.0
```

Then run the app:

```sh
swift run SignetTestSuite
```

To use a library installed somewhere else, set `SIGNET_PREFIX` to its install
prefix. The linker warns that the dylib targets a newer macOS than the package.
The warning is harmless.

## Security settings

The panel above the tabs sets the mode, passphrase and scope for every device
the app creates. These are fixed when a device is created, so the panel locks
while anything is running.

In Secure Mode the passphrase must pass the Sig-Net rules (10 to 64 characters,
3 of 4 character classes, no runs of 3 identical or 4 sequential characters).
The panel names the failing rule as you type. Peers must use the same
passphrase and scope.

Each part keeps its own device ID (TUID), generated once in ESTA's prototyping
range (`0x7FF0`) and saved in user defaults. Secure Mode session records are
saved in `~/Library/Application Support/SignetTestSuite/state/`. Don't delete
that folder casually: the library can refuse to start Secure Mode for a device
whose record is missing. The Manager keeps its session counter in user
defaults.

## Testing your equipment

- **A console or sender:** run Receive on its universes. Check levels, source
  count, priority merging, timecode and preview. The diagnostics panel shows
  why packets are dropped (wrong mode, bad signature, replay and so on).
- **A fixture or node:** run Transmit at it for levels, priority, sync,
  timecode and patterns. Run Manager to discover it, read and change its
  parameters, and send it RDM.
- **A Manager:** run Device. The log shows every parameter and RDM request it
  receives.

All parts can run at once. They share UDP port 5683 and see each other's
traffic through multicast loopback, which is how the self-test works.

## Network

Sig-Net uses UDP port 5683. Levels for universe *n* go to
`239.254.0.((n-1) % 109 + 1)`. Control traffic uses `239.254.255.248` to `.255`.
Allow this traffic through the macOS firewall. The Manager tab has an interface
field for Macs with more than one network.

## Self-test

```sh
swift run SignetTestSuite --selftest
```

Runs every part against the others inside one process, in Open and Secure Mode,
and exits non-zero on any failure. It takes about 20 seconds. It checks:

- Timecode frame counting, including drop-frame rates.
- The Transmitter starting and restarting (Secure restart reloads the session record).
- Levels from the Transmitter arriving at the Receiver.
- The fake Device booting twice, plus its RDM responder on hand-built frames.
- The Manager: spec test vectors, then discovering the fake Device, GET/SET of its label, refusal detection, Table of Devices and RDM DEVICE_INFO, and (Secure) rejection of a wrong passphrase.
- Multiple universes, priority merging, sync, timecode, preview, and (Secure) rejection of an Open-Mode sender and of a wrong passphrase.

## Findings so far

Differences between the library and the spec. Details are in
`docs/manager-semantics.md`.

Seen on the wire, while the Swift Manager tested the fake Device:

- Proprietary TIDs are answered when the request's Mfg-Code is 0. The spec says they should only be read when the Mfg-Code matches.
- `source_count` counts only senders that win at least one slot, not every sender received.

Found by reading the library source, not yet tested:

- RDM responses can be delayed up to 1000 ms; the spec says 250 ms.
- RDM discovery commands are not filtered out of the tunnel.
- There is no 2 second post-boot lockout on SET (spec section 8.6.4).

## Not implemented yet

- SNOW onboarding.
- Manager: suspending its own polling when another Manager is polling, answering other Managers' polls, network-change rollback, offboard and reboot buttons (they can be sent as raw SETs), multi-TID transactions, and RDM flow control.
- Saving the fake Device's parameter values across restarts.
- Fake Device RDM flow control: it never calls `signet_context_set_rdm_flow`, so it reports 0 of 0 slots available and its RDM responses carry no flow-control TLV.
- Fake Device network parameters: it installs a network handler, so `RT_SUPPORTED_TIDS` lists the network TIDs, but its parameter store never answers GETs for them.

## Files

| Path | Purpose |
| --- | --- |
| `Package.swift` | Swift package; points the compiler and linker at `vendor/signet` |
| `scripts/build-signet.sh` | Builds the library into `vendor/signet` |
| `Sources/CSignet/` | Module map that exposes `signet.h` to Swift |
| `Sources/SignetTestSuite/Signet.swift` | Shared security settings, key derivation, device IDs, file persistence |
| `Transmitter.swift`, `TransmitView.swift` | Transmit tab |
| `ReceiveView.swift` | Receive tab |
| `DeviceView.swift`, `DeviceRDM.swift` | Device tab and its RDM responder |
| `Manager*.swift` | Manager: codec and keys, engine, TID catalogue, view, self-test |
| `LoopbackTests.swift` | Combined send/receive checks |
| `AppView.swift`, `main.swift` | Window, security panel, app entry point and `--selftest` |
| `docs/manager-wire.md` | Packet format, keys and HMAC, with test vectors |
| `docs/manager-semantics.md` | Discovery, GET/SET, RDM, TID catalogue, timing, spec-vs-library notes |
| `docs/snow-summary.md` | SNOW scope and why it is deferred |
| `Sources/SignetTestSuite/Resources/SigNetLogo.png` | Sig-Net logo (white on green), from the official logo pack |

Sig-Net® is a registered trademark. The logo and colours follow the Sig-Net
Style Guide rev B: the logo is never stretched, and the brand colour is
#065A60 (lightened in Dark Mode for contrast).
