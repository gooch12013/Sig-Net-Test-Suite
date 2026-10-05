# Sig-Net test suite

![Sig-Net](Sources/SignetTestSuite/Resources/SigNetLogo.png)

A SwiftUI app for testing Sig-Net® equipment from a Mac. It can transmit,
receive, act as a discoverable fixture, and act as a Manager, in Open or Secure
Mode, so it can test consoles, fixtures and other Managers.

| Tab | Role | What it does |
| --- | --- | --- |
| Transmit | Sender | Up to 16 universes with faders, universe priority, sync, timecode generator (all 11 rates), preview, test patterns (chase, ramp, random) |
| Receive | Node (data plane) | Live 512-slot view per universe, merge source count, frame age and rate, timecode streams, preview frames, diagnostics counters, drops by reason, the last 32 rejected packets, library log |
| Device | Complete Node | A fake fixture that Managers can discover and configure: parameter store with transactions, two proprietary TIDs, a virtual RDM responder per endpoint, offboard and network-change handlers that only log |
| Manager | Manager | Finds devices and lists them by name. Per device: an overview (identity, connection, health, security events), a settings form with each port's live values and inline editing, RDM fixtures by name (identify, label, start address), filtered traffic, and raw TID/PID tools. Poll options are under Advanced |

Every role is written in Swift from the spec (*Sig-Net Protocol Framework
V1.10*), using swift-crypto for HMAC-SHA256 and HKDF. Packets are checked byte
for byte against the spec's test vectors. The protocol code lives in the
portable `SigNet` module, which also builds a command-line tool, `sig-net`, for
Linux and Windows.

SNOW (over-the-wire onboarding) is not implemented. See `docs/snow-summary.md`.

## Build and run

There is no library to build. You need Swift 5.10 or later.

```sh
swift run SignetTestSuite             # the app: macOS 13 or later
swift run sig-net --selftest          # the CLI: macOS, Linux or Windows
swift run sig-net --probe --node <TUID> --ip <device IP> [...]
```

The app is macOS-only (SwiftUI). On Linux and Windows the package builds just
`SigNet` and `sig-net`. CI (`.github/workflows/build.yml`) builds and self-tests
on all three on every push and pull request.

## Security settings

The panel above the tabs sets the mode, passphrase and scope for every device
the app creates. These are fixed when a device is created, so the panel locks
while anything is running.

In Secure Mode the passphrase must pass the Sig-Net rules (10 to 64 characters,
3 of 4 character classes, no runs of 3 identical or 4 sequential characters).
The panel names the failing rule as you type. Peers must use the same
passphrase and scope.

Each part keeps its own device ID (TUID), generated once in ESTA's prototyping
range (`0x7FF0`) and saved in user defaults with its Secure Mode session
counter. The Sender, Device and Manager got new TUIDs when the app moved off the
C library (roles `sender-v2`, `device-v2`, `manager-v2`): the library's session
records could not be carried over, so Nodes that had seen the old TUIDs would
have rejected the new session counters as replays. Self-tests use their own
`selftest-*` roles and never touch these.

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
Allow this traffic through the macOS firewall. On a Mac with more than one
network, pick the interface from the NIC menu in the top strip. Transmit,
Receive, Device and Manager all use it, and the app remembers it between
launches. Like the security settings, it locks while any role is running.

## Self-test

```sh
swift run sig-net --selftest [--offline] [--interface <local IPv4>]
swift run SignetTestSuite --selftest [--interface <local IPv4>]   # same checks
```

Both run one shared list (`Sources/SigNet/SelfTest.swift`) and exit non-zero on
any failure. It takes about 30 seconds. Offline checks, which need no network:

- Timecode frame counting, including drop-frame rates.
- RDM file transfer (ANSI E1.37-4): the controller against a strict Responder emulator on a virtual clock, covering uploads, test mode, damaged packets, cancels, multi-file lists, bootloader switches and downloads. The emulator counts every request that breaks the standard.
- Spec test vectors (Appendix G keys and HMACs) for the Manager, Sender and Receiver, the Receiver's parse path for every drop reason, and the Device's RDM responder on hand-built frames.

Then, in Open and Secure Mode, over multicast loopback inside one process:

- The Sender heard by a plain socket: signatures, sequence numbers, priority, sync, timecode, on-boot announce and TID_UNIVERSE.
- The Device booting twice (the second boot bumps the persisted Session ID).
- The Manager discovering another Manager, then the Device: GET/SET of its label, refusal detection, Table of Devices, RDM DEVICE_INFO and (Secure) rejection of a wrong passphrase.
- Sender to Receiver: multiple universes, priority merging, sync, timecode, preview, and (Secure) rejection of an Open-Mode Sender and of a wrong passphrase.

`--offline` stops after the offline checks. CI uses it on all three platforms,
because hosted runners don't loop multicast back. Run the full list on a real
machine.

## Probing a real device

```sh
swift run sig-net --probe --node <TUID> --ip <device IP> [--interface <local IP>] [--passphrase <p>] [--scope <s>] [--rdm-uid <UID>]
```

Runs the Manager tab's code against one real Node and prints a line per item:
every poll shape at every query level, a GET of every catalogue TID on its
endpoints, SET round-trips (label, identify, endpoint universe, label,
direction, RDM config), then RDM through endpoint 1 (ToD flush and request,
DEVICE_INFO, labels, SLOT_INFO, SLOT_DESCRIPTION 0-10, IDENTIFY on and off).
Every SET is put back afterwards. It never sends offboard, reboot or network
SETs. Omit `--passphrase` for Open Mode. It takes about 2.5 minutes.

## Notes on the reference C library

Earlier versions of this app used the Sig-Net desktop C library. Where it
differs from the spec, gear built on it may behave the same way:

- Its Sender sends no on-boot announce (§10.2.5) and no TID_UNIVERSE (§11.2.6), and doesn't resend paused timecode at 1 Hz (§10.8.1).
- Its timecode shares the levels' Sender endpoint and sequence numbers instead of its own lane (§8.6.2).
- Its Message IDs start at 0, which skips the Open Mode duplicate filter.
- Its Node applies SET transactions that mix in unsupported TIDs (EP_FAILOVER, EP_PROTOCOL, EP_DMX_TIMING) instead of rejecting the whole transaction (§10.1.3), and has no 2-second post-boot SET window (§8.6.4).
- Its Node reports RT_ROLE_CAPABILITY 0x01 in Secure Mode, gives no reply to GET DG_SECURITY_EVENT, and accepts NW_* TIDs only as SETs.
- Its Node answers proprietary TIDs when the request's Mfg-Code is 0, and its `source_count` counts only senders that win at least one slot.

Spec ambiguities worth knowing when testing gear:

- Slots a TID_PRIORITY doesn't cover: §10.6 says priority 0 (not driven), §11.2.2 says 100. This app uses 0.
- §8.6.2 gives each universe its own Sender endpoint, but §10.7.2 matches a single TID_SYNC by Sender-ID. This app's Sender puts all its universes on endpoint 1 so one sync covers them.
- The preview path: §11.2.3 and Appendix A disagree on `{universe}` versus `{stream}`.

More on the library's Manager-facing behaviour is in `docs/manager-semantics.md`.

## Not implemented yet

- SNOW onboarding.
- Manager: suspending its own polling when another Manager is polling, answering other Managers' polls, network-change rollback, offboard and reboot buttons (they can be sent as raw SETs), multi-TID transactions, and RDM flow control.

## Files

| Path | Purpose |
| --- | --- |
| `Package.swift` | Swift package: `SigNet` and `sig-net` everywhere, the app on macOS only |
| `.github/workflows/build.yml` | CI: macOS, Linux and Windows |
| `Sources/SigNet/` | Portable protocol module (Foundation, Dispatch, swift-crypto) |
| `TransmitterEngine.swift`, `ReceiverEngine.swift`, `DeviceEngine.swift`, `DeviceRDM.swift`, `ManagerEngine.swift` | The Sender, the data-plane Node, the complete Node with its RDM responder, and the Manager |
| `Manager*.swift`, `SigNetKeys.swift`, `Security.swift`, `UDPSocket.swift`, `Timecode.swift` | Codec, keys and HMAC, TID catalogue and labels, `--probe`, security settings and TUIDs, multicast socket, timecode |
| `FTC.swift`, `FirmwareUpdate.swift`, `FirmwareSelfTest.swift` | RDM file transfer (ANSI E1.37-4): constants and CRC, the controller, a strict Responder emulator and its self-test |
| `SelfTest.swift` | The `--selftest` list shared by both front-ends, including the Sender-to-Receiver loopback checks |
| `Sources/sig-net/main.swift` | The CLI |
| `Sources/SignetTestSuite/` | The macOS app: one SwiftUI view per tab (`TransmitView`, `ReceiveView`, `DeviceView`, `Manager*View`), `AppView` and `main.swift` for the window and security panel, `Signet.swift` and `Transmitter.swift` for the observable engine wrappers |
| `Snapshot.swift` | Developer aid: `--snapshot out.png` renders the window off-screen (no Screen Recording permission needed) |
| `docs/manager-wire.md` | Packet format, keys and HMAC, with test vectors |
| `docs/manager-semantics.md` | Discovery, GET/SET, RDM, TID catalogue, timing, spec-vs-library notes |
| `docs/snow-summary.md` | SNOW scope and why it is deferred |
| `scripts/make-app.sh`, `docs/packaging.md` | Builds a double-clickable `.app`; notes and limits |
| `Sources/SignetTestSuite/Resources/SigNetLogo.png` | Sig-Net logo (white on green), from the official logo pack |

Sig-Net® is a registered trademark. The logo and colours follow the Sig-Net
Style Guide rev B: the logo is never stretched, and the brand colour is
#065A60 (lightened in Dark Mode for contrast).

## License

The code is under the [PolyForm Noncommercial License 1.0.0](LICENSE). You can
use, change and share it for any non-commercial purpose, including personal
projects, research, testing and teaching. You can't use it in a product or
service that is sold. Anyone who passes on a copy, changed or not, must include
the license and its `Required Notice` line crediting the author.

The license does not cover the Sig-Net® name or logo
(`Sources/SignetTestSuite/Resources/SigNetLogo.png`), which belong to their
owner.

The app no longer uses the Sig-Net desktop C library
(`signet-desktop-src-0.1.0`), whose README states no license; nothing from it
is in this repo or in a packaged `.app`. The separate public
[Sig-Net SDK](https://github.com/WayneHowell/public-sig-net-sdk) (C++ for
Windows, not used here) is MIT-licensed, copyright Singularity (UK) Ltd, per
the header of each source file.
