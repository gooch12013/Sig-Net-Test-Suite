---
version: 1
slug: "sources-signettestsuite-managerview-swift"
primary_target: "Sources/SignetTestSuite/ManagerView.swift"
related_targets: ["Sources/SignetTestSuite/AppView.swift","Sources/SignetTestSuite/TransmitView.swift","Sources/SignetTestSuite/ReceiveView.swift","Sources/SignetTestSuite/DeviceView.swift"]
---

# Surface brief: Sig-Net Test Suite app window

## Scope and mode

The whole macOS app window (security strip, Transmit, Receive, Device, Manager), Manager first. Mode: Operate.

## Audience, task, content, constraints

- Firmware engineers on a bench, testing Sig-Net devices on a dedicated network.
- Task: see what a device reports and Get or Set any value in one action; RDM fixtures the same way.
- Content: real values from devices (a gateway node and its RDM fixture). Plain names only on main screens; parameter codes, hex and the packet log live in one Debug area.
- Constraints: native SwiftUI on macOS 13+; network-address, offboard and reboot never one click from main screens; Sig-Net wordmark and logo rules (PRODUCT.md).

## Direction contract

THESIS: The app is a piece of bench test gear: every value is a lit readout with soft keys beside it. It refuses the settings-form utility (System Settings rows, Edit links, segmented tabs) that every Mac tool ships.

OWN-WORLD: Graphite faceplate (#1E2326), raised module panels (#2C3338) with silkscreened uppercase labels, recessed near-black readout windows (#12161A) holding values in SF Mono at bright ink (#E9EEF0). Soft keys are small flat raised keys, GET and SET. Status lamps: green online, Sig-Net teal (#3FA7AE) latched/confirmed, amber (#F0B429) reserved only for a request in flight, red for refusal or fault. Brand teal #065A60 as the faceplate stripe and logo.

STORY: The engineer starts the Manager, picks a device from the rack list, and reads its modules like an instrument panel. Pressing GET relights one readout; SET opens the readout for input and commits on Return. Lamps say pending, latched or refused without reading a word.

FIRST VIEWPORT: Top strip: logo, "Test Suite", security controls. Below, the role tabs. In Manager: a narrow device rack on the left (lamp, name, model and address). Right: a display window with the device name large, model and address, an online lamp and a verified lamp, and one small lamp per port lit when it receives levels. Under it, tabs Info, Parameters, RDM, Debug, then modules of readout rows, each row: label, readout window, GET, SET. Primary action: GET/SET on each row; Find devices on the top strip.

FORM: Bench Instrument (protocol analyser and oscilloscope front panels), my top-ranked grounded candidate (1 of 7), taken as Impeccable's pick over the dealt Live Cut Sheet; seed key a498df9d. Signature interaction: the soft-key press, amber lamp pulsing while in flight, the readout flashing teal when the device confirms, red when it refuses. Motion grammar: 100 ms key press, 1.2 Hz amber pulse, 400 ms latch flash; reduced motion holds steady lamps, no pulse or flash.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance

## Unresolved

- Dark-only faceplate versus following the system appearance: building dark-only; revisit if a light bench needs it.
