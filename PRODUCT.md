# Product

<!-- impeccable:product-schema 1 -->

## Platform

macos

Native macOS app in SwiftUI (Swift package, macOS 13+). Impeccable's schema has no macOS value; follow Apple's Mac Human Interface Guidelines rather than web or iOS patterns.

## Users

Firmware and product engineers who build Sig-Net devices (for example a DMX gateway node). They know the protocol deeply and use the app on the bench, on a dedicated test network, to check that a device under development discovers, reports, configures and tunnels RDM correctly, and to debug it when it doesn't.

## Product Purpose

Sig-Net Test Suite lets one Mac play every Sig-Net role against real equipment: transmit levels, receive and diagnose streams, act as a discoverable reference device, and act as a Manager that discovers devices, reads and changes their settings, and talks RDM to the fixtures behind them. Success is an engineer seeing, at a glance, what a device reports and being able to get or set any value with one action, then confirming the device behaved.

## Positioning

The only tool here that implements all four roles, including a Manager written independently from the Sig-Net reference library, so the library's own Node and Sender can be checked against a second implementation and real third-party devices can be exercised end to end.

## Operating Context

- Bench setup: the Mac on a dedicated network interface (e.g. en10 at 2.0.0.1) with a multicast route to 239.254.0.0/16; devices on the same segment.
- Secure Mode with a shared passphrase and scope, or Open Mode.
- Typical session: start the Manager, find the device, read its settings, change one, read it back; discover RDM fixtures on a port, identify one, change its label or address.
- A headless probe (`--probe`) runs the same checks from the command line and reports per item; a self-test (`--selftest`) checks all roles against each other in-process.

## Capabilities and Constraints

- Roles: Transmit (Sender), Receive (data-plane Node), Device (complete Node acting as a fake fixture), Manager (pure Swift with CryptoKit).
- The Manager handles one request at a time; values shown are the last ones the device reported.
- Network-address changes, offboarding and reboot are dangerous and must never be one click from the main screens.
- Not implemented: SNOW onboarding.
- Terminology: the protocol calls parameters "TIDs" and RDM parameters "PIDs". Users do not want these codes, hex or underscored protocol names on the main screens. They stay reachable in a separate debug area, together with the packet log.

## Brand Commitments

- Sig-Net Style Guide rev B: write "Sig-Net" (capital S and N, hyphenated, never "Signet" or "SigNet"); "Sig-Net®" at the first text mention in manuals and marketing; logo colour black, white or #065A60; never stretch the logo.
- Logo asset: `Sources/SignetTestSuite/Resources/SigNetLogo.png` (white on green).
- The code name `SignetTestSuite` stays as an internal identifier only; user-facing text says "Sig-Net Test Suite".

## Evidence on Hand

- A real bench node (a DMX gateway) with an RDM fixture on port 1, reachable during development.
- No customer data, testimonials or performance claims exist; none should be invented.

## Product Principles

1. Data first: show what the device reports, in plain words, before anything about how it was fetched.
2. Every value is one action away from Get and, where allowed, Set.
3. Protocol detail is for debugging: present and complete, but out of the way.
4. Never let a dangerous change happen by accident.
5. Tell the truth about the device: a refusal, a silence and a success must look different.
