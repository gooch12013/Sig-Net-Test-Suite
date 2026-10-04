# Sig-Net SNOW Framework V1.0 - summary for scoping

Source: "Sig-Net SNOW Framework" V1.0 (29 pp, dated 11/7/2026). Section numbers below are the
spec's own. Note the spec has stale cross-references (6.3/6.4/6.5 are cited inconsistently in 6.4 and 6.6).

## 1. What SNOW is and who takes part (1.1, 4, 6.5)

- SNOW = Sig-Net Over Wire. Core Sig-Net only onboards by physical, out-of-band entry of the
  Root Key K0. SNOW is an optional over-the-network alternative for large rigs (1.1).
- A Manager opens an ephemeral TLS tunnel to an unprovisioned (offboarded) device and pushes
  derived keys through it. A Manager-owned directory of device public keys then enables remote
  key rotation and revocation (1.2, 7).
- Roles:
  - Initiating Manager (the onboarding tool). Derives keys, runs TLS client, holds trusted-key
    directory and the POM private key.
  - Node / Sender / Visualiser (the device being onboarded). Runs the TLS server, has a
    factory or first-boot asymmetric key-pair (4.1).
  - Guest Manager (touring console): gets Km_global, Ks, Kc only. No K0, no Km_local (6.5).
  - Equal Manager (backup console): gets K0. Must use PIN verification, Method B (6.4, 6.5, 9.8).
- Licence (1.3): free, but needs on-product attribution text, a unique SoemCode per product
  reported "during a SNOW transaction", and trademark guideline compliance.
- Devices also store one POM (Proof of Management) public key, secp256r1, 64 bytes, as the
  "owner" identity for remote wipe and re-key (4.3).

## 2. Message flow and transports

All SNOW traffic uses the "local" scope regardless of any custom operational scope (6.1).
Payloads use a separate TOTW_ TLV namespace (0x7001-0x700D) with the same 4-byte TLV framing as
core Sig-Net (4.2, 8.3). They sit in CoAP NON POSTs (8.1).

Onboarding (offboarded device):
1. Discovery (6.2): device beacons to <mult_node_beacon> with TID_RT_OTW_CAPABILITY, which
   announces the ephemeral TLS port. Beacon uses Security-Mode 0xFF.
2. Optional IP rescue (5.1, 9.1): Manager multicasts unauthenticated TOTW_RT_COME_HOME
   (TUID + IPv4/mask/gateway) to fix an Auto-IP device. Onboarded devices ignore it (5.4).
3. TLS handshake (6.3): Manager connects by unicast TCP to the announced port. Anonymous,
   forward-secret (e.g. ECDHE). Device sends its public key in a self-signed cert. Manager
   never sends a TLS record over 2,048 bytes.
4. Device sends TOTW_RT_PUBLIC_KEY (9.2) at the app layer.
5. Authentication (6.4), pick one:
   - Method A, visual TOFU (Nodes/Senders only, banned for Equal Managers): Manager sends
     TOTW_RT_IDENTIFY with 32 bytes from the RFC 5705 exporter, label
     "EXPORTER-Sig-Net-SNOW-Identify". Device flashes; operator confirms; key is trusted.
   - Method B, PIN (mandatory for Manager-to-Manager): both sides export 4 bytes, label
     "EXPORTER-Sig-Net-SNOW-PIN", read as big-endian u32 mod 1,000,000, shown as a 6-digit PIN
     on the device and typed into the Manager. Optional QR "SNOW:NNNNNN" (6.4.1).
   - Bypass (6.6): device public key already in an imported JSON manifest.
6. Key delivery (6.5): Manager sends TOTW_RT_SCOPE (9.13), then the role's key TLVs
   (KS 0x7004, KC 0x7005, KM_GLOBAL 0x7006, KM_LOCAL 0x7007, K0 0x7008 Equal Managers only),
   and always TOTW_RT_POM_PUBLIC_KEY (9.9). Device stores the POM key persistently (cleared
   only by factory reset).
7. Teardown (6.7): device acks, closes the listener, commits keys, moves to normal Sig-Net on
   UDP 5683.

Inside the tunnel, CoAP still carries the six Sig-Net security options, Mode 0xFF, and a
zero-length Sig-Net-Auth. The device must process TOTW TLVs despite the usual "drop Mode 0xFF
payload" rule (8.2).

Ongoing (onboarded device):
- Rotation (5.3, 7.1, 9.11): Manager multicasts signed TOTW_RT_OTW_REOPEN (Mode 0x00 with HMAC
  using Km_local, or ECDSA by the POM key; 48 or 80 bytes). Device opens its TLS port for 1-255 s
  (0 = 60 s) and multicasts its TID_RT_OTW_CAPABILITY, signed with Kc, to <mult_node_send>.
  Manager then re-runs TLS and pushes new keys. Identity check is the stored public key, no
  PIN or visual step.
- Node-first rollout (7.1.1): Nodes get the new key first and hold old+new for up to
  <key_rotation_overlap> seconds (try new, fall back to old, drop old on first new-key success).
  Senders switch after all Nodes confirm.
- Wipe (5.2, 9.10): TOTW_RT_POM_WIPE (TUID + 8-byte nonce + 64-byte ECDSA sig, Mode 0xFF)
  multicast to the beacon group factory-resets an onboarded device.
- TOTW_RT_UPDATE_POM (9.12): rotate the POM key, only inside a TLS session.
- Force Beaconing (5.5): an onboarded Manager sends 3 unauthenticated Mode 0xFF beacons
  <on_demand_beacon_interval> ms apart so another Manager can onboard it.
- Revocation (7.2): omit a device from the next rotation round. Manually onboarded devices
  cannot be rotated or revoked remotely (7.3).

## 3. What a test tool would have to build

Not specified in this document: TLS version, cipher suites, the TLS port number (it is
ephemeral and announced in the beacon), and certificate details beyond "self-signed". No PSKs
are used. Section 6.3 says "TLS/DTLS" but only TCP stream behaviour is described. Pin these down
with the authors or against a reference device before coding.

Shared by both roles:
- TOTW TLV encode/decode and the CoAP/security-option wrapper (reuses existing library code).
- TLS 1.2+/1.3 with an RFC 5705 exporter. Check this first: Apple's Network.framework and
  Secure Transport do not (to my knowledge) expose keying-material exporters or accept
  accept-anything self-signed server certs cleanly with exporters, so expect OpenSSL or
  mbedTLS as a new dependency. This is the biggest risk item.
- ECDSA P-256 sign/verify (CryptoKit/Security is enough), HKDF/HMAC-SHA256 (already in the
  library for core Sig-Net).

(a) Onboard a real fixture (Manager role):
- Beacon listener that reads OTW_CAPABILITY and the port; TLS client with anonymous trust.
- PIN entry or identify-confirm UI, a trusted public-key directory (TUID to key), manifest JSON
  import, per-device key derivation, send TLVs in the order above, wait for ack and close.
- Optional: COME_HOME, REOPEN, rotation with node-first ordering, POM key storage, WIPE sender.
- Rough size: about 1.5-2k lines plus the TLS dependency and a PIN/identify UI. Minimal
  (Method A or B, Nodes only, no rotation): the TLS and exporter work dominates.
- Needs a real SNOW fixture to test. None is confirmed to exist (spec dated mid-2026).

(b) Act as a fixture being onboarded (Node role):
- TLS server on an ephemeral port with a self-signed cert from a persistent key-pair; beacon
  with OTW_CAPABILITY; PUBLIC_KEY, IDENTIFY handling and a simulated flash; PIN display.
- Persist keys, scope name, POM key; handle reopen, wipe, COME_HOME (plus the "ignore if
  onboarded" rules); Dual-Key Transition Mode state machine.
- Rough size: similar to Manager-side, a little less UI, more state (offboarded / onboarded /
  tunnel-open / dual-key). Lets you test other Managers without hardware.
- State machines: device (Offboarded, TunnelOpen, Authenticating, KeysReceived, Onboarded,
  DualKey), manager per-device (Discovered, Handshake, Untrusted, Trusted, Delivering, Done).

## 4. Interaction with the main Protocol Framework

- TID_RT_OTW_CAPABILITY is defined in Sig-Net v1.0 Section 11.6.10 (cited in 5.3, 6.2), not in
  this document. It carries the TLS port. The C++ library treats `otw_capability` as an opaque,
  caller-supplied assertion (signet.h around line 836-854), so bytes can be injected today but
  nothing validates or acts on them. Check 11.6.10 for its exact layout before use.
- K0 delivery: only to Equal Managers via TOTW_RT_KEY_K0, PIN-authenticated (6.5, 9.8). Nodes and
  Senders get derived keys only, using the same derivation as manual onboarding. The existing
  key-derivation code is directly reusable.
- Role gating comes from TID_RT_ROLE_CAPABILITY, read by the Manager before choosing keys (6.5).
- Offboarding: manual offboard stays in Sig-Net v1.0 Section 7.7.2. A device still holding a
  previous K0 rejects all SNOW connections (6.6), so it must be offboarded or POM-wiped first.
  POM key survives offboarding and manual onboarding (6.5).
- Post-onboarding traffic is ordinary Sig-Net on UDP 5683. The Mode 0xFF drop rule (v1.0
  Section 8.6 step 1b) needs a TLS-stream exception (8.2).
- Mixed networks: SNOW and manually onboarded devices coexist (1.2); manual ones cannot be
  rotated (7.3).

## 5. Recommendation

- Later, not v1: the TLS-exporter dependency, undefined TLS parameters, and a fixture-less test
  environment make it the largest single feature, and the core protocol works without it.
- For v1, only advertise OTW_CAPABILITY passthrough, show/parse it in discovery views, and
  keep key derivation reusable so SNOW can be added.
- First SNOW slice: fixture-simulator Node role (Method A, TLS server, receive keys), then
  Manager role, then rotation/WIPE.
