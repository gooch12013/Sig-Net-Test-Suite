# Sig-Net Manager: message semantics and TID catalogue

Scope: what a Swift **Manager** (plus a test/sniffer tool) must send, expect and interpret. CoAP options,
HMAC, key derivation, URI encoding and multicast address arithmetic live in `manager-wire.md`; this file
only names them.

Sources and citation style:
- Spec = *Sig-Net Protocol Framework V1.10*, cited as `§x.y (L<n>)` where `L<n>` is the line in a
  `pdftotext -layout` dump of the revision these notes were first written against; § numbers are current.
- "lib" means the reference C++ implementation (Node/Sender only, there is no Manager in it). Where lib and spec disagree it is flagged **[Δ]**.

All multi-byte integers are big-endian (network order). TLV = `TID u16 | LEN u16 | VALUE[LEN]` (§10.1, L1990).

---

## 0. Quick model

| Concept | Rule | Ref |
|---|---|---|
| Who talks where | Manager → `/poll` (multicast `<mult_manager_poll>`, Km_global). Manager → `/manager/{tuid}/{ep}` (unicast preferred, or multicast `<mult_manager_send>`, Km_local of target). Devices → `/node/{tuid}/{ep}` (always **multicast** `<mult_node_send>`, Kc). Lost Nodes → `/node_lost/{tuid}/0` (Kc). Offboarded → `/node_beacon/{tuid}/0` (unauthenticated, Security-Mode 0xFF). | §10.3.1 L2244, App A L4297 |
| GET vs SET | No opcode. **LEN = 0 means GET**, LEN > 0 means SET/command. Replies never use LEN 0. | §10.4.3 L2370 |
| Atomicity | One packet = one transaction. Any invalid SET TLV → whole packet dropped silently, nothing applied, no reply. | §10.4.2 L2319 |
| Confirmation | Valid SET → Node multicasts the applied TLVs + trailing `TID_SET_REPLY{CHANGE_COUNT}` to `/node/{tuid}/{ep}`. | §10.4.2 L2335 |
| Consistency | `CHANGE_COUNT` (u16, wraps) bumps once per transaction that changed ≥1 persistent param. Manager compares it on every POLL_REPLY / SET_REPLY; mismatch → targeted poll. | §10.4.4 L2384 |
| Replies are shared | Every reply is multicast, so every Manager sees every reply. Passive Managers sync by snooping. | §13.2 L4180 |
| Guest Manager | Has Km_global/Ks/Kc but not Km_local → cannot GET/SET/RDM; reads only via targeted `TID_POLL`. | §6.2 L894, §10.4.3 L2372 |

---

## 1. Discovery (§10.2)

### 1.1 TID_POLL (0x0001, 25 bytes) — sent by Manager to `/poll`

| Bytes | Field | Notes |
|---|---|---|
| 0-5 | MANAGER_TUID | Manager's own 48-bit TUID (software: Device ID MSB=1, random, §6.6 L956) |
| 6-9 | MANAGER_SOEM_CODE | u32: ESTA mfr ID (hi16) + product variant (lo16); 0 reserved (§6.5 L936) |
| 10-15 | TUID_LO | inclusive range start |
| 16-21 | TUID_HI | inclusive range end. Compared as 48-bit big-endian unsigned |
| 22-23 | END_POINT | u16; `0xFFFF` = all endpoints (root + every data EP, one reply stream each) |
| 24 | QUERY_LEVEL | 0 HEARTBEAT, 1 CONFIG, 2 FULL, 3 EXTENDED |

Validation in lib: LEN must be 25, `TUID_LO <= TUID_HI`, `QUERY_LEVEL <= 3`, else the **whole packet** is
dropped. There are no other filters (no SoemCode/mfr filter) — only the TUID range.

Poll shapes a Manager uses:

| Purpose | TUID_LO / TUID_HI | QL | EP | Transport | Ref |
|---|---|---|---|---|---|
| Routine heartbeat (every `<poll_time>`=3 s) | `000000000000` / `FFFFFFFFFFFF` | 0 | 0 (spec silent; 0 or 0xFFFF both legal) | multicast | §10.2.2 L2095 |
| Initial population (boot, new network, operator "Full Refresh" only) | 0 / MAX | 2 (FULL) | 0xFFFF | multicast | §10.2.2 L2126 |
| Follow-up after CHANGE_COUNT change | target / target | ≥1 | 0xFFFF or the changed EP | unicast to source IP of the reply | §10.4.4 L2431-2438 |
| IP-change rollback verification | target / target | any (0 fine) | 0 | **unicast** to the Node's NEW IP | §10.4.7 L2474 |
| Guest read-only fetch | target / target | as needed | as needed | multicast or unicast | §10.4.3 L2372 |
| Open-Mode discovery (optional) | 0 / MAX | 0 | 0 | multicast, Security-Mode 0x01 | §10.2.2 L2130 |

Prohibited: global polls with QL>0 as part of routine background polling (§10.2.2 L2120).

### 1.2 What a Node returns per QUERY_LEVEL (§10.2.3 L2133, §11.9 L3943)

Every reply packet **starts with TID_POLL_REPLY**, then every supported TID for that endpoint whose poll
category ≤ QL, in ascending TID order in lib. Root and each data EP reply
in separate packets to `/node/{tuid}/{ep}`; the EP comes from the URI, not the payload.

| QL | Root (EP 0) adds | Data EP adds |
|---|---|---|
| 0 HEARTBEAT | ENDPOINT_COUNT 0x0602, RT_MULT_OVERRIDE 0x0606 | nothing (bare POLL_REPLY) |
| 1 CONFIG | DEVICE_LABEL 0x0605, RT_IDENTIFY 0x0607, RT_STATUS 0x0608 | RDM_EP_CONFIG, RDM_FLOW_CONTROL, all EP_* 0x0901-0x090C |
| 2 FULL | SUPPORTED_TIDS, PROTOCOL_VERSION, FIRMWARE_VERSION, ROLE_CAPABILITY, MODEL_NAME, OTW_CAPABILITY, all NW_* | — |
| 3 EXTENDED | DG_SECURITY_EVENT (one TLV per tracked code), DG_MESSAGE | DG_MESSAGE (lib: both) |

Never in poll replies: DG_LEVEL_FOLDBACK (GET only), anything N/A in §11.9.

### 1.3 TID_POLL_REPLY (0x0002, 12 bytes)

`[0-5] TUID | [6-9] SOEM_CODE u32 | [10-11] CHANGE_COUNT u16` (§11.1.2 L2862). Endpoint = URI segment.

### 1.4 Reply timing a Manager must wait for

| Poll kind | Node behaviour | Manager wait before retry/"absent" | Ref |
|---|---|---|---|
| Targeted (LO==HI) | reply "within" `<node_processing_max>` = 500 ms, no backoff | 500 ms is the spec's retransmit threshold | §10.2.3 L2155 |
| Range/broadcast | random 0..`<poll_backoff_max>`=1000 ms, then ≤500 ms | ≥1500 ms; cycle is 3 s anyway | §10.2.3 L2159 |
| EP = 0xFFFF | ≥`<endpoint_spacing_delay>`=1 ms between per-EP packets | add N_endpoints ms + fragments | §10.2.3 L2163 |
| Fragmented reply | several self-contained packets, each led by POLL_REPLY, any order | accept and merge independently | §10.2.4 L2180 |

**Reply supersession:** a Node that gets a new command mid-reply aborts the old reply sequence and drops its
unsent packets (§10.2.3 L2169). So do not pipeline several requests to one Node; wait for the reply or
timeout before sending the next. Lib queues at most 4 distinct pending poll replies per device.

Payload ceiling: CoAP message ≤1400 B, TLV payload after 0xFF marker ≤1200 B (§10.2.4 L2181). Manager
packing of batched SETs/GETs must respect the same limits (§10.4.2 L2311).

### 1.5 Multi-Manager poll snooping ("Discovery Master") — §10.2.2 L2099-2119

1. On start, listen on `<mult_manager_poll>` silently for `3 × (poll_time + manager_poll_jitter)` = 10.5 s.
   If another Manager's valid TID_POLL is seen, suspend own routine polling.
2. While suspended, resume only after 3 consecutive missed `<poll_time>` intervals from the master.
3. Before resuming, add uniform 0..500 ms jitter; if a poll is heard during jitter, cancel and stay passive.
4. Only the active (non-suspended) Manager runs background RDM GET polling (§10.5.2 L2531).
5. Managers must HMAC-verify snooped `/poll` packets too (§8.6.1 L1773).

Mixed versions: a Manager polls its own major version and one previous (`/sig-net/v2/.../poll` and
`/sig-net/v1/.../poll`) and talks to each Node with that Node's version's URI/KDF/HMAC (§12.3 L4112).

### 1.6 On-boot announcement (§10.2.5 L2190)

Every Device (any role, including other Managers and pure Senders) sends once after boot + link-up, after a
random 0..1000 ms delay, to `/node/{tuid}/0`, signed Kc, payload in this exact order:
`POLL_REPLY, RT_PROTOCOL_VERSION, RT_ROLE_CAPABILITY, RT_ENDPOINT_COUNT, RT_MULT_OVERRIDE, [RT_OTW_CAPABILITY]`.
Your Manager must send this too.

Manager reaction: add/refresh the device, then (a) do **not** send SETs/commands for
`<first_packet_bootstrap_window>` = 2000 ms after its link-up — they will be silently rejected (§8.6.4 L1830);
(b) send a targeted FULL poll; (c) remember its boot time for offboarding (§7.7.1). [Δ] lib does not
implement the 2 s bootstrap lockout, other vendors will.

### 1.7 Lost Mode (§10.2.6 L2211)

- **Manager side:** a device is lost after `<node_lost_timeout>` = 3 consecutive poll cycles with no
  POLL_REPLY (≈9 s at 3 s polling). Any packet carrying POLL_REPLY (poll reply, on-boot, node_lost, beacon)
  counts as presence.
- **Node side:** if no valid TID_POLL from *any* Manager for 3 poll intervals, the Node enters Lost Mode and
  sends to `/node_lost/{tuid}/0` every `<poll_time>`, payload identical to the on-boot set. Any received
  poll (even one not targeting it) resets the timer.
- **Diagnostic:** receiving `/node_lost` from a device you show as Online means your polls are not reaching
  it (one-way routing fault) (§10.2.6 L2232). HMAC failures on `/node` or `/node_lost` must be logged and
  surfaced as a possibly compromised TUID (§8.6.1 L1780).

### 1.8 Offboarded beacons (§10.2.1 L2036)

- To `/sig-net/v1/local/node_beacon/{tuid}/0` (always scope `local`) on `<mult_node_beacon>`, no more often
  than every `<beacon_min_interval>` = 5 s.
- Security-Mode 0xFF, Sender-ID = TUID + EP 0x0000, Mfg-Code 0, Session 0, Seq 0, **no Auth option**; do not
  HMAC-check it (App A note 1, L4322).
- Payload order: `POLL_REPLY (CHANGE_COUNT=0), RT_DEVICE_LABEL, RT_ROLE_CAPABILITY, RT_ENDPOINT_COUNT,
  [RT_OTW_CAPABILITY]`.
- Manager display rules (mandatory): show source IP next to TUID and label; flag as spoofing anomaly if the
  same TUID beacons from different IPs within `<beacon_timeout>` = 30 s; drop entries not refreshed within
  30 s; should hide beacons for TUIDs already in the authenticated table.
- On-demand beaconing: an onboarded Manager may send 3 unauthenticated beacons 500 ms apart
  (`<on_demand_beacon_interval>`) (§10.2.1 L2087).
- Offboarded devices discard every inbound Sig-Net packet; the only way in is out-of-band onboarding
  (OTW port/protocols from RT_OTW_CAPABILITY, §11.6.12).

### 1.9 Per-device display (suggested columns)

| Field | Source |
|---|---|
| TUID `MMMM:DDDDDDDD` (uppercase hex, §6.6 L972) | POLL_REPLY / URI |
| Manufacturer ID, product variant | TUID hi16; SoemCode hi16/lo16 |
| Source IP (update on every reply, §10.4.4 L2434) | UDP source |
| State: Online / Lost / node_lost-but-online (routing fault) / Beacon (offboarded) / Open Mode | §10.2.6, §10.2.1, RT_STATUS bit 3 |
| CHANGE_COUNT, last seen | POLL_REPLY, SET_REPLY |
| Device label, model, firmware (u32 + string), protocol version | 0x0605, 0x060B, 0x0604, 0x0603 |
| Roles (Node/Sender/Manager/Visualiser), Root firmware support, Open Mode support | 0x0609 |
| Endpoint count; per-EP universe, label, direction, capability, status, failover, protocol | 0x0602, 0x09xx |
| Health: hardware fault, factory defaults, UI-locked | 0x0608 |
| Multicast override in use | 0x0606 |
| Network: mode, configured vs current IPv4/IPv6, MAC | 0x05xx |
| Security events (counts, last offending IP), diagnostic messages | 0xFF01, 0xFF02 |
| RDM: ToD per EP, FIFO total/available, background discovery/queue flags | 0x0304, 0x0306, 0x0305 |
| Active universes per Sender (from TID_UNIVERSE) | 0x0203 |
| Security anomalies (HMAC/replay failures on /node) | Manager-side §8.6.1 |

---

## 2. Management GET / SET (§10.4)

### 2.1 Addressing

| Endpoint | Meaning | Ref |
|---|---|---|
| 0 | Root: device-wide TIDs (RT_*, NW_*, DG_SECURITY_EVENT, OFFBOARD, REBOOT) | §6.8.1 L991 |
| 1..N (N = RT_ENDPOINT_COUNT, ≤0xFF00, consecutive from 1) | Data EPs: EP_*, RDM_*, DG_LEVEL_FOLDBACK | §6.8.2 L1002 |
| 0xFF01-0xFFFE | reserved: Node discards | §6.8.3 |
| 0xFFFF | broadcast: each TLV applied to every endpoint where its target class fits (root TID → EP 0 once; data TID → EPs 1..N). Replies come per endpoint, ≥1 ms apart | §6.8.4 L1028 |

A TLV whose target class does not match the endpoint (e.g. EP_UNIVERSE on EP 0): as GET it is skipped; as SET
it invalidates the whole packet (§10.1.3 L2024). A non-existent endpoint
→ whole packet dropped. Broadcast SET of a data TID on a device with 0 data EPs → dropped.
Broadcast SET where any fanned-out EP rejects → whole packet dropped.

### 2.2 Request shapes

```
GET:   [TID][0x0000]                        (any number, any order)
SET:   [TID][LEN>0][value]                  (any number; one packet = one atomic transaction)
Mixed: GETs, SETs, RDM TLVs may share a packet
```
- Unknown TIDs are skipped by length (§10.1 L1996). Proprietary TIDs (≥0x8000) are interpreted only when
  the CoAP Mfg-Code equals the Node's ESTA ID (§10.1.2 L2004).
- TIDs that do not belong on the Command URI (e.g. POLL_REPLY, LEVEL) are silently ignored; a packet
  containing only such TIDs gets no reply.
- Every packet needs a fresh Seq-Num; a retransmission is a new packet (see manager-wire.md).

### 2.3 Node reply rules (what the Manager receives)

| Case | Reply on `/node/{tuid}/{ep}` | CHANGE_COUNT |
|---|---|---|
| SET valid, ≥1 persistent change | echo of each applied SET TLV (lib echoes the **request bytes**) + trailing SET_REPLY | +1 (once per packet) |
| SET valid, no change or only volatile params | echo + trailing SET_REPLY | unchanged |
| Any SET invalid / out of range / read-only / unsupported / wrong EP class / HMAC bad / bootstrap window | **nothing** | unchanged |
| GET only | requested values, packed, request order; unsupported/non-queryable silently omitted; **no SET_REPLY** | — |
| GET where nothing resolves | **no packet at all** | — |
| Mixed GET+SET | responses in command order, SET_REPLY last | as SET |
| RDM TLVs in packet | never echoed; RDM_RESPONSE comes separately later | — |
| Fragmented (>1200 B) | split at TLV boundaries, SET_REPLY only on the final chunk | — |

Within `<node_processing_max>` = 500 ms (§10.4.2 L2342).

### 2.4 TID_SET_REPLY (0x0003, 3 bytes)

`[0] flags (reserved, 0) | [1-2] CHANGE_COUNT u16`. Always the **last** TLV of a SET confirmation or
proactive notification (§11.1.3 L2876).

### 2.5 CHANGE_COUNT and eventual consistency (§10.4.4 L2384, §10.4.5 L2439)

- Persisted u16, wraps. Bumped by valid changes to `Persistent: Yes` TIDs from any cause (network, front
  panel, RDM side-effect). Not bumped by volatile TIDs (status, identify, reboot) or by RDM-parameter changes.
- Reset to 0 on offboarding (§7.7 L1388). Lib also counts proprietary TIDs as persistent unless the app
  declares them volatile.
- Manager algorithm:
  - On SET_REPLY: `rx == cached` (no-op) or `rx == cached+1 mod 2^16` (the change you just saw) → accept;
    anything else → targeted poll.
  - On POLL_REPLY: `rx != cached` → targeted poll, QL ≥ CONFIG (FULL if NW settings may have changed).
  - Before that poll, update the device's IP from the UDP source of the reply (§10.4.4 L2434).
  - Treat any mismatch, including a decrease, as "refresh" (spec says "greater than"; a decrease means
    offboard/reset or wrap).

### 2.6 Proactive notifications (Node → all Managers)

- On any config or status change, Node multicasts to `/node/{tuid}/{ep}` (ep 0 for global): the changed
  TLV(s) + trailing SET_REPLY (§10.4.4 L2399).
- Status TIDs (RT_STATUS, EP_STATUS) are rate-limited to one per `<status_publish_rate>` = 1 s per EP,
  coalesced (latest state wins, no FIFO) (§10.4.4 L2408).
- Linked-hardware side effects (one SET changes several EPs) are notified for every affected EP (§6.8.2 L1016).
- RDM-side changes arrive as unsolicited TID_RDM_RESPONSE (GET_COMMAND_RESPONSE), see §3.
- RDM FIFO changes: unsolicited TID_RDM_FLOW_CONTROL (§11.3.6 L3142).
- Security: TID_DG_SECURITY_EVENT (≤1/s per code); diagnostics: TID_DG_MESSAGE (≤1/5 s per fault).
- After an IP rollback: restored-state notify (lib sends NW_IPV4_CURRENT or NW_IPV6_CURRENT).

A Manager should treat any received `/node` TLV as authoritative state for (tuid, ep), regardless of who
caused it.

### 2.7 Timeouts, retries, and telling refusal from loss

Spec gives only the threshold: `<node_processing_max>` = 500 ms is "the Manager timeout threshold used to
schedule retransmissions" (App B L4367). No retry count is specified. Suggested policy:

1. Unicast request; wait 500 ms (+ RDM allowances, §3.6).
2. Retry up to 2 more times (new Seq-Num each). SET retransmission is idempotent (unchanged value → echo,
   no bump).
3. Still silent → probe: send a targeted GET of the same TID(s) (or a targeted poll QL1).
   - GET answered, SET not → **refused** (invalid value, read-only, wrong EP class, unsupported, UI lock,
     bootstrap window, offboard lockout, IP txn rules, or wrong Km_local).
   - Nothing answered → device unreachable; check Lost state, try multicast `<mult_manager_send>` (Node on
     wrong subnet, §10.3.2 L2269).
4. Narrow down a refusal: read RT_STATUS bit 2 / EP_STATUS bit 2 (UI-locked); GET DG_SECURITY_EVENT and
   watch code 0x0001 (HMAC fail → key mismatch) and 0x0008 (failed offboard); compare value against the
   catalogue ranges below; resend SETs one TLV per packet to find the bad one.

Because refusal is silent by design (anti-amplification, §10.4.2 L2326), the UI should say "no
confirmation" rather than "rejected" until the probe completes.

Never send a new command to the same Node while waiting for a reply (supersession, §1.4).

### 2.8 Network reconfiguration (§10.4.7 L2457)

Rules a Manager must obey (spec + what lib enforces):

| Rule | Lib behaviour if broken |
|---|---|
| All NW TIDs for the change in **one** packet to EP 0 | n/a (single packet is the transaction) |
| Packet contains only NW SET TLVs (no label/universe etc.) | discarded "mixed with unrelated SETs" |
| One family per packet (IPv4 0x0502-0x0505 or IPv6 0x0581-0x0584) | discarded |
| MODE TID always present | discarded |
| Static (mode 0): IPv4 needs ADDRESS+NETMASK (GATEWAY optional); IPv6 needs ADDRESS+PREFIX | discarded |
| DHCP/SLAAC/DHCPv6 (mode≠0): **no** address/mask/prefix/gateway TIDs | discarded |
| Only one IP transaction in flight per Node | discarded |
| IPv4 mode ≤1, IPv6 mode ≤2, prefix ≤128, exact lengths | discarded |
| Not via RDM on virtual EPs (E1.37-2/E1.33 SETs NACKed) | §10.5.3 |

Sequence:
1. Manager sends the NW SET packet (unicast to current IP).
2. Node replies (echo + SET_REPLY) **from its old IP**, then applies the new settings.
3. Node starts `<ip_rollback_timer>` = 60 s.
4. Manager sends a **targeted, unicast** TID_POLL (`/poll`, Km_global, TUID_LO=TUID_HI=target) to the
   Node's **new** IP. Lib only accepts it if the packet arrived unicast;
   multicast polls do not count. Repeat every ~1-2 s until a POLL_REPLY arrives from the new IP or 60 s pass.
5. Verified → Node commits. Not verified in 60 s → Node reverts to the old config and multicasts its restored
   state (lib: NW_*_CURRENT) on `<mult_node_send>`.
6. Static IPv4 netmask/gateway mismatches with the Manager's subnet: the unicast poll still has to reach the
   Node, so the Manager host must be able to route to the new address.

DHCP case: the Manager does not know the new address in advance. Suggested approach (not in spec): send a
targeted *multicast* poll, take the source IP of the POLL_REPLY (Node still answers multicast polls, it just
does not count them as verification), then send the targeted unicast poll there.

### 2.9 Offboarding (§7.7.1 L1402, §11.4.1 L3152)

- `TID_RT_OFFBOARD` (0x0401), value `57 49 50 45` ("WIPE"), unicast to `/manager/{tuid}/0`.
- Accepted only within `<offboard_lockout>` = 300 s after **physical** power-on (a TID_RT_REBOOT does not
  reset the window) and, for vendors implementing §8.6.4, not in the first 2 s after link-up. Workflow:
  operator power-cycles the device → Manager sees on-boot announcement → wait ≥2 s → poll → send OFFBOARD.
- Must be the only SET in the packet (lib rejects OFFBOARD mixed with any other SET).
- Lib replies with the echo + SET_REPLY **before** wiping; if the reply
  cannot be sent, the wipe is abandoned. After wiping: keys deleted, CHANGE_COUNT reset to 0, device appears
  as a beacon (§1.8).
- Too late → silent drop + DG_SECURITY_EVENT 0x0008 on the Node.

### 2.10 Other command TIDs

- `TID_RT_REBOOT` (0x060A, 5 B): `[0]` 0xFF hardware reset / 0xFE warm reboot, `[1-4]` "BOOT"
  (`42 4F 4F 54`); wrong magic → ignored. Expect an echo, then the device disappears and re-announces.
- `TID_RT_IDENTIFY` and `TID_EP_IDENTIFY` are independent; to clear all indicators send both = 0 to EP 0xFFFF
  (§11.6.7 L3467).
- `TID_RT_MULT_OVERRIDE` SET accepts only 0x00 (reset every EP override to default folding).
- `TID_EP_PROTOCOL` → Art-Net/sACN removes authentication from level data: Manager **shall** warn and
  require operator confirmation (§11.7.11 L3821).

---

## 3. RDM tunnelling (§10.5, §11.3)

### 3.1 Messages

| TID | Direction / URI | Value |
|---|---|---|
| 0x0301 RDM_COMMAND | Manager → `/manager/{tuid}/{ep}` (Km_local) | one full E1.20 request frame, 26-257 B, start code through checksum |
| 0x0302 RDM_RESPONSE | Node → `/node/{tuid}/{ep}` (multicast) | one full E1.20 response frame, 26-257 B. Lib appends RDM_FLOW_CONTROL in the same packet |
| 0x0303 RDM_TOD_CONTROL | Manager → data EP | `0x00` = send TOD_DATA now; `0x01` = flush ToD and run full discovery. Other values invalid |
| 0x0304 RDM_TOD_DATA | Node → data EP | `[0] Packet_Index 1..Total`, `[1] Total_Packets`, `[2..] UID×6`. Empty ToD = `01 01`. Fragments sent back-to-back, no pacing. Retrieve with TOD_CONTROL 0x00, not GET (§11.3.4 L3101) |
| 0x0305 RDM_EP_CONFIG | GET/SET data EP | bit0 background discovery (default on), bit1 background queue polling (default on); persistent |
| 0x0306 RDM_FLOW_CONTROL | GET; unsolicited from Node | `[0] total FIFO slots`, `[1] available` (available ≤ total) |

Several RDM_COMMAND TLVs may share one packet, alongside SETs; RDM TLVs are delivered only after the SET
transaction commits and are never part of its atomicity. Broadcast EP
0xFFFF fans an RDM_COMMAND to every applicable endpoint.

### 3.2 Endpoint restrictions

- Root (EP 0): only E1.37-4 [FTC] firmware-transfer PIDs, and only if RT_ROLE_CAPABILITY bit 6
  (Root_Firmware_Support); everything else ignored (§6.8.1 L995, §11.3.1 L3038). Root is not an RDM
  responder (no SUPPORTED_PARAMETERS, IDENTIFY_DEVICE).
- Physical data EP: proxied onto the DMX/RDM line.
- Virtual data EP (EP_CAPABILITY bit 4): internal responder. SETs of E1.33 / E1.37-2 network PIDs return
  NACK NR_UNSUPPORTED_COMMAND_CLASS (0x0005) or NR_WRITE_PROTECT (0x0008) (§10.5.3 L2543). GETs allowed.
  Lib blocks SET PIDs 0x0700-0x070D and 0x0800-0x0803 on virtual EPs and leaves the NACK to the app —
  a lib-based Node may answer with nothing.
- RDM only works on EPs with EP_CAPABILITY bit 2 (consume RDM) and EP_DIRECTION bit 2 (RDM enabled).
- **Never** tunnel DISCOVERY_COMMAND (CC 0x10) or PIDs DISC_UNIQUE_BRANCH/DISC_MUTE/DISC_UN_MUTE
  (0x0001-0x0003); the whole packet is dropped (§10.5.5 L2616). Nodes own discovery; use TOD_CONTROL.
  [Δ] lib has no CC 0x10 filter; the app must enforce it.

### 3.3 E1.20 frame the Manager builds (big-endian)

| Off | Field | Manager request value |
|---|---|---|
| 0 | START CODE | 0xCC |
| 1 | SUB START CODE | 0x01 |
| 2 | MESSAGE LENGTH | 24 + PDL (bytes 0..end of PD; frame size = this + 2) |
| 3-8 | DEST UID | responder UID from TOD_DATA (or broadcast FFFF:FFFFFFFF / mfr-broadcast mmmm:FFFFFFFF) |
| 9-14 | SOURCE UID | Manager's UID — use the Manager TUID (see §3.4) |
| 15 | TN | transaction number, increment per request; echoed in response |
| 16 | PORT ID / RESPONSE TYPE | request: port ID 1-255 (use 0x01); response: 0 ACK, 1 ACK_TIMER, 2 NACK_REASON, 3 ACK_OVERFLOW |
| 17 | MESSAGE COUNT | 0 in requests; queued-message count in responses |
| 18-19 | SUB-DEVICE | 0x0000 root, 1-512, 0xFFFF all |
| 20 | CC | 0x20 GET, 0x30 SET (responses 0x21 / 0x31); 0x10/0x11 forbidden here |
| 21-22 | PID | |
| 23 | PDL | 0-231 |
| 24.. | PD | |
| 24+PDL | CHECKSUM u16 | sum of bytes 0..23+PDL, mod 65536 |

Lib validates exactly this (start codes, LEN==size-2, 26..257, checksum) when frame validation is on. A bad frame is dropped silently.

### 3.4 Manager UID vs TUID (§6.7 L982)

§6.7 only requires a native RDM-responder Device to use one 48-bit value for both TUID and E1.20 UID.
For a Manager nothing is mandated; using the Manager's TUID (mfr ID + dynamic Device ID with MSB=1) as the
RDM source UID keeps one identity and lets every Manager pick its own responses out of the shared multicast
stream by `DEST UID == my UID` plus TN.

### 3.5 Response handling

- Responses (and proactive state changes) are **multicast** to all Managers. Correlate by
  (tuid, ep, dest UID == mine, TN, PID). Responses with another Manager's UID are still useful cache
  updates.
- Proactive: any RDM parameter change (front panel, other Manager, broadcast SET, queued message) →
  unsolicited RDM_RESPONSE with GET_COMMAND_RESPONSE (§10.5.2 L2514). The Node runs GET QUEUED_MESSAGE
  itself (§10.5.4 L2567). Optional slow background RDM GET polling is done only by the active Discovery
  Master; others snoop (§10.5.2 L2528).
- **ACK_TIMER**: informative "pending"; extend your timeout by the PD estimate (×100 ms). Do **not** send
  follow-up requests; the Node fetches the result and multicasts the final response (§10.5.4 L2602).
- **ACK_OVERFLOW**: the Node pumps the sequence itself and forwards each block as it arrives (possibly
  several RDM_RESPONSE TLVs per packet). Concatenate PD until a final ACK. The Manager must **not** pump
  (§10.5.4 L2573).
- **Flow control**: never have more RDM commands outstanding on an EP than RDM_FLOW_CONTROL.available
  (§11.3.6 L3144). Read it via GET or poll CONFIG; it updates unsolicited on every change and rides on most
  RDM_RESPONSE packets. While an overflow pump runs, queued commands are held, so expect latency.

### 3.6 RDM timing

| Item | Value | Ref |
|---|---|---|
| Response after physical transaction completes | ≤`<node_processing_max>` 500 ms | §10.5.1 L2510 |
| Proactive response random delay | 0..`<rdm_backoff_max>` 250 ms, then ≤500 ms | §10.5.2 L2520 |
| [Δ] lib backoff | unicast-triggered: immediate; multicast-triggered/proactive: 0..**1000 ms** (`poll_backoff_max`) | — |
| Suggested Manager timeout | unicast: 500 ms + DMX line time (≈30-50 ms per hop); multicast: 1.5 s; extend on ACK_TIMER | — |

---

## 4. TID catalogue (§11)

Legend. **G** = queryable via LEN 0 GET. **S** = Manager may SET on the Command URI. **C** = one-shot command (SET-only, not queryable). **Scope** R = root (EP 0),
D = data EP, R+D = both. **P** = Persistent (bumps CHANGE_COUNT). **Poll** = QUERY_LEVEL category
(H/C/F/E; `–` = never in poll replies). **Node mandate** from spec §11.10: Y, N, D = if data EPs,
RDM = if EP supports RDM, OTW = if OTW onboarding, MO = if multicast override supported. **Len** = value
bytes; `0/x` means GET is LEN 0, response/SET is x. Labels/names use an encoding byte `0x00 = ASCII` then
≤64 text bytes, not NUL-terminated.

### 4.1 Discovery family (0x00xx)

| TID | Name | § | Ops | Scope | P | Poll | Node | Len | Value |
|---|---|---|---|---|---|---|---|---|---|
| 0x0001 | TID_POLL | 11.1.1 | Manager→`/poll` only | R+D | N | – | Y | 25 | see §1.1 |
| 0x0002 | TID_POLL_REPLY | 11.1.2 | Node reply | R+D | N | H | Y | 12 | `[0-5]` TUID, `[6-9]` SoemCode u32, `[10-11]` CHANGE_COUNT u16 |
| 0x0003 | TID_SET_REPLY | 11.1.3 | Node reply, last TLV | R+D | N | – | Y | 3 | `[0]` flags=0 reserved, `[1-2]` CHANGE_COUNT u16 |

### 4.2 Sender / data plane (0x01xx, 0x02xx) — not on Command URI

| TID | Name | § | URI | P | Node | Len | Value |
|---|---|---|---|---|---|---|---|
| 0x0101 | TID_LEVEL | 11.2.1 | `/level/{u}` u=1..63999 | N | D | 1-512 | slot 1..n levels, NSC only (no start-code byte) |
| 0x0102 | TID_PRIORITY | 11.2.2 | `/level/{u}` | N | N | 1-512 | each 0-200; LEN 1 = whole-universe priority. Must precede LEVEL in same packet. Lib rejects any byte >200 |
| 0x0103 | TID_PREVIEW | 11.2.3 | `/preview/{u}` → `<mult_preview>` only | N | N | 1-512 | like LEVEL, for visualisers |
| 0x0201 | TID_SYNC | 11.2.4 | `/sync` (Ks) | N | N | 0 | none |
| 0x0202 | TID_TIMECODE | 11.2.5 | `/timecode/{s}` s=1..255 | N | N | 5 | `[0]` h 0-23, `[1]` m 0-59, `[2]` s 0-59, `[3]` frame, `[4]` rate: 0 24, 1 25, 2 29.97DF, 3 30, 4 48, 5 50, 6 59.94DF, 7 60, 8 100, 9 119.88DF, 10 120. Lib frame max per rate = 23,24,29,29,47,49,59,59,99,119,119 |
| 0x0203 | TID_UNIVERSE | 11.2.6 | Sender → `/node/{tuid}/0` | N | N (Sender Y) | 9 | `[0-1]` universe u16 1..63999, `[2]` 1 Join / 2 Leave, `[3-6]` IPv4 group (0.0.0.0 = default folding), `[7-8]` originating Sender EP u16 |
| 0x0204 | TID_OSC | 11.2.7 | `/aux/{tuid}/{ep}` (Ks) | N | N | 1-255 (lib/App C) | one OSC message (address, type tags, args) |

### 4.3 RDM family (0x03xx)

| TID | Name | § | Ops | Scope | P | Poll | Node | Len | Value |
|---|---|---|---|---|---|---|---|---|---|
| 0x0301 | TID_RDM_COMMAND | 11.3.1 | C (Manager) | R*(FTC only)+D | N | – | RDM | 26-257 | E1.20 request frame (§3.3) |
| 0x0302 | TID_RDM_RESPONSE | 11.3.2 | Node reply/notify | R*+D | N | – | RDM | 26-257 | E1.20 response frame |
| 0x0303 | TID_RDM_TOD_CONTROL | 11.3.3 | C | D | N | – | RDM | 1 | 0x00 send ToD; 0x01 flush + full discovery |
| 0x0304 | TID_RDM_TOD_DATA | 11.3.4 | Node reply | D | N | – | RDM | 2+6n (spec ≤1200, lib ≤1352) | `[0]` index 1..total, `[1]` total, `[2..]` UIDs |
| 0x0305 | TID_RDM_EP_CONFIG | 11.3.5 | G S | D | **Y** | C | RDM | 0/1 | bit0 background discovery, bit1 background queue polling; bits 2-7 reserved (lib rejects >0x03) |
| 0x0306 | TID_RDM_FLOW_CONTROL | 11.3.6 | G | D | N | C | RDM | 0/2 | `[0]` total FIFO, `[1]` available ≤ total |

### 4.4 Offboarding (0x04xx)

| TID | Name | § | Ops | Scope | P | Poll | Node | Len | Value |
|---|---|---|---|---|---|---|---|---|---|
| 0x0401 | TID_RT_OFFBOARD | 11.4.1 | C | R | N | – | N | 4 | magic `0x57495045` "WIPE"; anything else ignored |

### 4.5 Network (0x05xx) — root only, all optional (§11.5 L3171)

| TID | Name | § | Ops | P | Poll | Len | Value |
|---|---|---|---|---|---|---|---|
| 0x0501 | TID_NW_MAC_ADDRESS | 11.5.1 | G | Y(spec; read-only) | F | 0/6 | MAC |
| 0x0502 | TID_NW_IPV4_MODE | 11.5.2 | G S | Y | F | 0/1 | 0 static, 1 DHCP |
| 0x0503 | TID_NW_IPV4_ADDRESS | 11.5.3 | G S | Y | F | 0/4 | configured static IPv4 |
| 0x0504 | TID_NW_IPV4_NETMASK | 11.5.4 | G S | Y | F | 0/4 | static mask |
| 0x0505 | TID_NW_IPV4_GATEWAY | 11.5.5 | G S | Y | F | 0/4 | static gateway |
| 0x0506 | TID_NW_IPV4_CURRENT | 11.5.6 | G | N | F | 0/12 | `[0-3]` active IP, `[4-7]` mask, `[8-11]` gateway |
| 0x0581 | TID_NW_IPV6_MODE | 11.5.7 | G S | Y | F | 0/1 | 0 static, 1 SLAAC, 2 DHCPv6 |
| 0x0582 | TID_NW_IPV6_ADDRESS | 11.5.8 | G S | Y | F | 0/16 | static IPv6 |
| 0x0583 | TID_NW_IPV6_PREFIX | 11.5.9 | G S | Y | F | 0/1 | prefix length 0-128 |
| 0x0584 | TID_NW_IPV6_GATEWAY | 11.5.10 | G S | Y | F | 0/16 | static gateway |
| 0x0585 | TID_NW_IPV6_CURRENT | 11.5.11 | G | N | F | 0/33 | `[0-15]` active addr, `[16]` prefix, `[17-32]` gateway |

All Node mandates: N. SET rules: §2.8.

### 4.6 Root (0x06xx) — EP 0 only

| TID | Name | § | Ops | P | Poll | Node | Len | Value |
|---|---|---|---|---|---|---|---|---|
| 0x0601 | TID_RT_SUPPORTED_TIDS | 11.6.1 | G | N | F | Y | 0/2n (spec 2-1200; lib ≤1356) | u16 array of every supported TID incl. proprietary |
| 0x0602 | TID_RT_ENDPOINT_COUNT | 11.6.2 | G | N | **H** | Y | 0/2 | u16 number of data EPs (excl. EP 0) |
| 0x0603 | TID_RT_PROTOCOL_VERSION | 11.6.3 | G | N | F | Y | 0/1 | u8 major version (1 ⇒ `/v1/`) |
| 0x0604 | TID_RT_FIRMWARE_VERSION | 11.6.4 | G | N | F | Y | 0/4-68 | `[0-3]` u32 version (E1.20 SOFTWARE_VERSION_ID convention), `[4..]` ASCII ≤64 |
| 0x0605 | TID_RT_DEVICE_LABEL | 11.6.5 | G S | **Y** | C | Y | 0/1-65 | `[0]` encoding 0x00, `[1..64]` text (LEN 1 = empty label) |
| 0x0606 | TID_RT_MULT_OVERRIDE | 11.6.6 | G S | **Y** | **H** | Y | 0/1 | read: 0 all default folding, 1 ≥1 EP custom. SET: only 0x00 (reset all) |
| 0x0607 | TID_RT_IDENTIFY | 11.6.7 | G S | N (RAM, off at boot) | C | Y | 0/1 | 0 off, 1 subtle, 2 full, 3 mute all indicators/backlights, 4 un-mute |
| 0x0608 | TID_RT_STATUS | 11.6.8 | G | N | C | Y | 0/4 | u32 bits: 0 hw fault, 1 booted factory defaults, 2 config locked via local UI, 3 Open Mode, 4-31 reserved |
| 0x0609 | TID_RT_ROLE_CAPABILITY | 11.6.9 | G | N | F | Y | 0/4 | u32 bits: 0 Node, 1 Sender, 2 Manager, 3 Visualiser, 6 Root_Firmware_Support, 7 Open Mode supported; others reserved |
| 0x060A | TID_RT_REBOOT | 11.6.10 | C | N | – | N | 5 | `[0]` 0xFF hw reset / 0xFE warm; `[1-4]` "BOOT" `424F4F54` |
| 0x060B | TID_RT_MODEL_NAME | 11.6.11 | G | N | F | Y | 0/1-65 | `[0]` encoding 0x00, `[1..64]` text |
| 0x060C | — | — | unassigned gap | | | | | |
| 0x060D | TID_RT_OTW_CAPABILITY | 11.6.12 | G | N | F | OTW | 0/3 | `[0-1]` u16 OTW listener port, `[2]` bits: 0 DTLS1.2, 1 DTLS1.3, 2 TLS1.2, 3 TLS1.3, 4 PIN onboarding (Method B) |

### 4.7 Data endpoint (0x09xx) — EP 1..N only

| TID | Name | § | Ops | P | Poll | Node | Len | Value |
|---|---|---|---|---|---|---|---|---|
| 0x0901 | TID_EP_UNIVERSE | 11.7.1 | G S | Y | C | D | 0/2 | u16 1..63999, 0 = not patched (lib accepts 0..63999) |
| 0x0902 | TID_EP_LABEL | 11.7.2 | G S | Y | C | D | 0/1-65 | `[0]` encoding 0x00, `[1..64]` text |
| 0x0903 | TID_EP_MULT_OVERRIDE | 11.7.3 | G S | Y | C | MO | 0/4 | IPv4 multicast group; 0.0.0.0 = clear. Lib accepts 0.0.0.0 or 224.0.0.0/4 except 239.254.255.0/24 |
| 0x0904 | TID_EP_CAPABILITY | 11.7.4 | G | N | C | D | 0/4 | u32 bits: 0 consume LEVEL, 1 supply LEVEL, 2 consume RDM, 3 supply RDM, 4 virtual EP, 5 per-slot priority merge (else universe priority), 6-31 reserved |
| 0x0905 | TID_EP_DIRECTION | 11.7.5 | G S | Y | C | D | 0/1 | bits0-1: 0 disabled, 1 consumer (Sig-Net→DMX), 2 supplier (DMX→Sig-Net), 3 fallback; bit2 RDM enable; bits3-7 reserved (lib rejects reserved bits and RDM-enable on non-RDM EPs) |
| 0x0906 | TID_EP_INPUT_PRIORITY | 11.7.6 | G S | Y | C | N | 0/1-512 | priority 0-200 per slot; LEN 1 = all slots; unaddressed slots = 0 |
| 0x0907 | TID_EP_STATUS | 11.7.7 | G | N | C | D | 0/4 | u32 bits: 0 active tx/rx, 1 hw fault, 2 UI-locked, 3 receiving LEVEL, 4 >1 LEVEL stream, 5 in fallback, 6 in failover |
| 0x0908 | TID_EP_FAILOVER | 11.7.8 | G S | Y | C | N | 0/3 | `[0]` 0 hold, 1 blackout, 2 full, 3 play scene, 4 stop DMX; `[1-2]` u16 scene 1-65535 (send even if unused) |
| 0x0909 | TID_EP_DMX_TIMING | 11.7.9 | G S | Y | C | N | 0/2 | `[0]` 0 continuous, 1 delta/change-only; `[1]` 0 max, 1 medium, 2 min timing/refresh |
| 0x090A | TID_EP_REFRESH_CAPABILITY | 11.7.10 | G | N | C | N | 0/1 | u8 max fps: 0-44 ⇒ 44 Hz, 45-250 ⇒ that rate, 251-255 reserved |
| 0x090B | TID_EP_PROTOCOL | 11.7.11 | G S | Y | C | N (Manager Y) | 0/1 | 0 Sig-Net, 1 Art-Net 4, 2 sACN (confirm before non-0) |
| 0x090C | TID_EP_IDENTIFY | 11.7.12 | G S | N (RAM) | C | N | 0/1 | 0 off, 1 subtle, 2 full (suppressed while RT mute active) |

### 4.8 Diagnostics (0xFFxx)

| TID | Name | § | Ops | Scope | P | Poll | Node | Len | Value |
|---|---|---|---|---|---|---|---|---|---|
| 0xFF01 | TID_DG_SECURITY_EVENT | 11.8.1 | G; unsolicited | R | N | E | Y | 0/7/11/23 (lib emits 11 or 23 only) | `[0-1]` code, `[2-5]` u32 counter since boot, `[6]` addr type 0 none/1 IPv4/2 IPv6, `[7..]` last offending IP (0/4/16 B). GET returns one TLV per code with counter>0 |
| 0xFF02 | TID_DG_MESSAGE | 11.8.2 | G; unsolicited | R (11.9 & lib: R+D) | N | E | N | 0-64 | ASCII text, no NUL |
| 0xFF03 | TID_DG_LEVEL_FOLDBACK | 11.8.3 | G only | D | N | – | D | 0/1-512 | current DMX buffer of the EP; empty buffer reported as LEN 1 value 0 |

Security event codes: 0x0001 HMAC failure, 0x0002 replay (seq/session anomaly), 0x0003 DoS rate-limit
active, 0x0004 unauthorised onboarding attempt, 0x0005 sender table saturated (33rd sender, LRU <1 h old),
0x0006 epoch regression (lower Session ID from known TUID), 0x0007 sequence contiguity violation, 0x0008
failed offboard (lockout expired). Counters are RAM-only and continue counting while transmission is
rate-limited (≤1 packet/s/code), so the delta between two reports is the true attack rate (§10.9 L2797).
The IP is spoofable; show it as a hint.

### 4.9 Editor rules derived from the table

- Show a TID's editor only if it is in the device's RT_SUPPORTED_TIDS and its scope matches the selected EP.
- Read with GET (or rely on poll CONFIG/FULL); write only TIDs marked S; offer C TIDs as buttons with
  confirmation (OFFBOARD, REBOOT, TOD flush).
- Validate lengths before sending: any out-of-range value
  in a packet silently kills every other SET in that packet.
- Prefer one TLV per SET packet from an interactive editor, so a refusal is attributable.
- Proprietary TIDs (0x8000-0xFF00): only meaningful with the right Mfg-Code option; show raw hex.

---

## 5. Data-plane traffic a Manager / test tool may watch

| Traffic | Where | What to show | Ref |
|---|---|---|---|
| TID_UNIVERSE Join/Leave | `/node/{tuid}/0` on `<mult_node_send>` | per-Sender table of active universes, group IP (0.0.0.0 ⇒ default folding), sender EP. Re-sent every `<universe_announce_interval>` = 5 s, several TLVs per packet. Expire if not refreshed for ~3 intervals (suggestion) | §11.2.6 L2980 |
| Levels | `/level/{u}` on the folded group (`manager-wire.md`) | slots; per-source via 8-byte Sender-ID; PRIORITY first in packet; no PRIORITY ⇒ 100 | §10.6 L2626 |
| Rate | Sender default ≤44 fps, 3 repeats at idle start, then ≥1 Hz keep-alive (full universe) | warn if a Sender exceeds a patched Node's EP_REFRESH_CAPABILITY | §10.6.3 L2686 |
| Stream loss | no LEVEL for `<universe_lost_timeout>` = 3 s | mark stale | §10.6.4 L2711 |
| Sync | `/sync` on `<mult_time>`, LEN 0, sent ≥5 ms after last LEVEL of a frame | show sync rate per Sender-ID; Node falls back to async after `<sync_lost_timeout>` = 250 ms without SYNC | §10.7 L2719 |
| Timecode | `/timecode/{1..255}` on `<mult_time>` | hh:mm:ss:ff@rate; 1 Hz keep-alive when paused; lost after `<timecode_lost_timeout>` = 1 s; use Seq-Num to drop reordered frames | §10.8 L2761 |
| Preview | `/preview/{u}` on `<mult_preview>` | same layout as LEVEL | §11.2.3 L2919 |
| Security events | `/node/{tuid}/0` | §4.8 | §10.9 |
| DG messages | `/node/{tuid}/0` | text log per device | §11.8.2 |
| Foldback | GET 0xFF03 on a data EP | what the EP is actually outputting (merge result) | §11.8.3 |

---

## 6. Timing constants (App B §16 L4331)

| Name | Value | Unit | Who uses it | lib |
|---|---|---|---|---|
| `<poll_time>` | 3 | s | Manager poll interval; Node lost-presence interval | — |
| `<manager_poll_jitter>` | 500 | ms | Manager collision avoidance; startup listen = 3×(3 s+0.5 s) | — |
| `<poll_backoff_max>` | 1000 | ms | Node random delay for range/broadcast poll replies and on-boot | — |
| `<node_processing_max>` | 500 | ms | Node reply deadline; Manager retransmit threshold | — |
| `<node_lost_timeout>` | 3 | poll cycles | Manager: device lost; Node: enter Lost Mode | — |
| `<endpoint_spacing_delay>` | 1 | ms | gap between per-EP replies for EP 0xFFFF | — |
| `<status_publish_rate>` | 1 | s | min gap between status notifications per EP | — |
| `<rdm_backoff_max>` | 250 | ms | Node random delay before proactive RDM response | **absent** (lib uses 1000) |
| `<ip_rollback_timer>` | 60 | s | Node waits for targeted unicast poll after IP change | — |
| `<offboard_lockout>` | 300 | s | OFFBOARD accepted only this long after physical power-on | — |
| `<first_packet_bootstrap_window>` | 2000 | ms | after link-up Node rejects SETs/commands on `/manager` | **absent** |
| `<beacon_min_interval>` | 5 | s | min gap between offboarded beacons | — |
| `<beacon_timeout>` | 30 | s | Manager removes stale beacon entries / spoof window | — |
| `<on_demand_beacon_interval>` | 500 | ms | gap in Manager's 3-beacon burst | — |
| `<universe_announce_interval>` | 5 | s | Sender TID_UNIVERSE refresh | — |
| `<universe_lost_timeout>` | 3 | s | Node stream loss → failover | — |
| `<sync_lost_timeout>` | 250 | ms | Node leaves SYNC_ACTIVE | — |
| sync settle (no App B name) | 5 | ms | Sender gap between last LEVEL and SYNC (§10.7.1) | — |
| `<timecode_lost_timeout>` | 1 | s | timecode stream lost | — |
| `<key_rotation_overlap>` | 30 | s | Node keeps old key after SNOW rotation | — |
| `<mult_ttl>` | 32 | hops | all multicast | — |
| `<coap_port>` | 5683 | UDP | everything | — |
| Sender max rate / keep-alive | 44 fps / 1 Hz, 3 idle repeats | | §10.6.3 | — |
| Replay LRU guard | 3600 | s | Node sender table eviction | — |
| Payload limits | 1400 B CoAP msg, 1200 B TLV payload | | §10.2.4 | — |

---

## 7. Discrepancies and ambiguities found

Spec vs lib **[Δ]**:
1. TOD_DATA 0x0304: spec not queryable (§11.3.4 L3101, §11.9); lib registry/flags mark it queryable. Use TOD_CONTROL 0x00.
2. Lengths: SUPPORTED_TIDS spec 2-1200, lib 0-1356; TOD_DATA spec ≤1200, lib ≤1352; DG_SECURITY_EVENT spec
   allows 7, lib shape requires 11-23. Parse leniently (7/11/23).
3. EP_CAPABILITY bit 5 (per-slot priority, added in V1.08): lib treats it as reserved.
4. RDM proactive/multicast backoff: lib 0..1000 ms vs spec `<rdm_backoff_max>` 250 ms.
5. `<first_packet_bootstrap_window>` not implemented in lib.
6. DISCOVERY_COMMAND (CC 0x10) rejection not implemented in lib's tunnel path.
7. DG_MESSAGE scope: §11.8.2 Root; §11.9 and lib Root & Data.

Inside the spec:
1. TID_PRIORITY unaddressed slots: 0 (§10.6 L2639) vs 100 (§11.2.2 L2913).
2. §11 "Mandated" note says a Node silently ignores an unsupported SET on a fixed parameter while still
   reporting state (L2826); §10.4.2/§10.1.3 say the whole transaction is rejected. Lib rejects the packet.
   Either way the Manager sees no confirmation.
3. §7.7 says Session-ID resets to zero and in the next sentence that it persists unchanged (L1388-1391).
4. App A lists `/preview/{stream}`; §11.2.3 uses `/preview/{universe}`.
5. §11.5.3 NW_IPV4_ADDRESS shows reply URI `/node/{tuid}/{endpoint}` (others `/0`).
6. §11.3.4 lists Manager→`/manager` as a TOD_DATA sender; nothing defines Node handling of that.
7. App C JSON says POLL_REPLY target "Root"; §11.1.2 says Root & Data (lib: both, data EPs send bare
   POLL_REPLY).
8. TOD_CONTROL 0x01 (flush + discovery): spec does not say whether the Node sends TOD_DATA when the new
   discovery finishes; poll with 0x00 afterwards.
9. Port ID byte for tunnelled RDM requests is not specified; Manager source UID is not mandated (§6.7 covers
   responders only).
10. DHCP-mode IP change: spec requires a unicast poll to the "new IP" but gives no way to learn it.
