# Sig-Net Manager: wire format and security

Scope: what a Swift/CryptoKit Manager has to put on the wire and what it has to check on receive. TID semantics are covered elsewhere.
Sources: spec = *Sig-Net Protocol Framework V1.10* (§ numbers).
Tags: **[V]** = verified by running code or vectors (see §9). **[C]** = read from the reference C library's code. **[S]** = read from spec only.

---

## 1. Keys (§7.2.3, §7.3, §7.3.1)

| Item | Definition | Ref |
|---|---|---|
| K0 from passphrase | `PBKDF2-HMAC-SHA256(pass, salt="Sig-Net-K0-Salt-v1" (18 B ASCII), iter=100000, dkLen=32)` | §7.2.3 **[V]** |
| Passphrase policy | 10–64 chars; ≥3 of {A-Z, a-z, 0-9, symbols `!@#$%^&*()-_=+[]{}\|;:',.<>?/`}; no run of 3 identical; no run of 4 ascending or descending. The C library's K0 derivation rejects passwords that fail this | §7.2.3 [C] |
| HKDF | **HKDF-Expand only** (no Extract). PRK = K0. L = 32, so `key = HMAC-SHA256(K0, info ‖ 0x01)` | §7.3; OpenSSL adapter uses `EXPAND_ONLY` **[V]** |
| Ks (Sender) | info = `"Sig-Net-Sender-v1"` (17 B) | **[V]** |
| Kc (Citizen) | info = `"Sig-Net-Citizen-v1"` (18 B) | **[V]** |
| Km_global | info = `"Sig-Net-Manager-v1"` (18 B) | **[V]** |
| Km_local(T) | info = `"Sig-Net-Manager-v1-"` + the **target Node's** TUID as 12 **uppercase** hex chars (31 B in total) | **[V]** |

CryptoKit: `HKDF<SHA256>.expand(pseudoRandomKey: K0, info:, outputByteCount: 32)` or `HMAC<SHA256>.authenticationCode(for: info + [0x01], using: SymmetricKey(data: K0))`. Both give the same bytes.

### Which key a Manager uses

| Traffic | Direction | URI kind | Key | Ref |
|---|---|---|---|---|
| Discovery poll (global, or targeted by TUID range, including unicast) | TX | `/poll` | **Km_global** | §10.3.1 |
| GET / SET / RDM command to Node T | TX | `/manager/{T}/{ep}` | **Km_local(T)**. Derive and cache one key per target TUID | §10.3.1, §10.3.2 |
| Manager's own on-boot notification and poll replies (it acts as a citizen too) | TX | `/node/{ownTUID}/0` | Kc | §10.3.1 note; §10.2.5 |
| Node replies, push notifications, poll replies, security events | RX verify | `/node/{T}/{ep}` | **Kc** | §8.6.1 |
| Node lost-mode presence | RX verify | `/node_lost/{T}/0` | **Kc** | §8.6.1 |
| Other Managers' polls (poll snooping) | RX verify | `/poll` | **Km_global** | §8.6.1, §10.2.2 |
| Offboarded beacon | RX, **no HMAC** | `/node_beacon/{T}/0` | none (mode 0xFF) | §8.6 step 1b |
| Aux triggers (only if the Manager sends them) | TX | `/aux/{T}/{ep}` | Ks | §10.3.3 |

Receive side: pick the key from the parsed URI resource segment, never from the source address.

---

## 2. CoAP framing (§8.1, §8.4, §9.4)

### Header (4 bytes, no token)

| Byte | Bits | Value Manager sends | Notes / ref |
|---|---|---|---|
| 0 | Ver(2) T(2) TKL(4) | `0x50` = Ver 1, T = 1 (NON), TKL = 0 | the encoder refuses TKL≠0 [C] |
| 1 | Code | `0x02` (POST) | §9.4 |
| 2-3 | Message ID (BE) | per multicast group: random 16-bit seed, then +1 per packet | [C] |

- Message ID and Token are **not** in the HMAC (§8.5 note).
- Receive: TKL 1–8 is skipped and TKL > 8 is rejected. Ver must be 1, Code 0x02, T NON. These checks are skipped for beacons, which return earlier.
- Message ID only matters in **Open Mode**. Receivers drop an open packet whose (MsgID, group-key) pair was already seen from the same Sender-ID, with a history of 16. MsgID 0 bypasses this check. In Open Mode, use non-zero, non-repeating IDs. **[V]**

### Options (strictly ascending, RFC 7252 delta encoding)

| # | Name | Len | Content | Ref |
|---|---|---|---|---|
| 11 | Uri-Path | var | one option per segment, raw ASCII, no `/` | §8.2 |
| 15 | Uri-Query | var | **never sent** by the code. Accepted on RX and included in the HMAC URI if present | — |
| 2076 | Sig-Net-Security-Mode | 1 | `0x00` HMAC, `0x01` Open, `0xFF` Beacon | §8.3 |
| 2108 | Sig-Net-Sender-ID | 8 | TUID(6) ‖ endpoint(2, BE). **Manager uses endpoint 0** (administrative lane) | §8.3, §8.6.2 |
| 2140 | Sig-Net-Mfg-Code | 2 | BE. `0x0000` unless the payload has a proprietary TID (≥0x8000 and not in the dictionary); then your ESTA ID | §8.3 |
| 2172 | Sig-Net-Session-ID | 4 | BE u32 | §8.3 |
| 2204 | Sig-Net-Seq-Num | 4 | BE u32 | §8.3 |
| 2236 | Sig-Net-Auth | 32 or 0 | HMAC (mode 0x00). **Present with length 0** in modes 0x01 and 0xFF | §8.3 |
| — | `0xFF` + payload | | omitted when the payload is empty | §8.4 |

**Option header bytes.** Write `(deltaNibble<<4)|lenNibble`, then the extensions: 13 → one byte (v−13), 14 → two bytes BE (v−269). With Uri-Path last, the bytes are fixed whatever the URI:

| Option | Delta | Header bytes | Value |
|---|---|---|---|
| first Uri-Path | 11 | `B<len>` (len < 13). Later Uri-Path segments: `0<len>` | segment |
| 2076 | 2065 | `E1 07 04` | mode (1 B) |
| 2108 | 32 | `D8 13` | 8 B |
| 2140 | 32 | `D2 13` | 2 B |
| 2172 | 32 | `D4 13` | 4 B |
| 2204 | 32 | `D4 13` | 4 B |
| 2236 | 32 | `DD 13 13` (len 32) / `D0 13` (len 0) | 32 / 0 B |

A segment of 13 or more bytes (for example a long scope) needs `xD <len-13>`. **[V]** (`D`/`E` nibbles were checked against the code by round-trip, §9.)

**Decoder strictness on RX** (be as strict, and expect peers to be): all six security options present exactly once with exact lengths; any option after 2236 makes the packet malformed; an unknown **odd** (critical) option is malformed and an unknown even option is ignored; a payload marker followed by 0 bytes is malformed; datagrams over 1400 B are dropped. A mode other than 0x00, 0x01 or 0xFF is dropped silently.

### TLV payload (§10)

`TID (u16 BE) ‖ Length (u16 BE) ‖ Value[Length]`, concatenated with no padding. Length 0 on a queryable TID = GET (§10.4.3). Limits: CoAP message ≤ **1400 B**, payload after 0xFF ≤ **1200 B** (§10.2.4; TX truncates its buffer to 1400).

---

## 3. URIs (§8.2, §10.3, App. A)

Canonical form: `/sig-net/v1/{scope}/…`. `{scope}` is 1–32 chars from `[A-Za-z0-9-._~]`, factory default `local` (§8.2). `{tuid}` is 12 **uppercase** hex chars; the RX parser rejects lowercase. Numbers are decimal with no leading zeros; the parser rejects `05`.

| URI (Uri-Path segments) | Manager role | Sent / joined at | Key |
|---|---|---|---|
| `sig-net`,`v1`,scope,`poll` | TX (and snoop RX) | multicast 239.254.255.252. A targeted poll after an IP change goes unicast to the Node IP (§10.4.4) | Km_global |
| `sig-net`,`v1`,scope,`manager`,TUID,ep | TX | unicast to the Node IP:5683 (preferred, §10.3.2) **or** 239.254.255.251 | Km_local(TUID) |
| `sig-net`,`v1`,scope,`node`,TUID,ep | RX (TX for its own announce) | 239.254.255.253. Nodes **always** reply by multicast, even to unicast commands | Kc |
| `sig-net`,`v1`,scope,`node_lost`,TUID,`0` | RX | 239.254.255.254 | Kc |
| `sig-net`,`v1`,scope,`node_beacon`,TUID,`0` | RX | 239.254.255.255 | none |

Parser grammar: `poll` takes no parameters; `manager`, `node` and `aux` take TUID + ep (0–65535); `node_lost` and `node_beacon` take TUID + `0`. For `manager` and `aux`, a Node drops the packet if the TUID is not its own. The scope must equal the receiver's scope, compared byte for byte. The library hard-codes scope `local` for beacons.

---

## 4. HMAC (§8.5)

`Auth = HMAC-SHA256(key, M)`, the full 32 bytes with **no truncation**. M is the concatenation of:

1. **URI string** in ASCII: `"/" + seg1 + "/" + seg2 …` over the Uri-Path options in wire order. If Uri-Query options exist, append `"?" + q1 + "&" + q2 …`. No scheme or host, no trailing slash, no NUL.
2. **19-byte meta**:

   | Off | Len | Field |
   |---|---|---|
   | 0 | 1 | Security-Mode |
   | 1 | 6 | Sender TUID |
   | 7 | 2 | Sender endpoint (BE) |
   | 9 | 2 | Mfg-Code (BE) |
   | 11 | 4 | Session-ID (BE) |
   | 15 | 4 | Seq-Num (BE) |
3. **Payload** bytes (TLVs), excluding the 0xFF marker. Empty if there is no payload.

The HMAC excludes the CoAP header (Ver/T/TKL, Code, MsgID), the token, the option header bytes, and the Auth option. Nothing is zeroed, because the Auth option is simply left out of M. Step list for TX: build the segments, then the URI string, then meta from the exact values you will encode, then MAC = HMAC(key, uri‖meta‖payload), then encode the packet with Auth = MAC. RX recomputes M from the decoded options and compares in constant time; use `HMAC<SHA256>.isValidAuthenticationCode`.

---

## 5. Session ID and sequence: Manager TX rules (§8.3, §8.6)

| Rule | Detail | Ref |
|---|---|---|
| Persist Session-ID | **Required.** At startup, *before the first authenticated packet*: load the stored value, add 1, write it to non-volatile storage, and only then send. Random values are forbidden | §8.3 |
| Initial value | The first boot after onboarding has stored = 0, so the first session used is **1** | [C] |
| Exhaustion | Spec: at 0xFFFFFFFF, stop authenticated TX until offboard/rekey. Code refuses to boot if stored ≥ 0xFFFFFFFE, so the largest session used is 0xFFFFFFFE | §8.3 |
| Seq per lane | One counter per Sender-ID (TUID+ep), starting at **1** after every session bump and +1 per packet. The Manager normally has one lane (ep 0), shared by polls and commands | §8.6.2 |
| Seq wrap | When the next seq would be 0xFFFFFFFF: session += 1 and persist it, reset **all** lanes to 1, send with seq 1. 0xFFFFFFFF is never sent | §8.3 |
| Retransmit | Every retry gets a new seq and a new HMAC. Re-sending identical bytes is dropped as a replay | §8.5, §9.4 **[V]** |
| Ordering | Nodes drop seq ≤ last-seen on a lane. A unicast and a multicast packet from the same lane that arrive out of order will lose the older one. Serialize sends per lane | §8.6 step 8b |
| Open Mode | Session = 0 and Seq = 0 always (non-zero values are dropped as malformed). No persistence | §8.3 |

**How Nodes judge Manager freshness** (§8.6 steps 7-10, RAM only):

- *Session tier, keyed by TUID:* if `session < max(stored sessions for this TUID across all lanes)`, drop as replay_session.
- *Seq tier, keyed by the 8-byte Sender-ID:* if `session == lane.session && seq ≤ lane.seq`, drop as replay_seq. A higher session accepts any seq.
- *Bootstrap (§8.6.3):* an unknown TUID is accepted unconditionally once the HMAC passes, and that packet becomes the baseline.
- State is committed only after the HMAC verifies. The table holds ≥32 records with LRU eviction, and a record is only evicted if it has been idle for more than 3600 s, otherwise the packet is dropped with security event 0x0005.

So, at Manager start: bump and persist the session. Nodes that were not rebooted will reject an old or replayed session forever. Nodes forget everything when they power-cycle. A Manager that reinstalls with a fresh store (session 1) is rejected by any Node that still holds a higher session for that TUID until the Node reboots. Persist the session alongside the TUID, or generate a new TUID when the store is lost.

**§8.6.4 post-reboot window (added in V1.08):** for 2000 ms after link-up, Nodes reject SET and high-privilege commands on `/manager`, while polls are accepted. **The C library does not implement it**; the Swift Node in this repo does. Expect it from other vendors' Nodes: poll first and SET later.

**§8.6.1 Manager RX processing:** apply the full §8.6 pipeline (mode → ver → code → URI/scope → freshness → HMAC → commit) to `/node`, `/node_lost` and snooped `/poll`. Freshness is per 8-byte Sender-ID and session per TUID, using the same algorithm as above. Size the table for every Device in scope; the 32 minimum applies to Nodes only. On HMAC or freshness failure for `/node` or `/node_lost`: drop, log an anomaly, and alert the operator naming the TUID. Discard your own polls, which come back through multicast loopback (the library sets `IP_MULTICAST_LOOP=1`), by matching the Sender TUID. Offer a manual "forget TUID" action for Nodes that were rekeyed (§8.3 recovery note).

---

## 6. Transport (§9, App. A, App. B)

| Item | Value | Ref |
|---|---|---|
| UDP port | **5683** for every destination, unicast and multicast | §9.3 |
| TTL | **32** (`IP_MULTICAST_TTL`) | §9.6 |
| Max datagram | 1400 B CoAP message, 1200 B payload | §10.2.4 |
| Base | `239.254.0.0`. Fixed groups are `239.254.255.x`. Level groups are `239.254.0.((u-1)%109+1)` | App. A |
| node_beacon | 239.254.255.**255** | — |
| node_lost | .**254** | — |
| node_send | .**253** | — |
| manager_poll | .**252** | — |
| manager_send | .**251** | — |
| time (sync and timecode) | .**250** | — |
| preview | .**249** | — |
| aux | .**248** | — |
| Level folding pool | 109 (`<mult_u1>`..`<mult_u109>` = 239.254.0.1–.109) | §9.2.3 |
| Manager subscribes | 253, 254, 255 (§9.2.2) **plus 252** for poll snooping (§10.2.2) | |
| Nodes subscribe | 252, 251 | §9.2.2 |
| Bind | Manager must **bind UDP 5683** on INADDR_ANY (multicast datagrams arrive on port 5683), with SO_REUSEADDR + SO_REUSEPORT so it can coexist with a local Node, Sender or other CoAP stack. The library Node binds 5683; the library Sender binds an ephemeral port because it only sends. The source port of your sends is irrelevant because replies go to multicast :5683 | — |
| Interface | set `IP_MULTICAST_IF` and join on the chosen NIC | — |
| Timing | poll every 3 s + jitter 0–500 ms; Node lost after 3 missed polls; Node reply backoff 0–1000 ms; command timeout 500 ms | App. B |

---

## 7. Open Mode (§7.2.4, §8.3, §8.6 step 1)

| Field | Secure (0x00) | Open (0x01) |
|---|---|---|
| Option 2076 | `00` | `01` |
| 2108 / 2140 | same | same |
| 2172 / 2204 | session / seq | `00000000` / `00000000` (must be zero) |
| 2236 | 32 B HMAC | **present, length 0** (`D0 13`) |
| Keys | needed | none (KDF skipped) |
| Replay protection | session/seq lanes | none, apart from the code's MsgID duplicate cache (§2) |

Downgrade rule: a Node in Secure Mode drops every 0x01 packet, and an Open-Mode Node drops every 0x00 packet **[V]**. To find Open-Mode Nodes, a secure Manager may *interleave* open polls (`/poll` with mode 0x01) (§10.2.2). Replies from Open-Mode Nodes then arrive with mode 0x01; accept them only as unauthenticated and label them as such in the UI.

---

## 8. Spec vs code differences

| Topic | Spec | Code (what the library does) |
|---|---|---|
| Auth option in Open/Beacon | §8.3 says five options are always present and option 6 is "mode dependent" | The Auth option is **always emitted** (len 0), and the decoder **requires** it. Always send it |
| Session limit | cease at 0xFFFFFFFF | refuses at stored ≥ 0xFFFFFFFE |
| §8.6.4 2000 ms config lockout | normative since V1.08 | not implemented |
| Open-Mode duplicate filter | not in spec | MsgID + group, 16-entry history, per Sender-ID |
| Beacon scope | `/sig-net/v1/<scope>/node_beacon/…` | always `local` |
| Preview URI | `/preview/{stream}` (App. A) | `/preview/{universe}`. Not Manager-relevant |
| Freshness session baseline | "stored Session ID for this TUID" | max over all lanes of the TUID. Equivalent |

---

## 9. Worked packets (byte-exact) **[V]**

**Verification done:**

1. The Annex G (§21) KAT reproduces exactly in Python stdlib: K0 = `06577c60…48d3e3`, Ks = `23ffd543…a6c242`, Kc = `eac261f8…a26f81`, Km_global = `c00b7fef…043457`, Km_local(123456789ABC) = `8f41d6df…bb4889`, and the level HMAC tag = `c7126005fb474564dc7ce4c122e3e60d4b13dedeb8c6ad1e8daa51e5c66a8225`. The library's own vector `"Ge2p$E$4*A"` gives K0 = `52fcc2e7749f4035…`.
2. The packets below were built by an independent Python encoder. They were then fed into the library's **own** decoder and receive pipeline, configured as Node `123456789ABC`, scope `local`. Results: Poll and GET give **accepted**; replaying the identical bytes gives `replay_seq`; the Open GET gives accepted on an Open Node, `coap_duplicate` on a repeat, and `mode_mismatch` on a Secure Node.

Inputs: K0 = Annex G K0. Manager TUID `AABBCC000001`, ep 0, mfg 0, **session 5**. Scope `local`.

### 9a. Global heartbeat poll (Km_global, seq 1, MsgID 0x1234), 121 B

Payload: TID_POLL `0001 0019` + mgrTUID `AABBCC000001` + soem `00000000` + lo `000000000000` + hi `FFFFFFFFFFFF` + ep `FFFF` + query `00`.

```
HMAC input (uri ‖ meta ‖ payload):
2f7369672d6e65742f76312f6c6f63616c2f706f6c6c                     "/sig-net/v1/local/poll"
00 aabbcc000001 0000 0000 00000005 00000001                       meta(19)
00010019aabbcc00000100000000000000000000ffffffffffffffff00        payload(29)
tag = 32c0c4315922c1da83848d378536905bbc4e30bb48d785665317da21e3876b76

Wire:
50 02 1234                                   hdr: Ver1 NON TKL0, POST, MID
b7 7369672d6e6574  02 7631  05 6c6f63616c  04 706f6c6c       Uri-Path x4
e1 0704 00                                   2076 mode=00
d8 13 aabbcc000001 0000                      2108 sender-id
d2 13 0000                                   2140 mfg
d4 13 00000005                               2172 session
d4 13 00000001                               2204 seq
dd 13 13 32c0c431…e3876b76                   2236 auth(32)
ff 00010019aabbcc000001…ff00                 payload
```
Full hex: `50021234b77369672d6e6574027631056c6f63616c04706f6c6ce1070400d813aabbcc0000010000d2130000d41300000005d41300000001dd131332c0c4315922c1da83848d378536905bbc4e30bb48d785665317da21e3876b76ff00010019aabbcc00000100000000000000000000ffffffffffffffff00`

### 9b. GET TID_RT_DEVICE_LABEL to Node 123456789ABC ep 0 (Km_local, seq 2, MsgID 0x1235), 114 B

Key = Km_local(123456789ABC) = `8f41d6df9a5ac9d8f8c7c0580a0c5fb90026154dd2dca6469cc3929ec5bb4889`. Payload `0605 0000`.
- HMAC input (`"/sig-net/v1/local/manager/123456789ABC/0"` ‖ meta `00 aabbcc000001 0000 0000 00000005 00000002` ‖ `06050000`): `2f7369672d6e65742f76312f6c6f63616c2f6d616e616765722f3132333435363738394142432f3000aabbcc00000100000000000000050000000206050000`
- tag = `7ff14675a05e808270295af4b5f2baed1d06a1feae6e93272ec7e1b48e24436f`
- Wire: `50021235b77369672d6e6574027631056c6f63616c076d616e616765720c3132333435363738394142430130e1070400d813aabbcc0000010000d2130000d41300000005d41300000002dd13137ff14675a05e808270295af4b5f2baed1d06a1feae6e93272ec7e1b48e24436fff06050000`

### 9c. Same GET in Open Mode (MsgID 0x1236), 81 B

`50021236b77369672d6e6574027631056c6f63616c076d616e616765720c3132333435363738394142430130e1070401d813aabbcc0000010000d2130000d41300000000d41300000000d013ff06050000`

### Reference generator (Python 3 stdlib; use as a Swift test oracle)

```python
import hashlib, hmac, struct
K0 = hashlib.pbkdf2_hmac("sha256", b"SigNetT3stVector1!", b"Sig-Net-K0-Salt-v1", 100000, 32)
kdf = lambda info: hmac.new(K0, info + b"\x01", hashlib.sha256).digest()
Kmg = kdf(b"Sig-Net-Manager-v1"); Kml = lambda t: kdf(b"Sig-Net-Manager-v1-" + t.upper().encode())
def opt(n, prev, v):
    nib = lambda x: x if x < 13 else (13 if x < 269 else 14)
    ext = lambda k, x: b"" if k < 13 else (bytes([x-13]) if k == 13 else struct.pack(">H", x-269))
    d, l = n-prev, len(v); return bytes([nib(d) << 4 | nib(l)]) + ext(nib(d), d) + ext(nib(l), l) + v
def packet(key, segs, mode, tuid, ep, sess, seq, payload, mid, mfg=0):
    meta = bytes([mode]) + tuid + struct.pack(">HHII", ep, mfg, sess, seq)
    uri = b"".join(b"/" + s for s in segs)
    auth = hmac.new(key, uri + meta + payload, hashlib.sha256).digest() if mode == 0 else b""
    out, prev = bytearray([0x50, 0x02]) + struct.pack(">H", mid), 0
    for s in segs: out += opt(11, prev, s); prev = 11
    for n, v in [(2076, bytes([mode])), (2108, tuid + struct.pack(">H", ep)), (2140, struct.pack(">H", mfg)),
                 (2172, struct.pack(">I", sess)), (2204, struct.pack(">I", seq)), (2236, auth)]:
        out += opt(n, prev, v); prev = n
    return bytes(out) + (b"\xff" + payload if payload else b"")
```
