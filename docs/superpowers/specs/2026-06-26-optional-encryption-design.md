# Optional Encryption for `wfb_tx` / `wfb_rx` — Design

**Date:** 2026-06-26
**Status:** Implemented (branch `optional-encryption`)
**Target:** Local fork (based on svpcom/wfb-ng)

## 1. Goal & motivation

Make on-air encryption **optional per stream** so the high-bitrate **video** stream
can run unencrypted to **save CPU**, while **mavlink** and **tunnel** streams keep
full encryption.

The dominant crypto cost at video bitrates is the per-fragment AEAD
(`crypto_aead_chacha20poly1305`) applied to *every* data packet. The ~1 Hz session
handshake (`crypto_box`) is negligible. Dropping encryption for the video stream
reclaims that per-packet CPU on weak drone/GS SoCs.

## 2. Non-goals

- Not removing encryption globally. Encryption stays the **default** and stays
  **mandatory** for mavlink/tunnel (and any stream that keeps a key).
- Not an upstream submission. This is a local fork, so wire-format conservatism is
  relaxed — but the change is kept minimal and reversible.
- Not adding a faster-but-still-confidential cipher. The choice is binary:
  AEAD-encrypted vs plaintext.
- Not preserving interop with unmodified/old binaries. Both ends of a link are
  upgraded together (same package).
- A CLI "UNENCRYPTED" status indicator is a nice-to-have, out of core scope (§9).

## 3. Background: the two crypto layers today

Two packet types travel on air, distinguished by the first byte
(`wifibroadcast.hpp:188-190`):

| Type | Value | Crypto | Cost | Cadence |
| --- | --- | --- | --- | --- |
| `WFB_PACKET_SESSION` | `0x2` | `crypto_box` (Curve25519, asymmetric; tx-secret + rx-public) | expensive | ~1 Hz |
| `WFB_PACKET_DATA` | `0x1` | `crypto_aead_chacha20poly1305` (symmetric, keyed by `session_key`) | cheap-ish but **per packet** | every fragment |

- The **session packet** (`wsession_data_t`, `wifibroadcast.hpp:230-238`; built in
  `tx.cpp:rebuild_session_packet` `:119`) carries `epoch`, `channel_id`,
  `fec_type`, `k`, `n`, and a fresh random `session_key`. The RX opens it with
  `crypto_box_open_easy` (`rx.cpp:720`) and learns both the symmetric key and the
  FEC parameters needed to build its decoder.
- Each **data packet** payload is a single FEC fragment, AEAD-encrypted with the
  `session_key` and the `wblock_hdr_t` (`packet_type` + `data_nonce`) as additional
  authenticated data (`tx.cpp:663` / `tx.cpp:709`; decrypt `rx.cpp:870`).

Two structural facts that make this feasible:

1. **FEC runs on plaintext fragments.** Encryption is the outermost per-fragment
   step on TX and the first step on RX. RS and swfec both operate on already-plain
   fragments, so a plaintext mode is a localized swap of the encrypt/decrypt step —
   FEC/swfec/forwarder/cluster code is untouched.
2. **`wblock_hdr_t.data_nonce` is more than a crypto nonce.** It carries
   `(block_idx << 8) + fragment_idx` (RS) or the monotonic swfec sequence, which the
   RX needs for FEC ring placement and reordering. Plaintext mode keeps this header
   byte-for-byte; only the payload encryption is dropped.

Keys are loaded in the constructors (`tx.cpp:71`, `rx.cpp:291`); a missing key file
currently throws and exits. The default keypair is `"tx.key"` / `"rx.key"`
(`tx.cpp:1830`, `rx.cpp:1346`).

## 4. Design

### 4.1 CLI semantics — `-K` presence is the switch

| `-K` given? | Mode | Behavior |
| --- | --- | --- |
| yes (`-K gs.key`) | Encrypted | Exactly as today: load keys, `crypto_box` session + per-packet AEAD |
| no | Plaintext | No key files touched; plaintext session + plaintext data; loud startup `WARNING` |

- Change the default `keypair` in both `main()`s from `"tx.key"`/`"rx.key"` to `""`
  (`tx.cpp:1830`, `rx.cpp:1346`).
- Mode is a single derived bool, `encrypted = !keypair.empty()`, stored as a member
  of `Transmitter` and `Aggregator`. No constructor *signatures* change — they
  already take `keypair`.
- When plaintext, both binaries print at startup:
  `WARNING: no -K given — running UNENCRYPTED on radio_port <N>`.
- `-u` is already used (udp_port/client_port), which is the other reason to key off
  `-K` absence rather than add a new flag.

### 4.2 Wire format — distinct, self-describing plaintext types

```
existing:  WFB_PACKET_DATA          0x1   wblock_hdr  + AEAD(fragment) + 16B tag
           WFB_PACKET_SESSION       0x2   wsession_hdr + crypto_box(wsession_data)
new:       WFB_PACKET_DATA_PLAIN    0x3   wblock_hdr  + raw fragment        (no tag)
           WFB_PACKET_SESSION_PLAIN 0x4   wsession_hdr + raw wsession_data  (key field unused)
```

- The **plaintext session** reuses the *same* `wsession_data_t` struct (so RX
  param-extraction is identical); it is simply not `crypto_box`-wrapped, and the
  `session_key` field is zeroed/unused. It still carries `epoch/channel_id/fec_type/k/n`.
- The **plaintext data** packet is `wblock_hdr_t` (type `0x3` + `data_nonce`)
  followed by the raw FEC fragment — no cipher, no tag.

Distinct types (vs reusing `0x1/0x2` and inferring from mode) make the per-process
gate crisp and visible: a wrong-mode packet is rejected by *type*, counted in
`count_p_bad`, rather than silently parsed as a struct or failing AEAD. Cost: two
`#define`s.

### 4.3 TX changes (`tx.cpp`)

Each site branches `if (encrypted) { …today… } else { …plaintext… }`:

- **Constructor (`:51`/`:71`):** wrap key loading in `if (!keypair.empty())`. In
  plaintext, leave key buffers unused and set `encrypted = false`.
- **`rebuild_session_packet` (`:119`):** plaintext fills the same `wsession_data_t`,
  then `memcpy`s it after the header with type `WFB_PACKET_SESSION_PLAIN` instead of
  `crypto_box_easy`. Size omits `crypto_box_MACBYTES`. Keep the random per-rebuild
  nonce (RX dedup still works); leave `session_key` zeroed.
- **`send_block_fragment` (`:651`)** and **`send_swfec_wire` (`:697`):** plaintext
  sets type `WFB_PACKET_DATA_PLAIN` and `memcpy`s the raw fragment after
  `wblock_hdr_t` — no AEAD, no tag. Inject length = `sizeof(wblock_hdr_t) + packet_size`.

### 4.4 RX changes (`rx.cpp`)

- **Constructor (`:279`/`:291`):** wrap key loading in `if (!keypair.empty())`; set
  `encrypted = false` in plaintext.
- **`process_packet` `switch(buf[0])` (`:680`):** add two cases, each mode-guarded so
  a wrong-mode packet falls to `count_p_bad`:
  - `WFB_PACKET_DATA_PLAIN`: validate the plaintext minimum length, then in the
    post-switch tail **`memcpy` the raw fragment into the existing `decrypted[]`
    buffer** in place of the AEAD call (`:870`). Everything downstream
    (`count_p_data++`, swfec push / RS ring) is byte-identical.
  - `WFB_PACKET_SESSION_PLAIN`: same `generichash` dedup; parse the plaintext
    `wsession_data_t`; (re)build the RS/swfec decoder; emit the same IPC `SESSION` line.

**Critical subtlety — plaintext "new session?" detection.** In plaintext, `session_key`
is all-zero on both ends, so the existing gate `memcmp(session_key, new->session_key)`
(`rx.cpp:769,809`) would **never fire** → the RX would never build its decoder. The
plaintext session path must detect change on **`(fec_type, k, n, epoch)`** instead,
with "first session ever" = `fec_p == NULL && swfec_dec == NULL` (initial state is
`fec_k=-1, fec_n=-1, session_is_swfec=false, swfec_dec=NULL`, `rx.cpp:282-288`).

To avoid duplicating the RS/swfec setup, **extract a `setup_session(fec_type, k, n,
epoch)` helper** holding today's decoder-build bodies (the contents of the two
`if (memcmp(session_key, …))` blocks). Call it from both the encrypted branch (on
key change) and the plaintext branch (on param change). This keeps the swfec
param-only deadline-update path (`rx.cpp:834-846`) intact for both modes.

### 4.5 Size accounting — no macro changes

`MAX_PAYLOAD_SIZE` / `MAX_FEC_PAYLOAD` (`wifibroadcast.hpp:262-263`) stay as-is. They
are upper bounds; a plaintext packet is `<=` that (it drops the 16-byte tag, never
adds). The `decrypted[MAX_FEC_PAYLOAD]` buffers are already sized for the encrypted
max, so they hold plaintext comfortably. Only the **RX minimum-length checks** gain
plaintext variants: the `+ crypto_aead_chacha20poly1305_ABYTES` term drops for `0x3`,
and `crypto_box_MACBYTES` drops for `0x4`.

### 4.6 Python / config layer

**`services.py` — make `-K` conditional via one helper.** All 5 service initializers
(`init_udp_direct_tx`, `init_udp_direct_rx`, `init_mavlink`, `init_tunnel`,
`init_udp_proxy`) hardcode `-K %(key)s` at 8 sites. Add a module-level helper:

```python
def key_arg(cfg):
    return ('-K %s' % os.path.join(settings.path.conf_dir, cfg.keypair)) if cfg.keypair else ''
```

Replace each `-K %(key)s` → `%(key_arg)s` and each `key=os.path.join(...)` →
`key_arg=key_arg(cfg)`. Each command string is `.split()` before exec, so an empty
fragment vanishes — no dangling spaces, no other special-casing. `cfg.keypair`
already resolves to `None` cleanly (`ast.literal_eval`), and nothing else in the tree
reads `keypair`.

**`master.cfg` — secure-by-default, explicit opt-in.** Do not change the shipped
defaults (keys stay on for everything). Document the switch with a commented line in
the shared `[video]` profile (`master.cfg:245`):

```ini
[video]
# keypair = None   # UNENCRYPTED video — saves CPU. Leave commented to keep encryption.
                   # mavlink/tunnel keep their keys; only this stream goes plaintext.
```

Profiles merge left-to-right with later-wins (`services.py:65-68`), and the video
streams use `['base', 'drone_base'/'gs_base', 'video', …]` — so `[video] keypair =
None` overrides the inherited `drone.key`/`gs.key` and flips **both** drone-TX and
gs-RX video to plaintext in one place. mavlink/tunnel are untouched.

## 5. Security analysis

**Threat model.** An attacker can receive on the RF channel and transmit on it, and
knows or guesses `channel_id` (`link_id << 8 | radio_port`).

**Core invariant (enforced in code, not just config):**

> A `wfb_rx` started **with** `-K` processes **only** encrypted types (`0x1/0x2`) and
> drops plaintext types into `count_p_bad`. A `wfb_rx` started **without** `-K`
> processes **only** plaintext types (`0x3/0x4`) and drops encrypted types. Mode is a
> per-process property of key presence — it cannot be flipped by any on-air packet.

**For the plaintext video stream** (operator-accepted): confidentiality is lost
(anyone can watch); integrity/authenticity is lost (anyone on the channel can inject
or forge video fragments, or forge a session with bogus `k/n` or a higher `epoch`).
Worst case is **video denial-of-service or spoofing**. 802.11 FCS still drops
in-flight-corrupted frames and the FEC/in-order reorder structure rejects much
garbage, but a deliberate attacker can disrupt the plaintext video — this is inherent
to "no encryption" and limited to the video stream.

**For mavlink/tunnel (unchanged):** confidentiality and integrity are preserved
(AEAD + `crypto_box`). They run on different `channel_id`s (video `radio_port` `0x00`,
mavlink `0x10/0x90`, tunnel `0x20/0xa0`), and their RX processes are launched **with**
`-K`. By the core invariant, an attacker's plaintext injection on a mavlink/tunnel
`channel_id` is dropped without processing. **Enabling plaintext video cannot weaken
mavlink/tunnel.**

What dropping the session encryption for video specifically costs (vs a keep-the-
handshake variant): authenticated FEC-param delivery and the membership gate for the
video stream — i.e. the DoS/spoofing surface above. The keep-the-handshake variant
would preserve those but still require a key file for video, which is explicitly not
wanted. The trade is accepted for the zero-key simplicity.

## 6. Error handling

- **Never silent:** the startup `WARNING` (§4.1) makes plaintext mode loud.
- **Mode mismatch = no link, diagnosable like a key mismatch:** symptom is the
  familiar non-zero `bad` / zero `data` in stats.
- **Safety in code:** per-case mode guards in `process_packet` enforce the core
  invariant; an attacker's plaintext inject on an encrypted channel is dropped.
- **`-K` given but file missing:** unchanged — throws and exits.

## 7. Testing

- **Plaintext round-trip (new):** TX→RX with no `-K`, for both RS and swfec, asserting
  payload integrity over the UDP-loopback path (`UdpTransmitter` /
  `AggregatorUDPv4`).
- **Safety test (new):** TX plaintext → RX encrypted ⇒ zero `data`, non-zero `bad`
  (and the reverse).
- **Regression:** the encrypted path must stay byte-identical — run `make test` at the
  known baseline (2 pre-existing `test_proxy` errors + 1 `tuntap` skip are
  environmental) and the swfec reference vectors.
- **Manual smoke:** `wfb-server` with `[video] keypair = None` on both ends ⇒ video
  flows at lower CPU; mavlink/tunnel still encrypted; a plaintext inject on the
  mavlink channel is dropped.

## 8. Files changed (summary)

| File | Change |
| --- | --- |
| `src/wifibroadcast.hpp` | `#define WFB_PACKET_DATA_PLAIN 0x3`, `WFB_PACKET_SESSION_PLAIN 0x4` |
| `src/tx.hpp` / `src/tx.cpp` | `encrypted` member; key-load guard; plaintext branches in `rebuild_session_packet`, `send_block_fragment`, `send_swfec_wire`; default keypair `""` + warning in `main()` |
| `src/rx.hpp` / `src/rx.cpp` | `encrypted` member; key-load guard; `setup_session()` helper; two new `switch` cases with mode guards + plaintext "new session" detection; plaintext min-length checks; default keypair `""` + warning in `main()` |
| `wfb_ng/services.py` | `key_arg(cfg)` helper; replace 8 `-K %(key)s` sites |
| `wfb_ng/conf/master.cfg` | commented `# keypair = None` opt-in in `[video]` |
| tests | plaintext round-trip + safety tests |

## 9. Open / optional items

- **CLI "UNENCRYPTED" indicator** (out of core scope): tag the session as plaintext at
  the server from `cfg.keypair is None` and surface it in `wfb-cli`; no wire/contract
  change required.
- **Footgun hardening alternative** (decided against): require an explicit `-K none`
  sentinel rather than bare `-K` absence. Rejected in favor of the requested
  "missing `-K` = plaintext" semantics + the loud startup warning.
