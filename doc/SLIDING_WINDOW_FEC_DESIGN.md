# Sliding-Window FEC Design for wfb-ng

**Status:** draft for review — Phase 1 (design only, no code)
**Applies to:** `wfb_tx`, `wfb_rx`, `wfb_rx --agg` (aggregator)
**Authors:** design proposal
**Date:** 2026-04-22 (revision 2, post external-review triage)

---

## Changes in this revision

Triage of external review findings is at
`doc/SLIDING_WINDOW_FEC_DESIGN_REVIEW.md`. All changes below trace back to
an accepted issue in that review.

**API corrections**
- §2.2 diagram: replaced `rx_ring_push(block_idx)` (no such signature)
  with `get_block_ring_idx(block_idx)` at [src/rx.cpp:457](../src/rx.cpp#L457)
  (M1).
- §6: replaced hand-wavy `fec_encode_simd(code, inpkts[k], fecs[m-k], size)`
  with the real prototype from
  [src/zfex.h:55-59](../src/zfex.h#L55-L59); noted stale Doxygen
  `block_nums`/`num_block_nums` reference does not match the function's
  signature (M2).
- §9: widened codec init to take `fec_params_t` carrying
  `(fec_type, k, n, swin_w, swin_r_num, swin_r_den)` instead of the
  `(int k, int n)` pair at [src/tx.hpp:79](../src/tx.hpp#L79) /
  [src/rx.hpp:221](../src/rx.hpp#L221) (H3).
- §10.1: renamed codec selector from `-C` (collides with `control_port`
  at [src/tx.cpp:1805-1807](../src/tx.cpp#L1805-L1807)) to long options
  `--codec`, `--swin-w`, `--swin-r` (H1).

**CPU/memory estimate corrections**
- §6, §8.2, §8.4: `fec_encode_simd` computes all `(n-k)` parity rows per
  call ([src/zfex.c:811-827](../src/zfex.c#L811-L827)), not one. Original
  per-repair cost understated by `(n-k) = ⌈R·W⌉`× (up to 64×). Revised
  numbers include both the bulk-API fallback cost and the cost with a
  proposed narrow `fec_encode_row_simd` zfex extension committed to
  Phase 2a (H2, H4).

**Added integration points**
- §5.5 / §9: reference the existing `Aggregator::get_tag` helper at
  [src/rx.cpp:549](../src/rx.cpp#L549) and `tags_item_t` / tag-writer
  loop at [src/tx.hpp:38-41](../src/tx.hpp#L38-L41) /
  [src/tx.cpp:173-182](../src/tx.cpp#L173-L182). Design adds two TLV IDs
  only, not TLV infrastructure (M3).
- §9: enumerated RX session-parse ordering — `get_tag` must read
  `TLV_SWIN_WINDOW` / `TLV_SWIN_REPAIR_RATIO` before decoder init at
  [src/rx.cpp:696](../src/rx.cpp#L696).
- §10.3: listed [src/rx.cpp:698](../src/rx.cpp#L698) `IPC_MSG`,
  [wfb_ng/cli.py](../wfb_ng/cli.py), and
  [wfb_ng/log_parser.py](../wfb_ng/log_parser.py) as update sites —
  hardcoded `WFB_FEC_VDM_RS` in the SESSION log line must become
  session-dependent, and W/R fields must be added (M5).
- §9, §10.3: widened `PacketLossListener::on_packet_loss` at
  [src/rx.hpp:42](../src/rx.hpp#L42) from `uint32_t` to `uint64_t` to
  carry 56-bit SWIN `seq_num`; called out as an ABI break (M4).
- §4, §9: explicit requirement that window/repair ring buffers use
  `posix_memalign(ZFEX_SIMD_ALIGNMENT, ZFEX_ROUND_UP_SIMD(P))` to
  satisfy zfex's alignment check at
  [src/zfex.c:794-809](../src/zfex.c#L794-L809) (M7).

**Clarified error handling / semantics**
- §5.2: split "56 bits, max 2^55 − 1" into field-width vs. value-bound
  statements (L5).
- §5.3, §7.3: one rule for `repair_idx` — counts from 0 per window,
  independent across windows; removed conflicting wording (M8, M9).
- §5.5: `fec_k`, `fec_n` in the fixed session header are set to 0
  (reserved) under SWIN — no "advisory hints" fiction. `W` and `R` live
  in TLVs only (L7).
- §10.2: row 4 reframed as `fec_type != configured_codec` reject at
  [src/rx.cpp:659-664](../src/rx.cpp#L659-L664), not "impl not loaded"
  (M6).
- §10.3: `count_p_override`
  ([src/rx.hpp:210](../src/rx.hpp#L210)) documented as stays-at-zero
  under SWIN; `count_w_flush` is its SWIN-analogue (L6).

**Wording corrections**
- §1: fixed "rx_ring of 40 in-flight blocks" citation to point at both
  [src/rx.hpp:87](../src/rx.hpp#L87) (constant) and
  [src/rx.hpp:238](../src/rx.hpp#L238) (array) (L2); reworded "non-front
  side" in failure mode 2 (L3).
- §2.1: corrected field line range to
  [src/tx.hpp:95-97](../src/tx.hpp#L95-L97) (L1).

**Scope notes**
- §5.5: existing host-byte-order `tlv_hdr_t.len` at
  [src/tx.cpp:180](../src/tx.cpp#L180) /
  [src/rx.cpp:558-562](../src/rx.cpp#L558-L562) is a pre-existing
  portability hazard unrelated to SWIN — scoped out, not fixed here (L4).

---

## 1. Context and motivation

wfb-ng currently uses a block-based Reed-Solomon (RS) FEC: the transmitter
groups `K` source packets into a block, generates `N - K` parity packets with
`fec_encode_simd`, and emits all `N` on-air before opening the next block.
The receiver holds an `rx_ring` of 40 in-flight blocks — see
`RX_RING_SIZE` constant at
[src/rx.hpp:87](../src/rx.hpp#L87) and the array declaration
`rx_ring_item_t rx_ring[RX_RING_SIZE]` at
[src/rx.hpp:238](../src/rx.hpp#L238) — and decodes each one only after at
least `K` of its `N` fragments have arrived
([src/rx.cpp:795-826](../src/rx.cpp#L795-L826),
[src/rx.cpp:895](../src/rx.cpp#L895)).

Block FEC already includes a fast path: on the front block of the ring,
fragments that arrive in-order with no gap behind them are released to the
socket immediately ([src/rx.cpp:771-791](../src/rx.cpp#L771-L791)). On a
clean, in-order link there is no block-boundary latency — packets stream
out as they arrive. The latency problem is not on the happy path; it is
what happens the moment anything goes wrong.

Three failure modes follow directly from the block-and-ring design:

1. **Front-block gap stalls the ring tail.** The front-block fast path only
   emits fragments while `fragment_map[fragment_to_send_idx]` is non-zero
   ([src/rx.cpp:778](../src/rx.cpp#L778)). A single missing fragment at
   position `g` stops the loop at `g`; every later fragment in the same
   block *and every fragment of every later block already in the ring* is
   held. Release resumes only when the gap is filled by a late-arriving
   fragment, or when `fec_k` fragments of the front block arrive (possibly
   from across multiple blocks in the ring) and FEC reconstructs the
   missing one ([src/rx.cpp:795-856](../src/rx.cpp#L795-L856)).
2. **Non-front blocks are always held.** A fully-received in-order block
   behind a stalled front block cannot release any fragments until it
   becomes the front, no matter how long the front is stuck. The
   `send_packet` call at [src/rx.cpp:780](../src/rx.cpp#L780) is gated on
   `ring_idx == rx_ring_front`. The `has_fragments == fec_k` branch at
   [src/rx.cpp:795](../src/rx.cpp#L795) does run for both front and
   non-front blocks, but on the front block it only fires when the
   no-gap fast path at [src/rx.cpp:771-791](../src/rx.cpp#L771-L791)
   could not drain `K` fragments in-order — i.e. exactly when a gap is
   present.
3. **Block-boundary burst is structurally unrecoverable.** A loss burst
   that straddles two blocks — leaving each with fewer than `fec_k` good
   fragments — cannot be decoded on either block, because RS decode
   requires `fec_k` of `fec_n` *within the same block*. The same burst
   lying entirely inside one sliding window of width `W ≥ burst_len` is
   recoverable as long as `⌈R · W⌉ ≥ burst_len`.

On a noisy link these failure modes produce the "Override block …"
eviction events visible in logs when the ring fills up, and the
multi-block latency spikes that eventually make the operator ask for a
sliding-window codec.

A **sliding-window FEC** eliminates all three. There is no block boundary
and no ring-front concept; every arriving source packet is immediately
eligible for delivery regardless of what came before it. A gap at sequence
`N` stalls only `N` itself (until recovered by a later repair or the flush
deadline expires) — not `N + 1`, not later-arriving earlier windows, not
anything else. Parity is computed over a rolling window and emitted at a
scheduled repair ratio, so a burst that would have straddled a block
boundary under the old scheme falls inside a single recoverable window
instead.

This document specifies the design of a sliding-window RS FEC variant
(`WFB_FEC_SWIN_RS`) that coexists with the existing block FEC
(`WFB_FEC_VDM_RS`). Both are selectable per-session via the existing
`fec_type` field in the session packet
([src/wifibroadcast.hpp:192-193](../src/wifibroadcast.hpp#L192-L193),
[src/wifibroadcast.hpp:222-230](../src/wifibroadcast.hpp#L222-L230)). No
wire-format byte layouts are changed; the 9-byte `wblock_hdr_t`
([src/wifibroadcast.hpp:241-244](../src/wifibroadcast.hpp#L241-L244)) is
reused with a reinterpreted `data_nonce` field.

The goal of Phase 1 is a design the reviewer signs off before any code
changes. No implementation, no benchmark, no migration plan beyond the
shape of the selector. Implementation is a separate Phase 2 task.

---

## 2. Current block-FEC data flow (reference)

### 2.1 TX path

```
UDP / Unix ingress  ─▶  Transmitter::send_packet()        src/tx.cpp:651
                          │
                          ├─ copy payload into block[fragment_idx]
                          ├─ send_block_fragment()         src/tx.cpp:622
                          │    ├─ wblock_hdr_t with nonce  src/tx.cpp:631
                          │    ├─ chacha20poly1305 encrypt src/tx.cpp:634
                          │    └─ inject_packet()          src/tx.cpp:642
                          └─ if fragment_idx == fec_k:
                                fec_encode_simd()          src/tx.cpp:686
                                for i in [K, N): send_block_fragment()
                                block_idx += 1
```

Block boundary is deterministic by source-packet count. Partially-filled
blocks are closed by `fec_timeout`-driven padding packets emitted with flag
`WFB_PACKET_FEC_ONLY` ([src/tx.cpp:986-992](../src/tx.cpp#L986-L992)).
`fec_delay` inserts a sleep between parity packets to spread them in time
([src/tx.cpp:694-705](../src/tx.cpp#L694-L705)).

`fec_p`, `fec_k`, `fec_n` are held as private members of `Transmitter`
([src/tx.hpp:95-97](../src/tx.hpp#L95-L97)); there is no virtual encoder
abstraction.

### 2.2 RX path

```
pcap frame ─▶ Receiver::loop_iter()          src/rx.cpp:112
                │
                └─ Aggregator::process_packet()        src/rx.cpp:570
                     │
                     ├─ WFB_PACKET_SESSION ─▶ init_fec(k, n)  src/rx.cpp:696
                     └─ WFB_PACKET_DATA:
                          │
                          ├─ decrypt, parse nonce        src/rx.cpp:735-753
                          ├─ get_block_ring_idx(block_idx)  src/rx.cpp:457
                          │     (calls rx_ring_push() at :421 internally)
                          ├─ store fragment              src/rx.cpp:768
                          └─ try release / decode:
                                ├─ front-block, no-gap:  immediate emit
                                ├─ non-front block with K frags: apply_fec()
                                │                                src/rx.cpp:895
                                │                                  └─ fec_decode_simd()
                                │                                     src/rx.cpp:935
                                └─ send_packet() (in-order strictly)  src/rx.cpp:859
```

Key invariants that the sliding-window design is *not* required to preserve:

- In-order delivery is forced by block boundary: `packet_seq = block_idx *
  fec_k + fragment_idx` ([src/rx.cpp:865](../src/rx.cpp#L865)). Sliding
  window will use a native per-packet `seq_num` instead.
- Ring of 40 blocks with LRU eviction — replaced by a window of `W_rx`
  packet-granularity slots with a wall-clock flush deadline.

### 2.3 Session packet + `fec_type` dispatch (matters for coexistence)

Session packets carry `fec_type, k, n` inside the encrypted
`wsession_data_t` ([src/wifibroadcast.hpp:222-230](../src/wifibroadcast.hpp#L222-L230)).
RX rejects any `fec_type != WFB_FEC_VDM_RS` today with an error log and
`count_p_dec_err++` — no exception, no disconnect
([src/rx.cpp:659-664](../src/rx.cpp#L659-L664)):

```c
if (new_session_data->fec_type != WFB_FEC_VDM_RS) {
    WFB_ERR("Unsupported FEC codec type: %d\n", new_session_data->fec_type);
    count_p_dec_err += 1;
    return;
}
```

This is **fail-closed** for backward compatibility: an old RX faced with a
new-type TX discards session packets, never updates its session key, and
therefore also drops the new-type data packets (AEAD fails, wrong key).
Safe.

---

## 3. Requirements and non-goals

### Requirements

- **R1** Wire-compat: reuse the unchanged 9-byte `wblock_hdr_t`. No new
  packet-type values, no new primary headers, no MTU change
  (`MAX_FEC_PAYLOAD = 3996` at
  [src/wifibroadcast.hpp:254-255](../src/wifibroadcast.hpp#L254-L255)).
- **R2** AEAD nonce uniqueness: the 8-byte `data_nonce` passed to
  `crypto_aead_chacha20poly1305_encrypt`
  ([src/tx.cpp:637](../src/tx.cpp#L637)) must remain globally unique per
  session key.
- **R3** Coexistence selected at session init by `fec_type`; both codecs
  compiled in, both selectable by config, no mutual interference.
- **R4** No change to any crypto primitive or key-exchange protocol.
- **R5** No regression on the current block-FEC path beyond the insertion
  of a thin virtual dispatch.
- **R6** Must fit the RPi Zero 2W CPU budget at 1080p30 / ~3 Mbps video
  with realistic W and R (see §8).
- **R7** A TX running the new codec speaking to an old RX must fail
  closed — never produce corrupted output.

### Non-goals for Phase 1

- MCS or PHY-rate adaptation.
- RX→TX feedback channel for reactive repair.
- Any GF(2^16) codec path (required only for `W > 128 ∧ R > 1`, out of
  reasonable operating range).
- Rekey-scheme changes. Session key lifetime stays
  `2^55 - 1` ([src/wifibroadcast.hpp:186](../src/wifibroadcast.hpp#L186),
  [src/tx.cpp:715-721](../src/tx.cpp#L715-L721)).
- Adaptive W / R under loss estimation. W and R are session-scoped
  constants negotiated at session start.
- True per-packet incremental encode with running parity accumulators.
  Every repair re-encodes its W-source window from scratch. §8 shows this
  is affordable on all targets.
- Benchmark harness spec, wire-compat matrix, Python/Twisted orchestrator
  changes — deferred to Phase 2.

---

## 4. Proposed sliding-window data flow

### 4.1 TX path

```
UDP / Unix ingress
      │
      ▼
Transmitter::send_packet(payload)
      │
      ├─ encoder.on_source_packet(seq, payload)   ← IFecEncoder interface
      │     │
      │     ├─ append to window ring (length W)
      │     └─ set repair_due_in -= 1
      │
      ├─ inject source immediately                ← no batching
      │     wblock_hdr_t { type=DATA,
      │                    nonce=(is_repair=0 | repair_idx=0 | seq) }
      │
      └─ while encoder.next_repair(&buf, &nonce):
            inject repair
              wblock_hdr_t { type=DATA,
                             nonce=(is_repair=1 | repair_idx=i | seq_repair) }
```

Each source packet is emitted the moment it arrives. The encoder maintains
a ring of the last `W` source payloads (padded to the running max size in
the window — see §12.1 on padding amplification). Every slot in the
encoder's source ring and the decoder's window-and-repair rings MUST be
allocated via `posix_memalign(ZFEX_SIMD_ALIGNMENT, ZFEX_ROUND_UP_SIMD(P))`
— zfex checks alignment at
[src/zfex.c:794-809](../src/zfex.c#L794-L809) and returns
`ZFEX_SC_BAD_INPUT_BLOCK_ALIGNMENT` / `ZFEX_SC_BAD_OUTPUT_BLOCK_ALIGNMENT`
on mismatch, which will trip the existing `assert(rc == ZFEX_SC_OK)`
pattern at [src/tx.cpp:687](../src/tx.cpp#L687) /
[src/rx.cpp](../src/rx.cpp) apply_fec. Today's block FEC meets this via
`posix_memalign` at [src/tx.cpp:135](../src/tx.cpp#L135); the SWIN
implementation must do the same for every window and repair slot. When `repair_due_in`
reaches zero, the encoder produces one repair packet by calling
`fec_encode_simd` over the current window and emits it, then resets the
counter to `⌈1 / R⌉`. For `R < 1` this naturally spreads repairs across
`1/R` source packets; for `R ≥ 1` the loop emits multiple repairs per
source (uncommon; only for mavlink/tunnel profiles).

Every repair is over the **current sliding window** — i.e. the last `W`
source packets at the moment the repair is emitted. Windows overlap; the
stride between successive repairs is `1/R` source packets. No explicit
"window ID" is needed on the wire: a repair with source-sequence-tail
derived from its own `seq_num` covers `[seq - W + 1, seq]` by convention
(see §5.2).

### 4.2 RX path

```
pcap frame ─▶ Aggregator::process_packet()
      │
      ├─ WFB_PACKET_SESSION: dispatch init to IFecDecoder based on fec_type
      │
      └─ WFB_PACKET_DATA:
           decrypt, parse nonce
           parse: is_repair, repair_idx, seq_num
           │
           ├─ if is_repair == 0:
           │     decoder.on_source_packet(seq_num, payload)
           │     └─ release source to socket IMMEDIATELY
           │          (optionally: reorder within a small jitter buffer)
           │
           └─ if is_repair == 1:
                 decoder.on_repair_packet(seq_num, repair_idx, payload)
                 └─ if ≥ W known inputs in the repair's implicit window:
                       fec_decode_simd() for any missing positions
                       release recovered sources to socket in seq order

Background ticker:
     every T_flush_check ms, retire windows older than T_flush
     └─ any gap still unrecovered is counted as lost and skipped
        (socket output advances past its seq_num)
```

**Crucial property** (and the actual delta over block FEC): a received
source packet is delivered to the socket without waiting for *any* earlier
loss to resolve. Block FEC has the same property only on its fast path —
front block, no prior gap in the block ([src/rx.cpp:771-791](../src/rx.cpp#L771-L791)).
The moment a gap appears, block FEC holds every subsequent packet
(including those in later blocks already received in-order) until the gap
is filled or decoded. Sliding window drops that coupling: the decoder
only ever *accelerates* delivery of packets lost on-air; it never delays
one that was received directly, regardless of what is missing before it.
Reordering within a small jitter window (say 5 ms) is optional and
configurable; strict-in-order (matching current behavior) is the default.

---

## 5. Wire format changes

### 5.1 `fec_type` allocation

```c
// src/wifibroadcast.hpp
#define WFB_FEC_VDM_RS       0x1   // existing: block RS over Vandermonde
#define WFB_FEC_SWIN_RS      0x2   // new:      sliding-window RS
```

The session packet's `fec_type` field is a single `uint8_t`
([src/wifibroadcast.hpp:225](../src/wifibroadcast.hpp#L225)), so values up
to `0xff` are available. The selection is per-session; within a session
`fec_type` cannot change (it's part of the session key announcement).

### 5.2 Redefined `data_nonce` (under `WFB_FEC_SWIN_RS` only)

Today ([src/wifibroadcast.hpp:182](../src/wifibroadcast.hpp#L182),
[src/tx.cpp:631](../src/tx.cpp#L631)):

```
data_nonce (big-endian 64-bit):
    bits 63..8   : block_idx  (56 bits, max 2^55 - 1)
    bits  7..0   : fragment_idx (8 bits, 0..255)
```

Under `WFB_FEC_SWIN_RS`, the same 8 bytes are reinterpreted:

```
data_nonce (big-endian 64-bit):
    bit     63   : is_repair       (1 bit)
    bits 62..56  : repair_idx      (7 bits, 0..127)
    bits 55..0   : seq_num         (56 bits, max 2^55 - 1)
```

- For a **source packet**: `is_repair = 0`, `repair_idx = 0`,
  `seq_num` is a monotonic source sequence number. The `seq_num` field
  is 56 bits wide; its value is bounded to `2^55 − 1` by the session-
  rekey policy (same bound as today at
  [src/wifibroadcast.hpp:186](../src/wifibroadcast.hpp#L186) /
  [src/tx.cpp:715-721](../src/tx.cpp#L715-L721), which reserves the top
  bit for signed-arithmetic safety).
- For a **repair packet**: `is_repair = 1`, `repair_idx` selects the
  Vandermonde parity row used by zfex for this repair (see §5.3 for the
  allocation rule and §6 for the required zfex one-row-encode
  extension). `seq_num` is a monotonic repair sequence number in its
  own namespace, bounded identically to `2^55 − 1`. Session rekey fires
  when either stream's `seq_num` exceeds the bound.

`wblock_hdr_t.packet_type` stays `WFB_PACKET_DATA = 0x1` for both source
and repair: the RX decoder dispatches by `is_repair`, not by packet type.

### 5.3 Window-tail convention and repair semantics

Each repair packet implicitly covers the `W` source packets with
sequence numbers `[tail - W + 1, tail]`, where `tail` is the highest
source sequence number already emitted when the repair was generated. For
the receiver to know `tail`, the repair packet carries it in the
`wpacket_hdr_t` header inside the encrypted payload (see §5.4). `W`
itself is session-scoped and advertised in the session TLV.

`repair_idx` identifies which Vandermonde parity row was used to compute
this repair. The encoder maintains one logical systematic RS code per
window of rate `(W, W + ⌈R · W⌉)`; zfex row `W + repair_idx` is the
coefficient vector.

**Allocation rule (one rule, applies uniformly):** `repair_idx` counts
from 0 within each window (keyed by `window_tail_seq`). The first repair
emitted for a given window gets `repair_idx = 0`; the second gets `1`;
the N-th gets `N - 1`. Two distinct windows allocate `repair_idx`
independently — window A's `repair_idx = 0` and window B's
`repair_idx = 0` are unrelated, because their parity rows are computed
over different source inputs. The decoder therefore keys repair storage
on `(window_tail_seq, repair_idx)`.

For `R ≤ 1`, only `repair_idx = 0` is emitted per window. For `R > 1`,
successive repairs for the same window use `0, 1, …, ⌈R⌉ − 1`. The 7-bit
field bounds the per-window repair count at 128, so `⌈R · W⌉ ≤ 128`
must hold — all §7 defaults satisfy this.

**Encoder API note:** the existing zfex `fec_encode_simd`
([src/zfex.h:55-59](../src/zfex.h#L55-L59),
[src/zfex.c:811-827](../src/zfex.c#L811-L827)) computes *all* `n - k`
parity rows in one call. Using it as-is to emit a single row wastes
`(n - k - 1)` rows of work per repair. Phase 2a commits to a narrow
zfex extension `fec_encode_row_simd(code, inpkts, out, sz, fecnum)`
that produces one row at a time (see §6 and §8.2 for the cost delta).

### 5.4 Inner header under `WFB_FEC_SWIN_RS`

The encrypted inner `wpacket_hdr_t`
([src/wifibroadcast.hpp:248-251](../src/wifibroadcast.hpp#L248-L251))
stays 3 bytes for source packets (unchanged: `flags`, `packet_size`).

For **repair packets** we define a longer encrypted inner header:

```
wpacket_hdr_repair_t (inside AEAD-encrypted payload, repair-only):
    uint8   flags            (= WFB_PACKET_REPAIR_SWIN, new bit below)
    uint16  payload_size     (big-endian, size of the repair's parity payload)
    uint64  window_tail_seq  (big-endian, the `tail` above)
```

Total repair-inner-header size = 11 bytes. This sits entirely inside the
encrypted, AEAD-authenticated region, so it cannot be tampered with
without breaking authentication.

A new flag bit is added:

```c
#define WFB_PACKET_REPAIR_SWIN 0x2   // inner flag: repair, window_tail_seq follows
```

On the source side, inner `flags` keeps bit `0x1` (`WFB_PACKET_FEC_ONLY`)
for compatibility; bit `0x2` is only set on repair packets.

### 5.5 Session TLV for window/ratio negotiation

`wsession_data_t.tags[]` already supports TLV extensions
([src/wifibroadcast.hpp:229-237](../src/wifibroadcast.hpp#L229-L237)).
The on-wire TLV infrastructure already exists in both directions:

- TX writes tags via the `std::vector<tags_item_t> tags` constructor
  argument ([src/tx.hpp:38-41](../src/tx.hpp#L38-L41) defines
  `tags_item_t`, [src/tx.hpp:112](../src/tx.hpp#L112) holds the member)
  and the tag-writer loop in `Transmitter::init_session` at
  [src/tx.cpp:173-182](../src/tx.cpp#L173-L182).
- RX reads tags via the general helper
  `Aggregator::get_tag(buf, size, tag_id, value, value_size)` at
  [src/rx.cpp:549-568](../src/rx.cpp#L549-L568). It is currently marked
  `cppcheck: unusedFunction` — SWIN is its first consumer.

This design only adds two tag IDs; it does **not** add TLV
infrastructure.

```
TLV_SWIN_WINDOW        0x10   value = uint16 (big-endian) W
TLV_SWIN_REPAIR_RATIO  0x11   value = uint8 num, uint8 den  (R = num/den)
```

- When `fec_type == WFB_FEC_SWIN_RS`, both TLVs are REQUIRED. If either
  is absent or malformed, the session is rejected (new
  `count_p_dec_err++` at the SESSION handler) with the same behavior as
  today's "Invalid FEC N/K" path at
  [src/rx.cpp:666-678](../src/rx.cpp#L666-L678).
- `fec_k` and `fec_n` in the fixed session header are **reserved under
  SWIN** and MUST be set to `0`. The advisory-hint interpretation in a
  prior draft was fiction — no consumer actually used it (old RX
  rejects on `fec_type` at
  [src/rx.cpp:659-664](../src/rx.cpp#L659-L664) before reading `k`/`n`;
  new RX reads W/R from TLVs, not from the fixed header).

**Out of scope — pre-existing `tlv_hdr_t.len` portability hazard.** The
existing TX path writes `tlv->len = it->value.size()` in *host* byte
order at [src/tx.cpp:180](../src/tx.cpp#L180), and the existing RX path
reads `p->len` without byteswap at
[src/rx.cpp:558-562](../src/rx.cpp#L558-L562). On all current targets
(arm32v7, arm64v8, amd64) the host is little-endian, so this works
accidentally. SWIN inherits this hazard for the new TLV `len` field;
fixing it would change the session packet wire format for *all* TLV
users and is outside this design. Filed as a separate issue for Phase 2
plumbing. The *value* payloads of both new TLVs are defined in big
(network) byte order as stated above.

### 5.6 Nonce-uniqueness proof

Claim: under the new layout the set of all 64-bit `data_nonce` values
emitted under one session key is uniquely partitioned between source and
repair streams.

Proof sketch:

- `is_repair` is the high bit. Source nonces have high bit `0`; repair
  nonces have high bit `1`. The two half-spaces are disjoint.
- Within the source half-space, the low 63 bits are `(0 << 56) | seq_src`,
  and `seq_src` is monotonic in `[0, 2^55 - 1]` before rekey. Unique.
- Within the repair half-space, the low 63 bits are
  `(repair_idx << 56) | seq_repair`. `seq_repair` is monotonic in
  `[0, 2^55 - 1]` before rekey, and `repair_idx ∈ [0, 127]`. The pair
  is emitted at most once because the emitter only ever advances
  `seq_repair` (not `repair_idx`) per repair.
- Rekey happens strictly before either stream wraps.

Therefore every `data_nonce` is used at most once per session key, which
is the AEAD nonce-uniqueness requirement.

### 5.7 Backward compatibility

- **Old TX + new RX**: old TX emits `fec_type = WFB_FEC_VDM_RS`. New RX
  sees a supported type, initializes a block decoder, and behaves
  identically to the old RX. No change.
- **New TX (sliding) + old RX**: old RX sees `fec_type = WFB_FEC_SWIN_RS
  = 0x2`, rejects the session at
  [src/rx.cpp:659-664](../src/rx.cpp#L659-L664), never loads the session
  key, and drops every data packet on AEAD failure. Silent, safe,
  fail-closed. The operator sees the old RX's `count_p_dec_err` climb.
- **New TX + new RX with different codec selection**: both TX and RX must
  agree on `fec_type` via config (see §10). If they disagree, same
  fail-closed behavior as above.

---

## 6. Coding scheme choice

**Selected: Reed-Solomon over a sliding window, reusing zfex with a
narrow encode-one-row extension.**

zfex provides a systematic MDS RS code over GF(2^8) via Vandermonde
matrix ([src/zfex.h](../src/zfex.h)). The real encode prototype is:

```c
// src/zfex.h:55-59
zfex_status_code_t fec_encode_simd(
    const fec_t* code,
    const gf* ZFEX_RESTRICT const* ZFEX_RESTRICT const inpkts,
    gf* ZFEX_RESTRICT const* ZFEX_RESTRICT const fecs,
    size_t sz);
```

Note that the Doxygen block at
[src/zfex.h:46-53](../src/zfex.h#L46-L53) refers to `block_nums` and
`num_block_nums` parameters — these do **not** exist on this function
and the comment is stale. Sizes come from `code->k` and `code->n`. The
implementation body at
[src/zfex.c:811-827](../src/zfex.c#L811-L827) loops over all
`(code->n - code->k)` parity rows unconditionally and writes each into
`fecs[i]`. Kernels are SIMD-accelerated via NEON (`vqtbl1q_u8`) and
SSSE3 (`_mm_shuffle_epi8`) at
[src/zfex.c:196-265](../src/zfex.c#L196-L265).

`fec_decode_simd` performs a `k × k` Vandermonde-submatrix inversion and
back-substitution to recover missing positions.

Under the sliding-window design, each repair packet corresponds to a
single Vandermonde parity row of a systematic `(W, W + ⌈R · W⌉)` code.
The bulk API as it stands forces the encoder either to call
`fec_encode_simd` once per repair and discard `⌈R · W⌉ − 1` unused rows
(wasteful — see §8.2 for the cost), or to amortize one call across
`⌈R · W⌉` repairs of the *same* window (which clusters repairs in time
and loses the spread-in-time property that makes sliding window work).

**Phase 2a scope commits to adding a narrow zfex extension:**

```c
// Proposed addition in src/zfex.h
zfex_status_code_t fec_encode_row_simd(
    const fec_t* code,
    const gf* ZFEX_RESTRICT const* ZFEX_RESTRICT const inpkts,
    gf* ZFEX_RESTRICT out,
    size_t sz,
    unsigned int fecnum);   // which parity row; must be in [k, n)
```

Body is ~15 lines — a trimmed version of the inner loop at
[src/zfex.c:815-826](../src/zfex.c#L815-L826) with `i` fixed to
`fecnum - code->k`. This brings per-repair encode cost down by a factor
of `(n - k) = ⌈R · W⌉` vs the bulk-discard fallback. §8.2 reports both.

### Rejected alternatives

- **Systematic RaptorQ (RFC 6330).** Near-MDS fountain code with
  arbitrary-repair-count encoding that is incremental-friendly. The right
  tool for adaptive, feedback-driven schemes. Rejected for Phase 1 because
  (a) it introduces a new heavyweight dependency (typical implementations
  are 20–50 kLOC with nontrivial patent / licensing history), (b) on
  small-`W` regimes typical here (W ∈ [16, 128]) its intermediate block
  structure costs 2-5× the CPU of plain RS, and (c) its non-MDS
  probabilistic recovery is harder to reason about than deterministic RS
  in a latency-sensitive video path.
- **Random linear network coding (RLNC).** Repair = random GF(2^8)
  linear combination of the window. Simplest incremental encode,
  probabilistic MDS. Rejected because (a) it requires a per-repair
  coefficient vector on the wire (W bytes for W inputs), which burns 64
  bytes of MTU at W=64 — repair becomes its own amplification problem;
  (b) non-zero decode failure probability for small windows where we'd
  want to use it.

### Why RS fits here

- **Zero new dependency**: zfex already lives in the build and is already
  tuned for ARM / x86.
- **Deterministic recovery**: any `W` of `W + ⌈R · W⌉` received packets
  decode the window, period. No probability tables to reason about.
- **Affordable**: §8 shows < 1% of one A53 core on the binding target.
- **Natural fit**: every window is just a block RS encoding, so the
  codec primitives we need are exactly the ones we already have.

---

## 7. Window sizing and repair scheduling

### 7.1 Window size W

The trade-offs:

- Larger W → better burst-loss coverage; larger W also lets `R` be
  smaller for the same effective redundancy.
- Larger W → higher worst-case recovery latency
  (`≈ W / (R · pps)`) because a repair covering source `s` is only
  guaranteed to arrive `W / R` source-packet times after `s`.
- Larger W → larger `g · W · P / 16` decode cost under `g` gaps, but
  decode cost is small in absolute terms (§8).
- W does *not* cap individual packet size (MTU is unchanged).

### 7.2 Repair ratio R

Define `R = repairs_emitted / source_emitted`. To match the current
profiles' redundancy:

| Profile  | Today `(K, N)` | Today `R_eff = (N - K) / K` | Proposed `W` | Proposed `R` |
|----------|:--------------:|:---------------------------:|:------------:|:------------:|
| Video    | (8, 12)        | 0.50                        | 64           | 0.50         |
| Mavlink  | (1, 2)         | 1.00                        | 16           | 1.00         |
| Tunnel   | (1, 2)         | 1.00                        | 32           | 1.00         |

Constraint: `R · W ≤ 128` (7-bit `repair_idx` cap). All recommended
defaults satisfy this with headroom.

#### Recovery capacity per window

The RS matrix capacity is `⌈R · W⌉` parities per window. In
principle that recovers up to `⌈R · W⌉` losses within a window.
The §7.3 scheduling together with §7.4's **cascade decode**
(added in Phase 2b clarification) realize this bound under two
distinct regimes:

| Loss pattern         | R ≥ 1.0 (parity at every tail) | R < 1.0 (e.g. R=0.5, parity every ⌈1/R⌉ tails) |
|---------------------:|:------------------------------:|:-------------------------------------------------:|
| Isolated single loss | recoverable                    | recoverable                                       |
| Scattered losses spaced ≥ ⌈1/R⌉ apart | recoverable via cascade | recoverable via cascade         |
| Consecutive burst    | recoverable up to `⌈R · W⌉` via cascade | **NOT recoverable** (no parity at the "one-loss-window" tail to seed the cascade) |

**Cascade seeding condition.** Cascade starts from a window whose
tail holds a parity AND whose range contains exactly one loss.
Under R ≥ 1.0 every tail has a parity, so every window that
contains exactly one burst-member is a valid seed. Under R < 1.0
only a fraction of tails have parities; consecutive bursts have no
"exactly-one-loss window" at a parity-bearing tail (each shift of
the window boundary moves it past one burst-member, but the parity
only arrives at every ⌈1/R⌉-th tail, skipping the single-loss
boundary window).

**Practical implications:**

- **Mavlink / tunnel (R=1.0):** full consecutive-burst recovery up
  to `⌈R · W⌉` losses. Strictly stronger than block FEC at the same
  overhead ratio for bursty loss.
- **Video (R=0.5):** suited for sparse / interleaved losses, which
  is typical of Wi-Fi air-interface loss patterns. A dedicated
  consecutive-burst longer than 1 packet is NOT recoverable at
  R=0.5 — the design trades this worst-case burst coverage for
  lower bandwidth overhead. Operators who need consecutive-burst
  coverage at video rates should pick R ≥ 1.0 (or a Phase 3+
  scheduling variant that emits multiple parity rows per window
  under R < 1.0).
- Relative to block FEC at matched overhead (video R=0.5 vs block
  (8, 12)): block FEC recovers up to 4 per-block losses, including
  a 4-consecutive burst entirely within one block. SWIN at R=0.5
  does NOT handle consecutive bursts ≥ 2. SWIN's win is HOL-free
  immediate source delivery (§2 motivation) and cascade recovery
  of scattered losses, NOT burst tolerance at this overhead.

### 7.3 Emission schedule (Phase 1: proactive only)

For `R ≤ 1`:

- Maintain a counter `repair_due_in` initialized to `⌈1 / R⌉`.
- On every source packet: decrement.
- On reaching 0: emit one repair (with `repair_idx = 0`, per the §5.3
  allocation rule) covering the current window, reset counter to
  `⌈1 / R⌉`.

For `R > 1`:

- On every source packet, emit `⌈R⌉` repairs covering the current
  window. The first uses `repair_idx = 0`, the second `repair_idx = 1`,
  up to `repair_idx = ⌈R⌉ − 1`. Each successive source advances the
  window (i.e. the next source's repairs cover a new window with its
  own `window_tail_seq` and its own `repair_idx` starting again at 0).
- At the recommended defaults `R = 1.0` (mavlink, tunnel), this reduces
  to exactly one repair per source with `repair_idx = 0`.

Per §5.3: each window allocates `repair_idx` independently from zero.
The stream-wide "mod `⌈R · W⌉`" rotation that an earlier draft
proposed is not used.

No RX→TX feedback. A feedback-driven policy is out of scope for Phase 1
because it requires a back channel that asymmetric drone links don't
always provide.

### 7.4 RX window and flush deadline

- RX keeps `W_rx = 2 · W` source slots plus a repair store sized
  dynamically up to `W_rx · R` entries (std::map in the Phase 2b
  impl — fixed-capacity pool is a Phase 3 optimization).
- A source packet is emitted to the socket immediately on arrival, before
  any repair logic runs. Duplicate-seq arrivals are ignored (dedup via
  `count_p_uniq`-style set; see §10.3 risk).
- A repair packet triggers a **cascade decode** (see below) on its
  window `[tail - W + 1, tail]`.
- Wall-clock flush: every `T_flush_check = 10 ms`, retire any source
  slot whose `seq_num < max_seq_received - W_rx` OR whose age ≥
  `T_flush`. On retirement, gaps are declared lost; the stats counter
  advances.

Recommended `T_flush`:

| Profile  | `T_flush` |
|----------|:---------:|
| Video    | 100 ms    |
| Mavlink  | 300 ms    |
| Tunnel   | 300 ms    |

These values let typical bursts recover while keeping worst-case gap
detection bounded.

#### Cascade decode

A single `fec_decode_simd` call solves ONE window — given W inputs
(source slots plus parity substitutes), it recovers up to `n - k =
⌈R · W⌉` erasures in that window. To recover an N-consecutive
burst at parity-every-tail (R ≥ 1.0), RX must re-attempt decode on
ADJACENT windows after each successful recovery, because each
recovery provides one more "known source" to the overlapping
neighbor window, potentially unblocking it.

**Algorithm:**

1. Primary trigger: on each repair arrival at `window_tail_seq = T`,
   attempt `do_decode_once(T)`. If it recovers sources `S_1, ..., S_k`,
   enqueue the set of repair-bearing windows covering any `S_i`:
   `{ct : repair_store contains (ct, *) AND ct ∈ [S_i, S_i + W - 1]}`.
2. Pop the worklist; for each popped `ct`, run `do_decode_once(ct)`;
   if more recoveries, enqueue more; repeat until empty.
3. Secondary trigger: on out-of-order source arrival that fills a
   prior gap (as opposed to advancing the front), run the same
   cascade over windows covering the filled seq.

The worklist is bounded. Each window only "decodes for real" a
small constant number of times before its `known_sources == W`
early-return kicks in on subsequent visits.

**Load-bearing implementation invariants** (missing these causes
silent corruption, not just sub-optimal recovery):

- **Early-recovery preservation.** The encoder may emit a repair
  for window tail T immediately after placing source T in its
  ring. That repair arrives at RX before `max_seq_received`
  reaches T. If the decoder has seq T-W+1..T-1 (all sources
  preceding T) plus this parity, it can recover source T *before*
  the source itself is on the wire — or even before the source's
  drop is observable as a gap. When `max_seq_received` later
  advances past T (via a successor source's arrival), the
  ring-initialization loop MUST NOT clobber slot T's RECOVERED
  state back to EMPTY.
- **Stale-cascade skip.** `do_decode_once(tail)` MUST return
  without effect if `tail < next_emit_seq` — that window's sources
  have already been emitted (or flushed) to the socket; any
  "recovery" there is wasted work AND may write into ring slots
  that have been reused for newer seqs.
- **Ring-rollover abort.** Before setting up output buffers,
  `do_decode_once` MUST scan the window's W slots. If any slot's
  `seq` doesn't match the expected position (and isn't the
  uninitialized sentinel), the ring has rolled through this window
  and decode MUST abort — writing a recovered payload into a slot
  that now holds a different seq's data would corrupt that data.

These invariants aren't derivable from §9.3's surface-level
contract; they fall out of the ring+cascade combination and must
be respected in every IFecDecoder implementation that shares this
decoder shape.

---

## 8. Memory and CPU cost estimates

All numbers are back-of-envelope estimates from first-principles for the
zfex SIMD kernel. Empirical validation is a Phase 2 task (benchmark
harness). The point of this section is to show the design is
*comfortable* on the binding platform (RPi Zero 2W), not to promise an
exact figure.

### 8.1 Memory

**RX**, sliding-window at `W_rx = 2 · W`, worst-case payload size
`MAX_FEC_PAYLOAD = 3996` B (typical video UDP payload is ≤ 1400 B; full
3996 B only on jumbo):

| W   | `W_rx` | 3996 B/pkt | 1400 B/pkt | Repairs (`+ W_rx · R`, 3996 B) |
|-----|:------:|:----------:|:----------:|:-----------------------------:|
| 16  | 32     | 125 KiB    | 44 KiB     | at R=1.0: +125 KiB (W=16)     |
| 32  | 64     | 250 KiB    | 88 KiB     | at R=1.0: +250 KiB (W=32)     |
| 64  | 128    | 499 KiB    | 175 KiB    | at R=0.5: +250 KiB (W=64)     |
| 128 | 256    | 999 KiB    | 350 KiB    | at R=0.5: +499 KiB            |

Total RX at video defaults (W=64, R=0.5): **~750 KiB worst-case**.

Compare to current RX ring: `RX_RING_SIZE · fec_n · MAX_FEC_PAYLOAD = 40
· 12 · 3996 ≈ 1.83 MiB` at video defaults. **Sliding window uses less
RX memory than today** under the recommended profiles.

**TX** needs the last `W` source payloads to generate any repair. Same
arithmetic, no 2× safety factor: video ~250 KiB, mavlink ~30 KiB.

Memory is not a binding constraint on any target platform, including
512 MB RPi Zero 2W. Hard constraint would only appear at W > 1024 with
large payloads.

### 8.2 Encode CPU (per repair)

zfex's inner loop processes 16 bytes per vector iteration: one 16-byte
GF(2^8) table lookup (split-nibble) + XOR into destination + load/store
([src/zfex.c:196-265](../src/zfex.c#L196-L265)). Per-platform cost per
vector iteration `t_vec`:

| Platform                         | `t_vec` (est.) |
|----------------------------------|:--------------:|
| RPi Zero 2W (Cortex-A53 @ 1 GHz, 128-bit NEON) | ~2.5 ns |
| NanoPi NEO-class (Cortex-A7 @ 1 GHz, 64-bit NEON) | ~5–6 ns |
| amd64 GCS (Skylake+ @ 3 GHz, SSSE3)            | ~0.4 ns |

**Two numbers matter**, depending on whether the Phase-2a zfex extension
lands or not.

**With `fec_encode_row_simd` (§6, recommended path).** One parity row
only: cost per repair ≈ `W · ⌈P / 16⌉ · t_vec`.

| Platform       | W=64, P=1400 | W=64, P=3996 | W=128, P=1400 | W=128, P=3996 |
|----------------|:------------:|:------------:|:-------------:|:-------------:|
| RPi Zero 2W    | ~14 µs       | ~40 µs       | ~28 µs        | ~80 µs        |
| NanoPi NEO A7  | ~30 µs       | ~85 µs       | ~60 µs        | ~170 µs       |
| amd64 GCS      | ~2.2 µs      | ~6.4 µs      | ~4.5 µs       | ~13 µs        |

**Without the extension — bulk `fec_encode_simd`, discard
`(n - k - 1)` rows.** The inner loop at
[src/zfex.c:815-826](../src/zfex.c#L815-L826) runs `(n - k) = ⌈R · W⌉`
times per call. Cost per repair ≈ `⌈R · W⌉ · W · ⌈P / 16⌉ · t_vec`:

| Platform       | W=64 R=0.5, P=1400 | W=64 R=0.5, P=3996 | W=128 R=0.5, P=1400 | W=128 R=0.5, P=3996 |
|----------------|:------------------:|:------------------:|:-------------------:|:-------------------:|
| RPi Zero 2W    | ~450 µs            | ~1.3 ms            | ~1.8 ms             | ~5.2 ms             |
| NanoPi NEO A7  | ~960 µs            | ~2.7 ms            | ~3.8 ms             | ~11 ms              |
| amd64 GCS      | ~70 µs             | ~205 µs            | ~290 µs             | ~830 µs             |

As a percentage of one core at 1080p30 video load (source 300 pps,
repair 150 pps at R=0.5), **with the extension**:

| Platform       | W=32   | W=64   | W=128  |
|----------------|:------:|:------:|:------:|
| RPi Zero 2W    | 0.10%  | 0.21%  | 0.42%  |
| NanoPi NEO A7  | 0.22%  | 0.45%  | 0.90%  |
| amd64 GCS      | 0.016% | 0.033% | 0.067% |

Same workload **without the extension** (bulk-discard path):

| Platform       | W=32   | W=64   | W=128  |
|----------------|:------:|:------:|:------:|
| RPi Zero 2W    | 1.7%   | 6.8%   | 27%    |
| NanoPi NEO A7  | 3.6%   | 14%    | 58%    |
| amd64 GCS      | 0.26%  | 1.0%   | 4.3%   |

The bulk-discard path is **unacceptable at W=128 R=0.5 on RPi Zero 2W**
and tight at W=64. This is why Phase 2a commits to the zfex extension
rather than deferring it. Until the extension lands, W must stay ≤ 64
for RPi Zero 2W and the encode path is the single largest incremental
CPU cost of SWIN.

Worst-case 3996 B payload: multiply column values by ~2.85.

### 8.3 Decode CPU (per gap-recovery event)

`fec_decode_simd` does two things:

1. Invert the `g × g` submatrix of Vandermonde rows corresponding to the
   `g` *missing* positions — `O(g^3)` scalar GF(2^8) ops. At g=8,
   ~512 scalar ops × ~5 ns on A53 ≈ **2.5 µs** (negligible).
2. Apply the inverse to reconstruct the missing payloads —
   `O(g · W · P / 16)` SIMD addmul iterations, same lane cost as encode.

At g=4 gaps, W=64, P=1400 on RPi Zero 2W:
`4 · 64 · 88 · 2.5 ns ≈ 56 µs/event`.

At a decode event rate of 100/s (bursty: 4 gaps per second, each
triggering a window recompute), total = **0.56% of one core**. At g=16
(pathological 25% window loss) ~225 µs/event.

Block FEC today is cheaper per-decode (`apply_fec` at
[src/rx.cpp:895](../src/rx.cpp#L895): `k=8`, worst-case 4 missing, P=1400:
~7 µs/block × 37 blocks/s ≈ 0.026% of a core). Sliding window pays more
per decode but events are rarer — net is roughly the same on the
aggregate.

### 8.4 RPi Zero 2W sanity check

Budget for 1080p30 @ ~3 Mbps video, W=64, R=1/3, **assuming Phase-2a
`fec_encode_row_simd` extension is in place**:

| Cost                                          | Value                 |
|-----------------------------------------------|:---------------------:|
| Source pps                                    | ~300                  |
| Repair pps                                    | ~100                  |
| Encode: 100 repairs/s × 14 µs (one-row API)   | 1.4 ms/s = **0.14%** |
| Decode: 5% loss → g≈3, 4 events/s × 42 µs     | 0.17 ms/s = **0.02%** |
| AEAD (chacha20poly1305, +100 pps × 1400 B)    | ~0.12 ms/s = **0.12%** |
| **Total extra vs today**                      | **< 0.5% one A53 core** |

Without the extension (bulk-discard fallback) the encode line becomes
`100 · ⌈R·W⌉ · 14 µs = 100 · 22 · 14 µs ≈ 31 ms/s = 3.1%` at R=1/3. Still
affordable at this R, but it becomes the dominant FEC cost and
motivates the extension.

The Zero 2W has 4 A53 cores. The existing wfb-rx process pins to one.
Binding bottleneck today is pcap capture and kernel packet handling —
sliding-window FEC does not make that worse under either API.

---

## 9. Abstractions for coexistence

Today `Transmitter` ([src/tx.hpp:72](../src/tx.hpp#L72)) and `Aggregator`
([src/rx.hpp:169](../src/rx.hpp#L169)) both hold `fec_p`, `fec_k`,
`fec_n` as direct members
([src/tx.hpp:95-97](../src/tx.hpp#L95-L97),
[src/rx.hpp:232-234](../src/rx.hpp#L232-L234)) and inline the FEC calls
at [src/tx.cpp:686](../src/tx.cpp#L686) and
[src/rx.cpp:895](../src/rx.cpp#L895). The block-FEC implementation is
tightly coupled to these classes. Adding a second codec behind an
`if (fec_type == …)` branch scattered across tx.cpp and rx.cpp would
degrade both paths and ruin reviewability.

### 9.1 Parameter carrier

The current init signatures
`Transmitter::init_session(int k, int n)`
([src/tx.hpp:79](../src/tx.hpp#L79),
[src/tx.cpp:113](../src/tx.cpp#L113)) and
`Aggregator::init_fec(int k, int n)`
([src/rx.hpp:221](../src/rx.hpp#L221),
[src/rx.cpp:306](../src/rx.cpp#L306), called at
[src/rx.cpp:696](../src/rx.cpp#L696)) carry only `(k, n)`. Constructors
for all three `Transmitter` subclasses
([src/tx.hpp:159](../src/tx.hpp#L159),
[src/tx.hpp:208](../src/tx.hpp#L208),
[src/tx.hpp:312](../src/tx.hpp#L312)) likewise thread `(k, n)` down to
the base. To carry W, R cleanly, introduce:

```c++
// src/fec_iface.hpp (new)

struct fec_params_t {
    uint8_t  fec_type;      // WFB_FEC_VDM_RS or WFB_FEC_SWIN_RS
    // VDM_RS only (0 under SWIN):
    int      k;
    int      n;
    // SWIN_RS only (0 under VDM):
    uint16_t swin_w;        // W, from TLV_SWIN_WINDOW
    uint8_t  swin_r_num;    // R numerator, from TLV_SWIN_REPAIR_RATIO
    uint8_t  swin_r_den;    // R denominator, from TLV_SWIN_REPAIR_RATIO
};
```

Widen the init entry points to take `const fec_params_t&`:

```c++
void Transmitter::init_session(const fec_params_t& params);
void Aggregator::init_fec(const fec_params_t& params);
```

The three `Transmitter` subclass constructors and the
`wfb_tx`/`wfb_rx` `getopt` plumbing in
[wfb_ng/services.py:106](../wfb_ng/services.py#L106) take the same
struct (populated from either `-k/-n` under block, or
`--swin-w/--swin-r` under SWIN — see §10.1).

### 9.2 RX session-parse ordering

Under the new scheme, the RX path at
[src/rx.cpp:645-700](../src/rx.cpp#L645-L700) must extract W, R from the
session packet TLVs **before** calling `init_fec`. The helper
`Aggregator::get_tag` at
[src/rx.cpp:549-568](../src/rx.cpp#L549-L568) is reused. Revised
order:

1. Decrypt session packet (existing
   [src/rx.cpp:632-641](../src/rx.cpp#L632-L641)).
2. Validate `epoch`, `channel_id` (existing
   [src/rx.cpp:645-657](../src/rx.cpp#L645-L657)).
3. Validate `fec_type` against `configured_codec` (§10.2; moved check
   still at [src/rx.cpp:659-664](../src/rx.cpp#L659-L664)).
4. If `fec_type == WFB_FEC_VDM_RS`: validate `k, n` bounds (existing
   [src/rx.cpp:666-678](../src/rx.cpp#L666-L678)), populate
   `fec_params_t` from fixed header.
5. If `fec_type == WFB_FEC_SWIN_RS`: validate `k == 0 && n == 0`
   (reserved, §5.5); call `get_tag(tag_region, size, TLV_SWIN_WINDOW,
   &w_be, 2)` and `get_tag(..., TLV_SWIN_REPAIR_RATIO, &r_bytes, 2)`;
   validate `W, R` bounds (`W ≥ 1`, `R · W ≤ 128`); populate
   `fec_params_t`.
6. If `memcmp(session_key, new_session_data->session_key) != 0`
   ([src/rx.cpp:686](../src/rx.cpp#L686)), call the decoder-factory
   (§9.3) with `fec_params_t`.

### 9.3 Encoder / decoder interfaces

```c++
class IFecEncoder {
public:
    virtual ~IFecEncoder() = default;

    // Called for every source packet from the app. Updates window state.
    // The encoder does NOT emit the source packet — Transmitter does that.
    // payload buffer must be ZFEX_SIMD_ALIGNMENT-aligned.
    virtual void on_source_packet(uint64_t seq, const uint8_t* payload, size_t sz) = 0;

    // Emit the next repair packet if one is due. Returns false if not due.
    // If true: out buffer (caller-provided, ZFEX_SIMD_ALIGNMENT-aligned,
    // ZFEX_ROUND_UP_SIMD-padded) holds repair payload of size *sz_out;
    // nonce_out holds the 64-bit big-endian data_nonce per §5.2.
    virtual bool next_repair(uint8_t* out, size_t* sz_out, uint64_t* nonce_out) = 0;

    // Wall-clock advance. Called every ~10 ms from the TX event loop.
    // Block FEC ignores it; sliding FEC uses it for pacing.
    virtual void tick(uint64_t now_ms) = 0;
};

class IFecDecoder {
public:
    virtual ~IFecDecoder() = default;

    virtual void on_source_packet(uint64_t seq, const uint8_t* payload, size_t sz) = 0;
    virtual void on_repair_packet(uint64_t repair_nonce,
                                  uint64_t window_tail_seq,
                                  uint8_t repair_idx,
                                  const uint8_t* payload, size_t sz) = 0;

    // Drain any source packets (received or recovered) ready for the socket,
    // in increasing seq order. Returns false when no more are ready.
    //
    // seq_out: the FLAT packet_seq for loss-listener tracking (Phase 2b
    // B0 commit; was previously "data_nonce view" in the original
    // Phase 1 draft). Block returns block_idx * fec_k + fragment_idx.
    // Sliding returns the 56-bit seq_num (low bits of data_nonce).
    // Aggregator uses seq_out directly for its `packet_seq > seq + 1`
    // gap-detection check; no codec-aware decoding in Aggregator.
    virtual bool pop_ready(uint64_t* seq_out, uint8_t* out, size_t* sz_out) = 0;

    // Called every ~10 ms from the event loop to advance wall-clock flush.
    virtual void tick(uint64_t now_ms) = 0;

    // ----- Codec-aware query accessors (Phase 2b B0) -----
    // These keep rx.cpp fully codec-agnostic: Aggregator neither reads
    // fec_k / fragment_idx to decide is_repair, nor computes flat
    // packet_seq from (block_idx, fragment_idx).

    // True if data_nonce names a repair fragment. Block returns
    // (data_nonce & 0xff) >= fec_k_; sliding returns bit 63 of
    // data_nonce (is_repair per §5.2).
    virtual bool is_repair_fragment(uint64_t data_nonce) const = 0;

    // Running count of source fragments recovered via FEC since
    // construction (monotone cumulative). Aggregator mirrors to its
    // per-interval public count_p_fec_recovered using a baseline
    // captured at clear_stats time.
    virtual uint32_t count_p_fec_recovered() const = 0;

    // Running count of ring override-evictions (block-specific).
    // SWIN has no ring; SWIN returns 0 unconditionally.
    virtual uint32_t count_p_override() const = 0;

    // Running count of windows retired at T_flush with at least one
    // unrecovered gap (SWIN-specific, §10.3). Block has no T_flush;
    // block returns 0 unconditionally.
    virtual uint32_t count_w_flush() const = 0;
};

std::unique_ptr<IFecEncoder> make_fec_encoder(const fec_params_t&);
std::unique_ptr<IFecDecoder> make_fec_decoder(const fec_params_t&,
                                              PacketLossListener* loss_listener);
```

Two implementations under `src/fec_block.{cpp,hpp}` and
`src/fec_swin.{cpp,hpp}`. `Transmitter` owns `std::unique_ptr<IFecEncoder>`,
`Aggregator` owns `std::unique_ptr<IFecDecoder>`. Every buffer exchanged
across these interfaces MUST satisfy zfex's alignment contract at
[src/zfex.c:794-809](../src/zfex.c#L794-L809) —
`posix_memalign(ZFEX_SIMD_ALIGNMENT, ZFEX_ROUND_UP_SIMD(max_size))` as
today's block path does at [src/tx.cpp:135](../src/tx.cpp#L135).

This keeps the tx / rx pipelines fec-type-agnostic: `Transmitter`
always emits each source immediately and then drains `next_repair()`
until it returns false; `Aggregator` always routes each data packet
via `decoder->is_repair_fragment(data_nonce)` and then drains
`pop_ready()`. The two codecs never share state.

**Note (Phase 2b B0 revision history):** the original §9.3 draft
said Aggregator "routes based on `is_repair`" without specifying how
Aggregator would compute it, and left pop_ready's `seq_out` as the
data_nonce composite. Phase 2a's implementation used the block-only
rule `fragment_idx < fec_k` directly in Aggregator, which did not
generalize to SWIN. B0 adds the four virtual accessors above so
that both rx.cpp and codec internals can be written without
`if (fec_type == ...)` branches anywhere in the hot path.

### 9.4 `PacketLossListener` widening (ABI break)

The current listener signature at
[src/rx.hpp:42](../src/rx.hpp#L42) is:

```c++
virtual void on_packet_loss(uint32_t lost_count,
                            uint32_t last_seq, uint32_t new_seq) = 0;
```

Under block FEC today, `packet_seq = block_idx * fec_k + fragment_idx`
is computed and cast to `uint32_t` at
[src/rx.cpp:865](../src/rx.cpp#L865). Under SWIN, `seq_num` is
56 bits — truncation to `uint32_t` wraps every ~71 minutes at 1000 pps
and silently corrupts gap counts.

**Fix**: widen the signature to
`on_packet_loss(uint32_t lost_count, uint64_t last_seq, uint64_t new_seq)`.
This is a source-compat break for any external binding (Python wfb_ng,
cluster-mode consumers). Phase 2a must walk all implementers — the
only in-tree implementer is the Python-bound listener path through
`AggregatorUDPv4` / `AggregatorUNIX` — and update them.

**B0 clarification on seq semantics:** `last_seq` and `new_seq` are
the **flat packet_seq** — the same value `pop_ready` returns in its
`seq_out`. Aggregator passes them through without transformation.
Block decoder computes `block_idx * fec_k + fragment_idx` internally;
sliding decoder uses `seq_num`. Listener implementers do not need
to know which codec is active — the seq space is already canonicalized
by the decoder.

---

## 10. Coexistence, rollout, backward compatibility

### 10.1 Configuration

A new config key in each stream profile in
[wfb_ng/conf/master.cfg](../wfb_ng/conf/master.cfg):

```
[video]
fec_type = block   # or 'sliding'
fec_k    = 8       # block only; ignored under 'sliding'
fec_n    = 12      # block only; ignored under 'sliding'
swin_w   = 64      # sliding only; ignored under 'block'
swin_r   = 0.5     # sliding only; ignored under 'block'
```

Wired through [wfb_ng/services.py:106](../wfb_ng/services.py#L106) to new
flags on the C++ binaries.

**Short flag `-C` is already taken** by `wfb_tx` for `control_port` at
[src/tx.cpp:1805-1807](../src/tx.cpp#L1805-L1807), and
`services.py:107` already passes it. The codec selector and SWIN
parameters are added as **long options only** to sidestep the collision
and to avoid competing for the few remaining short letters in the
`wfb_tx` getopt string at
[src/tx.cpp:1700](../src/tx.cpp#L1700):

- `wfb_tx --codec=block` (default) or
  `wfb_tx --codec=sliding --swin-w=64 --swin-r=1/2`
- `wfb_rx --codec=block` (default) or
  `wfb_rx --codec=sliding` (W and R are learned from the session
  TLV, so the RX side does not need `--swin-w`/`--swin-r`, but they
  may be accepted as overrides for diagnostic use).

Implementation note: `wfb_tx`'s current `getopt(…)` call would extend
to `getopt_long(…)`; `wfb_rx`'s `getopt(…)` at
[src/rx.cpp:1151](../src/rx.cpp#L1151) does the same. All existing
short options stay byte-for-byte identical.

Block remains the default; `fec_type = sliding` is opt-in per stream
profile.

### 10.2 Mixed-version fleet behavior

Under the §9 refactor both codecs are compiled into every binary. The
reject at [src/rx.cpp:659-664](../src/rx.cpp#L659-L664) therefore
changes from a hardcoded `fec_type != WFB_FEC_VDM_RS` check to a
**configured-codec mismatch** check: `fec_type != configured_codec`,
where `configured_codec` comes from `--codec=` at RX startup. Same
file:line, same fail-closed behavior, but it is a policy decision, not
a compile-time capability.

| TX           | RX config | Behavior                                      |
|--------------|-----------|-----------------------------------------------|
| block (old)  | block     | Works (new RX handles old `fec_type=VDM_RS`)  |
| block (new)  | block     | Works (wire-compatible, no change)            |
| sliding (new)| block     | **Fail-closed**: RX rejects session at `fec_type != configured_codec` |
| sliding (new)| sliding   | Works                                         |
| block (new)  | sliding   | **Fail-closed**: same guard, symmetric        |
| sliding (new)| old RX    | **Fail-closed**: old RX hardcodes `fec_type != WFB_FEC_VDM_RS` → same path |

In all fail-closed cases the session is never accepted, the session key
is never updated, and subsequent data packets fail AEAD — operator
visibility is via rising `count_p_dec_err`. No corruption, no partial
delivery.

### 10.3 Stat compatibility

Existing RX counters keep their semantics where they make sense;
three need explicit attention under SWIN.

- `count_p_uniq` ([src/rx.hpp:206](../src/rx.hpp#L206),
  [src/rx.cpp:738](../src/rx.cpp#L738)) keys off the full 8-byte
  `data_nonce`. Under the new layout, source `(is_repair=0, seq)` and
  repair `(is_repair=1, seq)` with numerically equal `seq` map to
  distinct set keys, so the set insert already does the right thing.
  This invariant is load-bearing — call it out in a comment.
- `count_p_fec_recovered` is incremented for each source packet the
  decoder recovers (same semantics as today).
- `count_p_lost` is inferred from gaps in the delivered `seq_num`
  sequence at socket output. With sliding window, losses are counted
  when `T_flush` expires on an unrecovered window slot.
- **`count_p_override`** ([src/rx.hpp:210](../src/rx.hpp#L210),
  incremented at [src/rx.cpp:440](../src/rx.cpp#L440)) counts block-FEC
  ring overflows. Under SWIN there is no ring overflow by construction
  (the window is fixed-size and slots are retired by age, not by
  pressure). `count_p_override` therefore stays at 0 under SWIN and
  `log_parser.py` consumers must treat 0 under SWIN as "N/A", not "no
  overflow". `count_w_flush` (new, per below) is the SWIN analogue.
- **New counter `count_w_flush`** tallies windows retired with ≥ 1
  unrecovered gap at `T_flush` expiry. Useful for link-quality
  estimation. Added to `dump_stats` at
  [src/rx.cpp:501-509](../src/rx.cpp#L501-L509) alongside existing
  counters.

### 10.3.1 SESSION log line and its downstream parsers

The existing SESSION log emission at
[src/rx.cpp:698](../src/rx.cpp#L698):

```c
IPC_MSG("%" PRIu64 "\tSESSION\t%" PRIu64 ":%u:%d:%d\n",
        get_time_ms(), epoch, WFB_FEC_VDM_RS, fec_k, fec_n);
```

hardcodes `WFB_FEC_VDM_RS`. Under SWIN this must become:

```c
IPC_MSG("%" PRIu64 "\tSESSION\t%" PRIu64 ":%u:%d:%d:%u:%u/%u\n",
        get_time_ms(), epoch, params.fec_type,
        params.k, params.n,
        params.swin_w, params.swin_r_num, params.swin_r_den);
```

The two extra fields are always emitted (written as `0:0/0` under
block), so the log format is forward-compatible for parsers that
expect a fixed field count.

**Downstream update sites**:

- [wfb_ng/cli.py](../wfb_ng/cli.py): currently formats the SESSION line
  as `'{FEC:} %(fec_k)d/%(fec_n)d'`. Update to branch on `fec_type` and
  render `SWIN W=%d R=%d/%d` under `WFB_FEC_SWIN_RS`.
- [wfb_ng/log_parser.py](../wfb_ng/log_parser.py): extend the SESSION
  line parser to read the two new trailing fields. Existing fixed-field
  consumers (e.g. mavlink log parsing) are unaffected — only the
  SESSION record grows.

Both files are in-tree; no external parser ABI is broken by adding
fields at the tail. The only break is the IPC_MSG format string growth
itself; any out-of-tree log consumer that parses the SESSION line
strictly will need to tolerate the extra fields.

### 10.3.2 PacketLossListener ABI break

See §9.4. The `on_packet_loss` signature widens from three `uint32_t`
args to `(uint32_t, uint64_t, uint64_t)`. In-tree implementers in
`wfb_ng/` are updated in Phase 2a.

---

## 11. Migration trade-offs

This section is the one-page answer to "should we flip the switch?" It
summarizes what an operator gains, what it costs, and when block FEC is
still the right choice.

### 11.1 Pros (reasons to migrate)

- **Gap-handling decouples from block boundaries.** A missing packet at
  `seq N` stalls only `N` until it is recovered or `T_flush` expires; it
  does not hold `N + 1`, `N + 2`, or any later-block packets already
  received. Block FEC stalls all of them until the gap fills or FEC
  decodes (§1 failure modes 1 and 2). On a noisy link this is the visible
  win.
- **Burst loss straddling a block boundary is recoverable.** A burst of
  length `B` that leaves two adjacent blocks each with `≥ fec_k - B/2 + 1`
  fragments missing is unrecoverable under block FEC but recoverable
  under a single window as long as `W ≥ B` and `⌈R · W⌉ ≥ B` (§1 failure
  mode 3, §7.2).
- **Lower RX memory footprint** at recommended defaults: ~750 KiB worst
  case for video vs ~1.83 MiB today (§8.1).
- **Wire format unchanged byte-for-byte.** Same 9-byte `wblock_hdr_t`,
  same crypto primitive, same MTU, same session-key protocol. Only the
  `fec_type` byte in the session packet and the internal interpretation
  of `data_nonce` change (§5).
- **Fail-closed rollout.** Mixed-version fleets never corrupt or
  mis-decode: old RX drops new-TX sessions at
  [src/rx.cpp:659-664](../src/rx.cpp#L659-L664), new RX configured for a
  different codec applies the same guard symmetrically (§5.7, §10.2).
  Rollback is a config flip.
- **Reuses existing zfex.** No new dependency, no license review, no new
  SIMD tuning work; NEON and SSSE3 kernels are already in place.
- **Deterministic MDS recovery.** Any `W` of `W + ⌈R · W⌉` packets
  reconstructs the window. No probability tables, no failure-rate tails.
- **CPU budget is not a constraint.** < 1% of one A53 core on the binding
  platform (RPi Zero 2W) at 1080p30 video (§8.4).
- **Per-profile, per-session opt-in.** Video can go sliding while mavlink
  stays block, or vice versa. No all-or-nothing switchover.

### 11.2 Cons (reasons to hold or stay on block)

- **Padding amplification is larger.** Block FEC pads within `K`;
  sliding window pads within `W`, which is ~8× larger at recommended
  defaults. A single 1400-B outlier in a window of 64 small packets
  produces `⌈R · W⌉` repair packets sized to the outlier. For streams
  with highly bursty packet sizes (some tunnel workloads), this can
  *waste on-air bandwidth* compared to block FEC. Mitigation exists
  (`repair_max_payload`, §12.1) but costs recovery coverage of those
  large packets.
- **Higher per-decode CPU cost.** ~56 µs per decode event at W=64 g=4 vs
  ~7 µs per block decode at `(k=8, n=12)` (§8.3). Events are rarer, so
  aggregate is similar, but a bursty loss pattern can produce decode
  spikes.
- **Recovery latency is window-scoped, not block-scoped.** Under block
  FEC a small gap might be decoded as soon as the current block closes
  (`N / pps` ms worst case). Under sliding window the same gap waits
  for enough in-window repairs to arrive, bounded by `T_flush` (100 ms
  video). For isolated single-packet loss on a low-jitter link, block
  FEC's recovery can be faster in absolute ms. The sliding win shows up
  only once losses are bursty or back-to-back — which is exactly when
  you care.
- **More decoder state to reason about.** `W`-slot window + repair store
  + background flush ticker + per-window tail tracking vs today's
  ring-of-blocks. Debugging traces and log semantics change.
- **`fec_delay` and the `fec_timeout` padding path become vestigial**
  under sliding (§12.1, §11.3). Operators who inherit tuned configs
  must know which knobs still apply; support surface grows.
- **Late repairs are discarded silently** after `T_flush` (§12.1). This
  is a policy choice, not a bug, but it surprises operators the first
  time they see it in a trace.
- **Implementation debt: the abstraction refactor.** Introducing
  `IFecEncoder` / `IFecDecoder` (§9) touches the hot path in
  [src/tx.cpp](../src/tx.cpp) and [src/rx.cpp](../src/rx.cpp). Even
  though the block path is semantically preserved, any refactor through
  the hot path carries regression risk on the codec operators already
  rely on.
- **zfex has no incremental encode**, so every repair re-encodes its
  full `W`-source window. CPU is fine (§8.2), but this is wasteful on
  paper and makes a bad impression on hardcore network-coding reviewers.
  Lifting it is a Phase-3 zfex extension, not in scope here.
- **Wire-trace interpretation branches on `fec_type`.** Packet-capture
  tooling that decodes `wblock_hdr_t` must know the session's
  `fec_type` to interpret `data_nonce` correctly. Existing tooling
  assumes block semantics.

### 11.3 When to stay on block FEC

Even once the sliding codec is shipped and validated, block FEC is the
right default for:

- **Isolated single-packet loss on otherwise clean links** where small
  `N` gives tight recovery latency and sliding's `T_flush` feels
  pessimistic.
- **Streams with highly variable packet sizes** and no sensible
  `repair_max_payload` cap (tunnel with mixed small-ACK / large-payload
  TCP). Padding amplification dominates the FEC overhead.
- **Interop with older fleets** that cannot be upgraded in lockstep.
  Block remains the wire-compatible choice until the fleet is on new
  binaries.
- **Minimal-resource receivers** where the ~750 KiB vs ~1.83 MiB memory
  comparison flips the other way (e.g. very small `fec_k`, `fec_n`
  profiles where the block ring is smaller than a reasonable window).

### 11.4 Suggested migration path

1. **Phase 2a** (after this doc is signed off): implement the
   `IFecEncoder` / `IFecDecoder` refactor, keeping block-FEC semantics
   byte-identical. Ship. Validate that the block codec is unchanged.
2. **Phase 2b**: implement `fec_swin.{cpp,hpp}` behind the
   interface, with `fec_type = sliding` opt-in per profile. Default
   stays block. Validate in-tree tests.
3. **Phase 2c**: run side-by-side benchmarks (Phase-2 doc: harness) on
   representative links (lab netem, field traces). Publish results.
4. **Phase 2d**: flip the default for `[video]` profile to sliding if
   bench results warrant; hold `[mavlink]` and `[tunnel]` on block
   unless benches say otherwise.
5. **Phase 3+**: optional — incremental-encode zfex extension,
   feedback-driven `R`, adaptive `W`.

No step is reversible-on-a-config-flip until step 4, and that step is
per-profile. Rollback cost is minimal.

---

## 12. Risks and open questions

### 12.1 Known risks (must be surfaced in implementation PRs)

- **Padding amplification.** RS requires all window inputs padded to the
  max payload length in the window. A window with one 1400-B packet and
  63 small ones produces 1400-B repair packets. Worst case: a single
  outlier large packet inflates `W - 1` repairs behind it. **Mitigation**:
  a session-negotiated `repair_max_payload` cap (advisory, not
  enforced). Source packets larger than the cap are emitted as source
  only and excluded from the current window. Recommended default for
  video: 1400 B.

- **Late-repair discard.** A repair that arrives after its window's
  `T_flush` has expired is silently dropped. Operators must understand
  the policy — there is no "late recovery".

- **`fec_delay` becomes vestigial.** Repairs are naturally spread by
  the `1/R` stride, so the existing TX pacer at
  [src/tx.cpp:694-705](../src/tx.cpp#L694-L705) has no effect under
  sliding. Document as deprecated for `WFB_FEC_SWIN_RS`; do not remove
  to preserve block-path behavior.

- **Variable W or R mid-session: forbidden.** Changing either requires a
  session rekey. Enforce at config load time.

- **zfex lacks incremental encode.** Every repair re-encodes its
  `W`-source window from scratch. The §8 numbers show this is fine on
  all targets. A future zfex extension (running parity accumulators)
  would reduce encode to `O(P / 16)` per source admission; this is a
  Phase-3 optimization, not needed now.

- **`count_p_uniq` silent-break risk.** Uniqueness under the new layout
  depends on `is_repair` being the high bit and on source/repair
  sequence namespaces being rekeyed together. Any future change to
  either invariant can silently double-count — guard with an assertion
  in the decoder.

### 12.2 Open questions, deferred to Phase 2+

Items resolved by the revision-2 triage (§9.1, §9.4, §10.1, §10.3, §6,
§8.2) are no longer listed here. What remains:

- **Benchmark harness spec.** How to drive both codecs over a controlled
  lossy link (netem, or the existing
  [src/fec_test.cpp](../src/fec_test.cpp) rig extended). What metrics to
  capture: goodput, glass-to-glass p50 / p99 latency, recovered ratio,
  window-flush count. A Phase-2 doc.
- **Wire-compat matrix expansion.** Explicit matrix of every TX/RX
  binary-version × fec_type combination, with expected behavior and
  operator-visible symptoms. Phase 2.
- **Feedback-driven repair.** Adaptive `R` from measured loss, small
  back-channel in the downlink. Phase 3.
- **Adaptive W.** Per-session W that grows / shrinks under measured
  loss. Phase 3.
- **GF(2^16) path.** Only needed for `W > 128 ∧ R > 1`. Not in any
  current operating point.
- **True incremental encode** (distinct from the one-row extension
  committed in §6): maintain running parity accumulators so that
  admitting a new source costs `O(P / 16)` per parity row rather than
  `O(W · P / 16)`. Phase 3.
- **`tlv_hdr_t.len` byte-order fix.** Pre-existing host-order bug
  at [src/tx.cpp:180](../src/tx.cpp#L180) /
  [src/rx.cpp:558-562](../src/rx.cpp#L558-L562), inherited by the new
  TLVs. Separate Phase-2 issue (§5.5).
- **Config-loader changes in [wfb_ng/conf/master.cfg](../wfb_ng/conf/master.cfg)
  and [wfb_ng/config_parser.py](../wfb_ng/config_parser.py)** to
  accept `fec_type`, `swin_w`, `swin_r`. Phase 2 plumbing; out of
  scope for this design.

---

## Appendix A: File reference index

- [src/tx.cpp](../src/tx.cpp) — `send_packet`, `send_block_fragment`, FEC trigger
- [src/tx.hpp](../src/tx.hpp) — `Transmitter` class
- [src/rx.cpp](../src/rx.cpp) — `Aggregator::process_packet`, `apply_fec`, rx_ring
- [src/rx.hpp](../src/rx.hpp) — `Aggregator`, `rx_ring_item_t`, `RX_RING_SIZE`
- [src/wifibroadcast.hpp](../src/wifibroadcast.hpp) — headers, nonce layout, `fec_type`
- [src/zfex.h](../src/zfex.h) — RS codec API
- [src/zfex.c](../src/zfex.c) — RS codec implementation (SIMD kernels at :196-265)
- [src/fec_test.cpp](../src/fec_test.cpp) — existing benchmark harness
- [wfb_ng/conf/master.cfg](../wfb_ng/conf/master.cfg) — profile defaults
- [wfb_ng/services.py](../wfb_ng/services.py) — Python → C++ flag plumbing
- [doc/wfb-ng-std-draft.md](wfb-ng-std-draft.md) — existing protocol draft

## Appendix B: Constants touched by this design

```
// Existing (unchanged):
WFB_PACKET_DATA          0x1
WFB_PACKET_SESSION       0x2
WFB_PACKET_FEC_ONLY      0x1   (inner flag)
WFB_FEC_VDM_RS           0x1
BLOCK_IDX_MASK           ((1LLU << 56) - 1)
MAX_BLOCK_IDX            ((1LLU << 55) - 1)

// New:
WFB_FEC_SWIN_RS          0x2
WFB_PACKET_REPAIR_SWIN   0x2   (inner flag, repair-only)
TLV_SWIN_WINDOW          0x10  (uint16 W)
TLV_SWIN_REPAIR_RATIO    0x11  (uint8 num, uint8 den)

// Nonce layout under WFB_FEC_SWIN_RS:
bit     63   : is_repair       (1 bit)
bits 62..56  : repair_idx      (7 bits)
bits 55..0   : seq_num         (56 bits)
```
