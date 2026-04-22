# Sliding-Window FEC Design for wfb-ng

**Status:** draft for review — Phase 1 (design only, no code)
**Applies to:** `wfb_tx`, `wfb_rx`, `wfb_rx --agg` (aggregator)
**Authors:** design proposal
**Date:** 2026-04-22

---

## 1. Context and motivation

wfb-ng currently uses a block-based Reed-Solomon (RS) FEC: the transmitter
groups `K` source packets into a block, generates `N - K` parity packets with
`fec_encode_simd`, and emits all `N` on-air before opening the next block.
The receiver holds an `rx_ring` of 40 in-flight blocks
([src/rx.hpp:87](../src/rx.hpp#L87)) and decodes each one only after at least
`K` of its `N` fragments have arrived
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
   becomes the front, no matter how long the front is stuck
   ([src/rx.cpp:795](../src/rx.cpp#L795) condition checks `has_fragments
   == fec_k` only on the non-front side, and the `send_packet` call at
   [src/rx.cpp:780](../src/rx.cpp#L780) is gated on `ring_idx ==
   rx_ring_front`).
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
([src/tx.hpp:72-95](../src/tx.hpp#L72-L95)); there is no virtual encoder
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
                          ├─ rx_ring_push(block_idx)     src/rx.cpp:421
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
the window — see §10 on padding amplification). When `repair_due_in`
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
  `seq_num` = monotonic 56-bit source sequence number. Session
  rekeys when `seq_num > 2^55 - 1` (same bound as today).
- For a **repair packet**: `is_repair = 1`, `repair_idx` = the
  Vandermonde parity-row index used by zfex for this repair
  (i.e. the i-th parity for the window has `repair_idx = i`;
  see §5.3). `seq_num` = monotonic 56-bit repair sequence number,
  in its own namespace independent of the source stream.
  Session rekeys when either stream's `seq_num` exceeds `2^55 - 1`.

`wblock_hdr_t.packet_type` stays `WFB_PACKET_DATA = 0x1` for both source
and repair: the RX decoder dispatches by `is_repair`, not by packet type.

### 5.3 Window-tail convention and repair semantics

Each repair packet implicitly covers the `W` source packets with
sequence numbers `[tail - W + 1, tail]`, where `tail` is the highest
source sequence number already emitted when the repair was generated. For
the receiver to know `tail`, the repair packet carries it in the
`wpacket_hdr_t` header inside the encrypted payload (see §5.4). `W`
itself is session-scoped and advertised in the session TLV.

The `repair_idx` field selects which Vandermonde parity row zfex uses for
this repair. Concretely, if the encoder maintains an effective
systematic RS code of rate `(W, W + ⌈R · W⌉)`, the i-th repair emitted
for window ending at `tail` uses parity row `W + i (mod ⌈R · W⌉)`. Since
`R · W ≤ 128` must hold (7-bit `repair_idx` cap), all defaults in §7
satisfy this.

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
([src/wifibroadcast.hpp:229-237](../src/wifibroadcast.hpp#L229-L237)). Two
new tag IDs:

```
TLV_SWIN_WINDOW        0x10   value = uint16 (big-endian) W
TLV_SWIN_REPAIR_RATIO  0x11   value = uint8 num, uint8 den  (R = num/den)
```

- When `fec_type == WFB_FEC_SWIN_RS`, both TLVs are REQUIRED.
- `fec_k` and `fec_n` in the fixed session header become advisory hints
  under `WFB_FEC_SWIN_RS`: set `fec_k = W_min_advisory` (e.g. 1) and
  `fec_n = W + ⌈R · W⌉` so old-format consumers get reasonable buffer
  sizes before they realize they can't decode. Pragmatically, old RX
  rejects the session anyway.

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

**Selected: Reed-Solomon over a sliding window, reusing zfex.**

zfex provides a systematic MDS RS code over GF(2^8) via Vandermonde
matrix ([src/zfex.h](../src/zfex.h)). `fec_encode_simd(code, inpkts[k],
fecs[m-k], size)` encodes all `m - k` parities in one bulk call; it is
SIMD-accelerated via NEON (ARM, `vqtbl1q_u8`) and SSSE3 (x86,
`_mm_shuffle_epi8`) in [src/zfex.c:196-265](../src/zfex.c#L196-L265).
`fec_decode_simd` performs a `k × k` Vandermonde-submatrix inversion and
back-substitution to recover missing positions.

Under the sliding-window design, *each repair packet is a single row of a
systematic `(W, W + ⌈R · W⌉)` RS encoding*. zfex is called once per
repair with `k = W` source pointers and writes `m - k = ⌈R · W⌉` parity
packets — of which the TX uses only the one corresponding to the current
`repair_idx`. (For implementations that only ever need one parity at a
time, a future optimization can narrow the zfex call; Phase 1 uses the
bulk API and discards unused rows.)

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

At the video defaults, sliding-window is *strictly stronger* than block
FEC for bursty loss: a burst that straddles two blocks under `(8, 12)`
is unrecoverable; the same burst inside a single W=64 window is
recoverable up to `⌈R · W⌉ = 32` losses.

Constraint: `R · W ≤ 128` (7-bit `repair_idx` cap). All recommended
defaults satisfy this with headroom.

### 7.3 Emission schedule (Phase 1: proactive only)

- Maintain a counter `repair_due_in` initialized to `⌈1 / R⌉` (ceiling
  for `R < 1`; for `R ≥ 1`, emit `⌈R⌉` repairs per source, see below).
- On every source packet: decrement.
- On reaching 0: emit one repair over the current window, set counter
  back to `⌈1 / R⌉`.
- For `R ≥ 1`: on every source packet, emit `⌈R⌉` repairs
  (repair_idx = 0, 1, ...). For `R = 1.0` (mavlink, tunnel), that's
  exactly one repair per source.

No RX→TX feedback. A feedback-driven policy is out of scope for Phase 1
because it requires a back channel that asymmetric drone links don't
always provide.

### 7.4 RX window and flush deadline

- RX keeps `W_rx = 2 · W` source slots plus `W_rx · R` repair slots.
- A source packet is emitted to the socket immediately on arrival, before
  any repair logic runs. Duplicate-seq arrivals are ignored (dedup via
  `count_p_uniq`-style set; see §10.3 risk).
- A repair packet triggers a decode attempt on its window
  `[tail - W + 1, tail]` if the total known inputs (source + repair)
  for that window is at least `W`.
- A decode attempt reconstructs every missing source packet in the
  window and releases them to the socket in `seq_num` order (catching up
  where possible; strictly past-position gaps are released out of order
  only if the jitter buffer is enabled).
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
GF(2^8) table lookup (split-nibble) + XOR into destination + load/store.
Per-platform cost per vector iteration `t_vec`:

| Platform                         | `t_vec` (est.) |
|----------------------------------|:--------------:|
| RPi Zero 2W (Cortex-A53 @ 1 GHz, 128-bit NEON) | ~2.5 ns |
| NanoPi NEO-class (Cortex-A7 @ 1 GHz, 64-bit NEON) | ~5–6 ns |
| amd64 GCS (Skylake+ @ 3 GHz, SSSE3)            | ~0.4 ns |

Per-repair cost ≈ `W · ⌈P / 16⌉ · t_vec`. Examples:

| Platform       | W=64, P=1400 | W=64, P=3996 | W=128, P=1400 | W=128, P=3996 |
|----------------|:------------:|:------------:|:-------------:|:-------------:|
| RPi Zero 2W    | ~14 µs       | ~40 µs       | ~28 µs        | ~80 µs        |
| NanoPi NEO A7  | ~30 µs       | ~85 µs       | ~60 µs        | ~170 µs       |
| amd64 GCS      | ~2.2 µs      | ~6.4 µs      | ~4.5 µs       | ~13 µs        |

As a percentage of one core at 1080p30 video load (source 300 pps, repair
100 pps at R=1/3):

| Platform       | W=32   | W=64   | W=128  |
|----------------|:------:|:------:|:------:|
| RPi Zero 2W    | 0.07%  | 0.14%  | 0.28%  |
| NanoPi NEO A7  | 0.15%  | 0.30%  | 0.60%  |
| amd64 GCS      | 0.011% | 0.022% | 0.045% |

At R=0.5 (150 pps repair), multiply by 1.5. Worst-case 3996 B payload:
multiply by ~2.85. Even the worst corner (RPi Zero 2W, W=128, P=3996,
R=0.5) is **< 1.2% of one core**. Encode is not the binding cost.

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

Budget for 1080p30 @ ~3 Mbps video, W=64, R=1/3:

| Cost                                          | Value                 |
|-----------------------------------------------|:---------------------:|
| Source pps                                    | ~300                  |
| Repair pps                                    | ~100                  |
| Encode: 100 repairs/s × 14 µs                 | 1.4 ms/s = **0.14%** |
| Decode: 5% loss → g≈3, 4 events/s × 42 µs     | 0.17 ms/s = **0.02%** |
| AEAD (chacha20poly1305, +100 pps × 1400 B)    | ~0.12 ms/s = **0.12%** |
| **Total extra vs today**                      | **< 0.5% one A53 core** |

The Zero 2W has 4 A53 cores. The existing wfb-rx process pins to one.
Binding bottleneck today is pcap capture and kernel packet handling —
sliding-window FEC does not make that worse.

---

## 9. Abstractions for coexistence

Today `Transmitter` ([src/tx.hpp:72](../src/tx.hpp#L72)) and `Aggregator`
([src/rx.hpp:169](../src/rx.hpp#L169)) both hold `fec_p`, `fec_k`,
`fec_n` as direct members and inline the FEC calls. The block-FEC
implementation is tightly coupled to these classes. Adding a second
codec behind an `if (fec_type == …)` branch scattered across tx.cpp and
rx.cpp would degrade both paths and ruin reviewability.

**Recommended minimal interface** (to be implemented in Phase 2):

```c++
// src/fec_iface.hpp (new)

class IFecEncoder {
public:
    virtual ~IFecEncoder() = default;

    // Called for every source packet from the app. Updates window state.
    // The encoder does NOT emit the source packet — Transmitter does that.
    virtual void on_source_packet(uint64_t seq, const uint8_t* payload, size_t sz) = 0;

    // Emit the next repair packet if one is due. Returns false if not due.
    // If true: out buffer holds repair payload of size *sz_out;
    // nonce_out holds the 64-bit big-endian nonce to put into wblock_hdr_t.
    virtual bool next_repair(uint8_t* out, size_t* sz_out, uint64_t* nonce_out) = 0;
};

class IFecDecoder {
public:
    virtual ~IFecDecoder() = default;

    virtual void on_source_packet(uint64_t seq, const uint8_t* payload, size_t sz) = 0;
    virtual void on_repair_packet(uint64_t repair_nonce, uint64_t window_tail_seq,
                                  const uint8_t* payload, size_t sz) = 0;

    // Drain any source packets (received or recovered) ready for the socket,
    // in increasing seq order. Returns false when no more are ready.
    virtual bool pop_ready(uint64_t* seq_out, uint8_t* out, size_t* sz_out) = 0;

    // Called every ~10 ms from the event loop to advance wall-clock flush.
    virtual void tick(uint64_t now_ms) = 0;
};
```

Two implementations under `src/fec_block.{cpp,hpp}` and
`src/fec_swin.{cpp,hpp}`. `Transmitter` owns `std::unique_ptr<IFecEncoder>`,
`Aggregator` owns `std::unique_ptr<IFecDecoder>`, each initialized in the
existing `init_session` / `init_fec` call sites based on `fec_type`.

This keeps the tx / rx pipelines fec-type-agnostic: `Transmitter`
always emits each source immediately and then drains `next_repair()`
until it returns false; `Aggregator` always routes each data packet
based on `is_repair` and then drains `pop_ready()`. The two codecs never
share state.

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
flags on the C++ binaries:

- `wfb_tx -C block` (default) or `-C sliding -W 64 -R 0.5`
- `wfb_rx -C block` (default) or `-C sliding` (W and R are learned from
  the session TLV).

Block remains the default; `fec_type = sliding` is opt-in.

### 10.2 Mixed-version fleet behavior

| TX           | RX           | Behavior                                      |
|--------------|--------------|-----------------------------------------------|
| block (old)  | block (new)  | Works (new RX handles old fec_type)           |
| block (new)  | block (old)  | Works (wire-compatible, no change)            |
| sliding (new)| block (old)  | Fail-closed: old RX drops session at [src/rx.cpp:659-664](../src/rx.cpp#L659-L664) |
| sliding (new)| block (new)  | Fail-closed same way (new RX configured for block decoder doesn't have sliding impl loaded) |
| sliding (new)| sliding (new)| Works                                         |
| block (new)  | sliding (new)| Fail-closed (sliding RX rejects `fec_type=VDM_RS` — SAME guard, mirrored) |

The last row is new: a sliding-configured RX should apply the same
fail-closed guard against `fec_type != WFB_FEC_SWIN_RS` for safety
symmetry. An operator who selects sliding on RX and block on TX sees
their mistake via climbing `count_p_dec_err`.

### 10.3 Stat compatibility

Existing RX counters keep their semantics:

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
- A new counter `count_w_flush` tallies windows flushed with ≥ 1
  unrecovered gap, useful for link-quality estimation.

`log_parser.py` ([wfb_ng/log_parser.py](../wfb_ng/log_parser.py))
continues to work; only new fields are added, existing fields keep
semantics.

---

## 11. Risks and open questions

### 11.1 Known risks (must be surfaced in implementation PRs)

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

### 11.2 Open questions, deferred to Phase 2+

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
- **True incremental encode.** Phase 3 optimization; requires a zfex
  extension.
- **Python / Twisted orchestrator changes.** CLI display of W/R in
  [wfb_ng/cli.py](../wfb_ng/cli.py); log parsing of new counters in
  [wfb_ng/log_parser.py](../wfb_ng/log_parser.py). Phase 2.

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
