# FEC Pipeline Enhancements — Design Document (v2)

**Status:** Draft, pre-implementation. v2 supersedes
[fec-enhancements.md](fec-enhancements.md) (v1); v1 is retained
for diff context. A v2.1 revision block sits directly below §Changes
from v1 — read it for decisions taken during Phase 0.5 implementation.
**Scope:** Design only. No source files are modified by this document.
**Audience:** Branch owner (self-described as weak in C) plus future
reviewers.

---

## Changes in v2.1 — Phase 0.5 revisions

These changes came out of actually starting to build Phase 1 and
hitting two places where v2's assumptions collided with real flight
operation. Both changes were settled with the branch owner in
conversation; this block records them so the rest of the document can
be read coherently.

**R1 — UNDECIDED-1A is wrong; settling on 1C instead.**
v2 assumed "flight sessions are minutes between rekeys" (§4.3). The
real operating profile is 5-minute flights max, but `(k, n)` and
`interleave_depth` changes from the adaptive daemon can fire as often
as every 200 ms (obstacle transitions, range-based bitrate changes).
Under 1A's "drain + regenerate session_key per rekey" scheme, the
per-rekey drain cost becomes a dominant airtime loss exactly when the
link is struggling — math:

```
D=4, block_duration ≈ 10 ms, rekey interval = 200 ms
drain per rekey          = D · block_duration = 40 ms
airtime lost             = 40 / 200 = 20%
```

**Decision: use option 1C.** The `session_key` becomes
process-lifetime-constant (regenerated only at process start, never in
response to `CMD_SET_FEC` / `CMD_SET_INTERLEAVE_DEPTH`). `(k, n, depth)`
changes are carried in a new session-refresh TLV reusing the current
key. A small drain still happens on (k, n) or depth change — close
the open FEC block with FEC-only closers, let the interleaver empty —
but only for structural reasons, not for key rotation. Drain cost
drops to ≤ 1 block-duration regardless of D.

Accepted risk: `session_key` freshness is lost as a property.
Owner's §4.8 stance ("I dont care about attack") covers this.
Revisit if the threat model changes.

**R2 — "Triangular convolutional interleaver" is a block interleaver.**
v2 §3.3 described a triangular convolutional (Forney) interleaver.
v2 §4.2 budgeted latency as `(depth − 1) × block_duration`. These
two specifications disagree: Forney CI with row delays
(0, D, 2D, …, (n-1)D) gives fragment delay `f · D emit slots` and
steady-state buffer `O(D · n · (n-1) / 2)` slots per side, while
§4.2's math balances only for a matrix (D × n) block interleaver with
`O(D · n)` buffer and `(D − 1) · block_duration` delay.

**Decision: block interleaver.** §4.2's latency math is the binding
spec (the Phase 3 adaptive controller will enforce it), and on the
drone-side SoC we want `O(D · n)` memory, not `O(D · n²)`.
§3.3 below is edited to call it what it is.

The shared schedule is pinned in
[src/bench/interleaver.hpp](../../src/bench/interleaver.hpp) and the
`interleaver_schedule_test` Catch2 binary — both lands in the
Phase 0.5 PR. Phase 1's production `src/interleaver.cpp` must pass
the same schedule test.

**R3 — `WFB_FEC_VDM_RS_INTERLEAVED = 0x2`, not `0x1`.**
v2 said `WFB_FEC_VDM_RS_INTERLEAVED = 1`. That collides with the
existing `#define WFB_FEC_VDM_RS 0x1` at
[src/wifibroadcast.hpp:193](../../src/wifibroadcast.hpp#L193).
Phase 1 uses `0x2` for the new value; stock-RX rejection on unknown
`fec_type` still works.

**R4 — Phase 0 scope actually shipped did not include the reference
interleaver.**
v2 §5.1 listed `src/fec_bench/interleaver.hpp` and
`src/fec_bench/interleaver_schedule_test.cpp` as Phase 0 deliverables.
The Phase 0 PR (commit `72d4fee`) deferred both by agreement with the
owner — Phase 0 scope was "just the harness." Phase 0.5 closes that
debt: a reference interleaver + schedule test + harness `--interleave-depth`
axis + committed `bench/interleaved.csv`. Phase 1 then integrates
into `tx.cpp` / `rx.cpp` as originally planned.

**R5 — Path rename: `src/fec_bench/` → `src/bench/`.**
v2 used `src/fec_bench/`. The Phase 0 PR committed under `src/bench/`.
All file-path references in the rest of the document should read
`src/bench/`.

**R6 — ARM benchmark targets deferred.**
v2 §3.5 and §5.3 required `fec_bench` to run on SSC338Q and Radxa
Zero 3W. The Phase 0 PR shipped with laptop-x86 numbers only
(`bench/baseline.csv`); ARM runs are outside the current PR pipeline.
The X_cpu pass bars in §3.6 are evaluated on laptop for Phase 0.5
sweeps; the ARM bars re-engage when the owner runs the harness on
hardware. If ARM measurement changes the picture, the plan is
updated then.

---

## Changes from v1

This section is the diff. Read it first. Every blocking item in
[fec-enhancements-review.md](fec-enhancements-review.md) §2 is either
resolved here or moved to an `UNDECIDED` block below for the branch
owner to settle. Every non-blocking item in review §3 is addressed or
explicitly deferred.

### Blocking issues (review §2)

**B1 — "Wire-compatible when depth > 1" language removed; stock-RX
break made explicit and clean.**
v1 claimed a stock RX "can in principle decode" a `depth > 1` stream.
Wrong: the flush at `rx.cpp:795-813` is triggered by
`has_fragments == fec_k` on any block, not by ring overflow — which
under interleaving is the common case, not an edge. A stock RX
actively force-flushes the in-transit primaries of older blocks. Per
owner direction ("let it break"), v2 drops stock-RX compatibility for
`depth > 1`. A new `fec_type` value `WFB_FEC_VDM_RS_INTERLEAVED = 0x2`
(v2.1 R3; v2 originally said `1`, collides with existing
`WFB_FEC_VDM_RS = 0x1`) is carried in `wsession_data_t.fec_type`
whenever `depth > 1`; a stock
RX rejects the session at the session-packet handler (it checks
`fec_type`) instead of silently scrambling primaries. See §2 Phase 2
and §4.1.

**B2 — IPC stats contract rewritten to match the code.**
v1's table had three record types under `dump_stats()`. Verified at
`rx.cpp:488-522`: only `RX_ANT` and `PKT` fire periodically. `SESSION`
at `rx.cpp:698` is edge-triggered on session-key change only — the
adaptive-link daemon would see nothing on cold start. v2 provides the
full inventory: RX-side (`RX_ANT`, 11-field `PKT`, edge-triggered
`SESSION`) and TX-side (`TX_ANT`, 7-field `PKT`,
`LISTEN_UDP`, `LISTEN_UDP_END`, `LISTEN_UDP_CONTROL`, `LISTEN_UNIX`,
`LISTEN_UNIX_END`). v2 also specifies a cold-start bootstrap: emit
`SESSION` once per `log_interval` (small rx.cpp change — one line)
so the daemon can read `(k, n, fec_type)` without waiting for a
rekey. See §2 Phase 4.

**B3 — Invariant-A fix specified as a concrete state machine.**
v1 said "deadline timer, hold-off of D blocks, or equivalent." v2
commits to a **per-block deadline timer** on `CLOCK_MONOTONIC`
(consistent with `wifibroadcast.cpp:50-64`). On first-fragment arrival
for block B, `deadline[B] = now + (n - 1) * depth * ipi + slack`. The
early-emit fast path at `rx.cpp:774-792` is gated on `depth == 1`;
when `depth > 1` it is disabled in favor of "emit in-order only when
the block at `rx_ring_front` has either reached k fragments, been
FEC-recovered, or crossed its deadline." Late fragments after deadline
are counted (`count_late_after_deadline`) and discarded. Full state
machine in §4.7 (new subsection).

**B4 — Depth change requires a session refresh with small drain.**
v1 said depth change was atomic-at-next-block, no rekey. That was
wrong: depth is a wire-ordering property and a mid-stream change
leaves already-scheduled fragments colliding with the new RX hold-off
window. v2 originally required a full drain + `init_session` (new
`session_key`). Under v2.1 R1 (option 1C), `CMD_SET_INTERLEAVE_DEPTH`
now runs a lighter sequence: close the open FEC block with FEC-only
closers (existing idiom), let the interleaver empty, then broadcast a
session-refresh TLV with the new `(k, n, depth)` on the *same*
`session_key`. Drain cost is ≤ 1 block-duration. See §2 Phase 2 table
and §4.7.

**B5 — Per-rekey outage eliminated by 1C, not budgeted.**
Original v2 plan: TX blocks on `init_session` until the interleaver
drains (≤ D × block_duration). Under v2.1 R1, `init_session` fires
only at process start, never on `CMD_SET_FEC` / `CMD_SET_INTERLEAVE_DEPTH`.
So the "≤ D × block_duration stall per rekey" cost is gone. The
remaining drain on `(k, n)` or depth change is ≤ 1 block-duration (to
close the current block cleanly) regardless of D. The B5 failure
mode ("count_p_dec_err silently eats D blocks of old-key ciphertext")
also disappears because `session_key` does not rotate.

**B6 — ARM targets named; CPU gate measured on them.**
Production targets confirmed by owner: **SSC338Q** (drone-side,
runcam wifilink2) for TX, **Radxa Zero 3W** (ground station) for RX.
v2 requires `fec_bench` to build and run on both. The X_cpu = 10%
pass bar in §3.6 is evaluated on these SBCs, not a laptop. Laptop
numbers are retained for regression detection only. See §3.5, §3.6,
and §5.3.

### Non-blocking concerns (review §3)

1. **`packet_seq` uint32 wrap (~70 days)** — Acknowledged in §4.3.
   Not fixing; flight sessions are bounded to minutes. The spurious
   "packet lost" count at the wrap edge is cosmetic.
2. **TLV `len` host-order vs header comment** — For the new
   `interleave_depth` TLV (uint8_t value), endianness is moot. v2
   specifies the value as single-byte and flags the
   `wifibroadcast.hpp:212` comment vs `tx.cpp:180` code inconsistency
   as a cleanup item in Appendix B (not a blocker).
3. **Observability** — Addressed. Phase 2 adds three new RX counters:
   `count_bursts_recovered` (block recovered with ≥ ⌈(n-k)/2⌉ erasures
   clustered), `count_holdoff_fired` (deadline flushed a block),
   `count_late_after_deadline` (fragments arriving post-deadline).
   Emitted as three new trailing fields on the RX `PKT` record; see
   §2 Phase 4 for the versioning story.
4. **Unit/fuzz/sanitizer plan** — Addressed. Phase 0 now includes
   Catch2 unit tests for the interleaver schedule (bit-identical
   between harness and the production reference). Phase 2 adds a pcap
   replay test asserting byte-identical TX output at `depth=1` vs
   `master`, and an ASan+UBSan CI job running `fec_test` under a
   scripted loss pattern. See §3.8.
5. **UEP is video-only** — Explicit note in §2 Phase 3 and Appendix B:
   `mavlink` and `tunnel` are opaque byte streams, keep stock `(k, n)`.
6. **Control-socket authentication** — Per owner ("I dont care about
   attack, it will never happen"), accepted risk. Explicit note in
   §4.8 and Appendix B.
7. **`RX_RING_SIZE` 40 → 64 memory footprint** — Quantified.
   Worst-case at `fec_n = 256`: 64 × 256 × 1466 ≈ 24 MB. Typical case
   `fec_n ≤ 16`: ≈ 1.5 MB. Radxa Zero 3W is 1 GB+; fine. v2 adds a
   runtime check: refuse `depth > 1` when `fec_n > 32` (rationale in
   §4.2 note).
8. **`WFB_PACKET_FEC_ONLY` rejected at `fragment_idx == 0`**
   (tx.cpp:656-659) — Phase 3 risk item 5 rewritten: classifier must
   send at least one real data byte to open the high-priority block,
   and may then close the block with FEC-only closers.
9. **Fast reflex vs slow trim** — Framing added to §2 Phase 4 preamble
   and Appendix B: interleaving is the per-block reflex against bursts
   (milliseconds); adaptive depth is the hundreds-of-ms trend response.
   Do not conflate.
10. **Phase 1 (side-car MVP) worth the code?** — **UNDECIDED block 2**
    below. v2's tentative default: drop Phase 1.

### Call-outs — changes most likely to have ripple effects

- **Wire format** (intentional break): Phase 2 sets
  `fec_type = WFB_FEC_VDM_RS_INTERLEAVED (0x2)` whenever `depth > 1`
  (v2.1 R3 corrects v2's `0x1`, which collided with
  `WFB_FEC_VDM_RS`). v1 advertised "wire format unchanged." That is
  now "wire format unchanged at `depth == 1`, new `fec_type` at
  `depth > 1`." This is the minimum break that makes the B1 failure
  mode clean.
- **Phase structure**: if UNDECIDED block 2 resolves to "drop Phase 1",
  v1's five phases collapse to four (0, 2, 3, 4 — renumbered 0, 1, 2,
  3 in the rewrite). The benchmark pass/fail bars in §3.6 do not move.
- **Benchmark substrate**: X_cpu = 10% is now measured on SSC338Q and
  Radxa Zero 3W, not a laptop. If the ARM measurement shows the
  memcpy-bound interleaver legitimately exceeds 10%, v2 permits
  revising the bar to 15% *on ARM* with the delta recorded.
- **Stats contract versioning**: the RX `PKT` record gains three
  trailing fields (#12-14). Existing positional parsers keeping 11
  fields will silently ignore the tail. A new contract version marker
  is emitted on each `SESSION` (see §2 Phase 4).

### Things the reviewer got right — v2 does not change these

- Every source line citation in review §4 is correct. `rx.cpp:795-813`
  flush, `tx.cpp:656-659` FEC-only rejection, `rx.cpp:488-522`
  dump_stats, `rx.cpp:698` edge-triggered SESSION, `tx.cpp:874-882`
  CMD_SET_FEC drain-then-reinit pattern — all verified.
- Option A (two parallel FEC instances) over Option B (UEP-RS inside
  one block) for Phase 3 — correct engineering call; preserved.
- Latency-budget math in §4.2 — sound; owner confirmed "reasonable for
  FPV flying, not aggressive but not slow either." The 20/30/50 ms
  tiering stays.

### UNDECIDED — options for the branch owner

**UNDECIDED block 1 — Rekey frequency in real flight.**
Sets how much the B5 drain-before-rekey cost actually matters.

- **1A (recommended default)** — "Once per takeoff / once per radio
  setting change." Cost of drain-before-rekey is cosmetic (tens of ms,
  once). Adaptive-link daemon clamps its own rekey interval ≥ 2 s as
  hysteresis. Minimum engineering; fits "weak in C" constraint.
- **1B** — "Adaptive rekeys every few seconds." Drain cost stacks; need
  to avoid it. Add a 1-byte key-epoch field to `wblock_hdr_t` (eats one
  bit of `fragment_idx` or widens the header) and have RX keep the
  previous `session_key` alive for `(n-1) * depth` packet times. More
  C code; more risk; more wire churn.
- **1C** — Carry `(k, n, depth)` changes in a session-TLV "refresh"
  packet that re-uses the current session_key instead of rotating it.
  Loses the key-freshness property of `init_session` but avoids the
  outage entirely. Requires a new session packet subtype.
- **v2 default if no answer:** 1A, with a hard-coded 2 s minimum rekey
  interval in the adaptive daemon (not in wfb-ng — see `adaptive-link.md`).
- **v2.1 decision: 1C.** Real flight has 200 ms minimum interval between
  `(k, n, depth)` changes (obstacle transitions, range-driven bitrate
  adjustments). Under 1A at D=4 that would cost ~20% of airtime on
  drain stalls exactly when the link is struggling. 1C
  (`session_key` stays constant; new session-refresh TLV for
  `(k, n, depth)`) eliminates per-rekey drain. Key-freshness loss is
  accepted per §4.8. See v2.1 R1.

**UNDECIDED block 2 — Keep or drop Phase 1 (side-car MVP)?**

- **2A (keep)** — Pros: some end-to-end exercise on real hardware
  before in-tree work. Cons: v1 itself admits Phase 1 "cannot measure
  interaction with zfex block framing." Side-cars operate on UDP
  datagrams, which are whole pre-FEC RTP units — they cannot interleave
  fragments *within* an FEC block, which is the thing Phase 2 ships.
  Two new binaries, lots of new C, added latency.
- **2B (drop — recommended default)** — Pros: the Phase 0 harness
  already validates the fragment-level interleaver in-process, which
  is the correct abstraction level. Less C to write (owner is weak in
  C). First on-wire exercise lands in Phase 2, which is where the
  real risk was going to be anyway. Cons: Phase 2 is the first moment
  the interleaver touches production code.
- **v2 default if no answer:** 2B. Phase 0 → Phase 2 directly.

**Settled:** **1C** (v2.1 R1, revised up from v2's 1A default — see the
v2.1 revision block; 200 ms rekey intervals in real flight made 1A
cost-prohibitive) and **2B**. Phase numbering reflects dropping the
side-car MVP: v1's Phase 2 is now Phase 1, v1's Phase 3 is now Phase 2,
v1's Phase 4 is now Phase 3.

---

**Features under design, in priority order:**

1. Convolutional interleaving over FEC blocks — protect against burst
   losses by spreading symbols of each FEC block across time.
2. Unequal error protection (UEP) for NAL-unit classes — stronger FEC
   for SPS / PPS / IDR, weaker FEC for P-frame residuals.
3. Control-plane API for an external adaptive-link process — a small
   addition inside wfb-ng (interleave-depth set/get plus a stable
   stats contract) so a separate process can drive all runtime knobs.
   The adaptive process itself (policy, encoder / radio / OS
   backends, latency-budget enforcement) is specified separately in
   [adaptive-link.md](adaptive-link.md).

Each feature must be independently shippable, default-OFF, and
revertible via a config flag. `depth == 1` keeps the on-air wire format
bit-compatible with stock receivers. `depth > 1` deliberately breaks
stock-RX compatibility via a new `fec_type` value (see §4.1).

---

## 1. Current system — summary (verified against source)

Full file-by-file analysis is in the session transcript that produced
v1; the load-bearing facts the design depends on are:

- **FEC is per-block, systematic Vandermonde Reed–Solomon** via zfex,
  `(k, n) = (8, 12)` by default, changeable at runtime via `CMD_SET_FEC`
  on a localhost UDP control socket ([tx.cpp:851-887](../../src/tx.cpp#L851-L887)).
- **Wire nonce** is a 56-bit `block_idx` + 8-bit `fragment_idx`, packed
  as big-endian `uint64_t` inside `wblock_hdr_t` ([wifibroadcast.hpp:241-244](../../src/wifibroadcast.hpp#L241-L244)).
- **Primary vs. parity is not flagged on the wire**; RX infers from
  `fragment_idx < k` ([rx.cpp:895-937](../../src/rx.cpp#L895-L937)).
- **Both TX and RX are single-threaded** around `poll()` loops, no
  mutexes on the FEC path.
- **RX has a 40-slot block ring** ([rx.hpp:87](../../src/rx.hpp#L87)) and no per-block timer — the
  only deadline is ring overflow ([rx.cpp:430-453](../../src/rx.cpp#L430-L453)).
- **The pipeline is payload-agnostic** — nothing inspects RTP or NAL
  units today ([tx.cpp:651](../../src/tx.cpp#L651), [rx.cpp:859](../../src/rx.cpp#L859)).
- **RX exposes RSSI/SNR/FEC-recovery counters via stdout `IPC_MSG`**
  ([rx.cpp:488-522](../../src/rx.cpp#L488-L522)). A bidirectional return link already exists
  via the stock `mavlink` and `tunnel` streams defined in
  [wfb_ng/conf/master.cfg](../../wfb_ng/conf/master.cfg#L132-L154), so Phase 3 does not need
  new air-link plumbing.
- **`fec_test.cpp` is a Catch2 benchmark** harness we can extend ([src/fec_test.cpp](../../src/fec_test.cpp)).
- **`fec_timeout` defaults to 0 everywhere** ([wfb_ng/conf/master.cfg](../../wfb_ng/conf/master.cfg#L241) and siblings);
  owner confirms never used in the field.

### 1.1 Three load-bearing RX invariants that the design must respect

**Invariant A — premature flush on later-block completion.**
At [rx.cpp:795-813](../../src/rx.cpp#L795-L813), when any block B reaches k fragments, every
older incomplete block in the ring is force-flushed in one shot
(whatever primaries arrived are emitted, the rest are lost). Under
convolutional interleaving, fragments of block N are deliberately
delayed — they arrive **after** fragments of block N+1, N+2, …, N+D-1.
So in a lossless channel with interleaving enabled, block N+D-1 will
typically reach k **before** block N does, and the existing flush will
discard block N's still-in-transit fragments.

> **Consequence:** Phase 1 *must* replace this flush path with a
> deadline-driven scheme. The early-emit fast path at [rx.cpp:774-792](../../src/rx.cpp#L774-L792)
> is also touched — see §4.7 for the full state machine.

**Invariant B — far-future `block_idx` clamp.**
At [rx.cpp:471](../../src/rx.cpp#L471), when a fragment with `block_idx` far beyond
`last_known_block` arrives, `new_blocks` is clamped to `RX_RING_SIZE`
and intermediate block state is lost. Interleaver depth × loss reach
must stay well below `RX_RING_SIZE`.

> **Consequence:** Interleaver depth D has a hard upper bound well
> below `RX_RING_SIZE`. In practice D is bounded tighter by the FPV
> latency budget (§4.2): D ≤ 3 for bulk / D ≤ 4 for critical at 60 fps,
> roughly one step less at 90 fps. v2 bumps `RX_RING_SIZE` 40 → 64
> when interleave is active; see §4.2.

**Invariant C — session rekey wipes in-flight state.**
At [rx.cpp:691-699](../../src/rx.cpp#L691-L699), a new session key triggers `deinit_fec()` /
`init_fec()` and installs a fresh `session_key`. Any packet already in
flight under the old key fails AEAD decrypt at [rx.cpp:723-727](../../src/rx.cpp#L723-L727)
and is counted as `count_p_dec_err`. Today blast radius ≈ 1 open block;
with depth D it would be D blocks.

> **Consequence (v2.1 R1 update):** Under 1C, `session_key` does not
> rotate at runtime, so Invariant C does not fire on `CMD_SET_FEC` /
> `CMD_SET_INTERLEAVE_DEPTH`. The "blast radius D blocks" concern is
> resolved by not rekeying, rather than by gating rekey behind a
> drain. The Invariant C code path still exists for process start /
> restart, where it is correct. See §4.7.

---

## 2. Phased plan

Each phase lists: goal, files touched (add vs. modify), risks, rollback
plan, and verification.

### Phase 0 — Benchmark harness (standalone, no production code touched)

- **Goal:** Repeatable A/B harness for the new interleaver against stock
  FEC under configurable channel models. Produces CSV of metrics over
  parameter sweeps. No binary behavior changes.
- **Files added:**
  - `src/fec_bench/channel_model.hpp` — uniform, Gilbert–Elliott,
    periodic loss simulators (header-only).
  - `src/fec_bench/interleaver.hpp` — reference convolutional
    interleaver (software-only, in-process, no wire traffic). Must
    produce the same schedule the Phase 1 production code will emit;
    the schedule is a *shared spec*, not a parallel implementation.
  - `src/fec_bench/bench_harness.cpp` — Catch2 `BENCHMARK` + parameter
    sweep driver.
  - `src/fec_bench/interleaver_schedule_test.cpp` — Catch2 unit tests
    that pin the schedule (see §3.8).
  - `scripts/fec_bench_report.py` — CSV → summary table.
  - This document.
- **Files modified:**
  - `Makefile` — add `fec_bench` target, opt-in, not tied to `all`.
- **Risk:** None to the live link — this code never runs in production
  builds.
- **Rollback:** `git revert` of the Phase 0 PR.
- **Verification:** `make wfb_tx wfb_rx` builds unchanged; existing
  `fec_test` still passes. `make fec_bench && ./fec_bench` runs on a
  laptop *and* on both ARM targets (SSC338Q, Radxa Zero 3W) and writes
  a non-empty CSV.

### Phase 1 — In-tree integration behind `--interleave-depth N` flag

- **Goal:** Integrate convolutional interleaving into `wfb_tx` and
  `wfb_rx`, default depth `N = 1` (no interleaving, identical to
  today). Any `N > 1` activates the new path and sets a distinct
  `fec_type`.
- **Files modified (tentative):**
  - [src/tx.cpp](../../src/tx.cpp) — add `interleave_depth` argument; when > 1, push
    computed `fec_encode_simd` output into an interleave buffer instead
    of calling `send_block_fragment` directly. Emit on the interleave
    schedule. Extend `CMD_SET_FEC` drain idiom to cover the interleaver
    (drain before `init_session`; see §4.7).
  - [src/rx.cpp](../../src/rx.cpp) — replace the flush path at lines 795-813 with the
    deadline-driven state machine in §4.7. Add a per-block deadline
    timer. Gate the early-emit fast path at 774-792 on `depth == 1`.
    Emit `SESSION` once per `log_interval` in addition to the existing
    on-change emission (B2 bootstrap). Add three new counters
    (`count_bursts_recovered`, `count_holdoff_fired`,
    `count_late_after_deadline`) and append them to the RX `PKT`
    record.
  - [src/wifibroadcast.hpp](../../src/wifibroadcast.hpp) — add `WFB_FEC_VDM_RS_INTERLEAVED = 0x2`
    (v2.1 R3) to the `fec_type` enum. Add a new TLV attribute id
    `TLV_INTERLEAVE_DEPTH` (uint8_t value) in `wsession_data_t.tags`
    so RX can read the depth from session state.
  - [src/tx_cmd.c](../../src/tx_cmd.c) / `tx_cmd.h` — add
    `CMD_SET_INTERLEAVE_DEPTH` / `CMD_GET_INTERLEAVE_DEPTH`. Semantics
    under v2.1 R1 (1C): close the open FEC block, drain the
    interleaver, broadcast a session-refresh TLV on the existing
    `session_key` carrying the new `(k, n, depth)`. No `init_session`,
    no new `session_key`.
  - Config validation at TX startup: refuse to launch if
    `depth > 1 && fec_timeout > 0` (owner confirms this combination is
    not used in the field; simplest to fail fast than to support it).
  - Config validation at TX startup: refuse `depth > 1 && fec_n > 32`
    (memory footprint cap; see §4.2).
- **Files added:**
  - `src/interleaver.hpp`, `src/interleaver.cpp` — TX-side interleave
    buffer + schedule; RX-side de-interleave buffer + deadline state.
- **Wire format:**
  - `depth == 1`: **unchanged** from master. Enforced by the pcap
    replay test in §3.8.
  - `depth > 1`: fragments from different blocks are interleaved on
    the wire; each fragment still carries its own
    `(block_idx, fragment_idx)` nonce; **`fec_type` is set to
    `WFB_FEC_VDM_RS_INTERLEAVED`** in the session packet. A stock RX
    rejects a session with an unknown `fec_type` cleanly instead of
    silently scrambling primaries (B1 resolution).
- **Risk hierarchy:**
  1. **RX flush-path replacement** ([rx.cpp:795-813](../../src/rx.cpp#L795-L813)) — biggest
     correctness risk. Must preserve existing behavior byte-for-byte
     when `depth == 1`. §4.7 specifies the state machine; §3.8
     specifies the pcap replay that pins the `depth == 1` path.
  2. **Latency regression** — worst-case RX latency grows by
     `(depth - 1) × avg_block_duration`. §4.2 sets the ceilings.
  3. **Ring overflow** — bumping `RX_RING_SIZE` to 64 behind the flag,
     with a build assert tying it to max-depth × safety-factor. See
     §4.5 item 8.
  4. **Refresh stall** — on depth or (k, n) change, TX stalls for
     ≤ 1 × block_duration (just long enough to close the open FEC
     block with FEC-only closers and let the interleaver empty). No
     `session_key` rotation (v2.1 R1). At 200 ms minimum refresh
     interval and 10 ms block_duration, worst-case airtime overhead
     ≤ 5%.
- **Rollback:** `--interleave-depth 1` (or omit the flag). Every new
  code path is inside `if (depth > 1)` branches; default behavior is
  byte-identical.
- **Verification:**
  1. `depth == 1` path: pcap replay test diffs TX UDP output against
     `master` byte-for-byte.
  2. Existing `fec_test` unchanged.
  3. Phase 0 harness at depths 1, 2, 4, 8 meets the §3.6 pass bars on
     *both* ARM targets.
  4. Adaptive depth change (`CMD_SET_INTERLEAVE_DEPTH`) on a live loop
     shows no `count_p_dec_err` spike at RX (drain-before-rekey
     invariant).
  5. ASan+UBSan CI run of `fec_test` under injected loss (see §3.8)
     passes clean.

### Phase 2 — UEP: two parallel FEC streams (design only in this doc)

- **Goal:** SPS / PPS / IDR slices get `(k=4, n=12)` (200% redundancy);
  P-frame residuals get `(k=8, n=10)` (25% redundancy). Same channel,
  two `port_number`s. **UEP is video-only** — `mavlink` and `tunnel`
  are opaque byte streams and stay on stock `(k, n)`.
- **Recommended architecture (Option A):**
  - Run two `wfb_tx` instances, differing only in port_number and
    `(k, n)`, fed by an upstream classifier.
  - Classifier is a new side-car binary (`wfb_nal_classify`) that
    reads RTP-over-UDP, parses NAL units, routes to the appropriate
    TX ingress port. Keeps `wfb_tx` payload-agnostic.
  - On RX, run two `wfb_rx` instances, one per port, feeding a NAL
    merger side-car that reassembles the original RTP stream in
    timestamp order.
- **Alternative considered (Option B):** UEP-RS inside a single FEC
  block. Requires a code not in zfex. Rejected as disproportionate
  scope; revisit only if Option A proves insufficient.
- **Risks (C-level and higher):**
  1. **NAL parsing at the classifier** — H.264 NAL unit types are
     stable (RFC 6184); H.265 (RFC 7798) differs. Parameterize on
     encoder profile.
  2. **Fragmented NAL units** — FU-A / FU-B fragments must all go to
     the same priority class, or the merger cannot reassemble. The
     classifier must inspect FU header, not just the outer NAL type.
  3. **RTP timestamp monotonicity across two streams** — the merger
     reorders by timestamp, not arrival order; reorder-buffer depth is
     bounded by the difference in FEC latency between the two classes.
  4. **Session epoch skew** — two independent `wfb_tx` processes have
     independent session-key epochs. Benign today.
  5. **Encoder coupling — keep-warm path.** During long IDR gaps the
     high-priority stream is nearly idle. The classifier cannot open
     a fresh block with a `WFB_PACKET_FEC_ONLY` packet
     ([tx.cpp:656-659](../../src/tx.cpp#L656-L659) rejects `FEC_ONLY`
     at `fragment_idx == 0`). Correct pattern: classifier sends at
     least one real data byte (even a 1-byte heartbeat NAL) to open
     a block, then may close it with FEC-only. Updated from v1.
- **Open questions to resolve before starting Phase 2:**
  - Encoder ground truth (H.264 vs. H.265, AVC vs. Annex-B, RTP
    packetization mode).
  - Classifier placement — ahead of GStreamer RTSP or inline in a
    modified `wfb_rtsp`?
  - Is it acceptable to force-key-frame on a link-quality drop?

### Phase 3 — Control-plane API for an external adaptive-link process

- **Goal:** Expose a complete, stable control interface so an external
  "adaptive-link" daemon can drive every runtime knob in wfb-ng without
  requiring C changes in `wfb_tx` / `wfb_rx`. The policy engine itself
  (state machine, hysteresis, latency-budget enforcement, UEP
  coordination, encoder/radio/OS backends) is out of scope for this
  document; see [adaptive-link.md](adaptive-link.md).
- **Framing (new in v2):** interleaving is the *fast reflex* —
  burst-response on a per-block timescale (ms). Adaptive depth is the
  *slow trim* — trend response across hundreds of ms through the
  tunnel air-link round trip. Do not conflate the two; they operate on
  different timescales and serve different failure modes.
- **This phase's sole deliverable inside wfb-ng:**
  - `CMD_SET_INTERLEAVE_DEPTH` / `CMD_GET_INTERLEAVE_DEPTH` (landed in
    Phase 1 alongside the interleaver; re-asserted as part of the
    stable external contract here).
  - Commit the stats output format as a stable external contract
    (contract table in §2.1 below).

#### What wfb-ng already exposes

`tx_cmd` already implements a request/response UDP control socket
([src/tx_cmd.h](../../src/tx_cmd.h)) with correlation via `req_id` and a
return code in `cmd_resp_t.rc`. Commands today:

| Command | Covers |
|---|---|
| `CMD_SET_FEC` / `CMD_GET_FEC` | `(k, n)` |
| `CMD_SET_RADIO` / `CMD_GET_RADIO` | `stbc`, `ldpc`, `short_gi`, `bandwidth`, `mcs_index`, `vht_mode`, `vht_nss` |

**MCS and guard interval are already covered** by `CMD_SET_RADIO`.
No new transport is needed.

#### What Phase 3 adds to wfb-ng

| Addition | Lands in | Notes |
|---|---|---|
| `CMD_SET_INTERLEAVE_DEPTH` / `CMD_GET_INTERLEAVE_DEPTH` | Phase 1 | Drain + rekey, identical shape to `CMD_SET_FEC`. Not "atomic at next block" — the wire schedule changes, so a rekey is required (B4). |
| Stable IPC_MSG contract (§2.1) | Phase 3 | Commitment not to break the format silently. Version marker emitted on `SESSION`. |
| `SESSION` also emitted once per `log_interval` | Phase 1 (one-line rx.cpp change) | B2 bootstrap — daemon can read `(k, n, fec_type, depth)` on connect without waiting for a rekey. |
| (Optional) `CMD_GET_STATS` on RX control socket | Deferred | Only if stdout parsing proves fragile. |

#### 2.1 Stable IPC_MSG contract (rewritten from v1)

All records are tab-separated. Leading column is `ts_ms` (uint64
millisecond timestamp). Second column is the record type. Remaining
columns are record-specific.

**RX side** (emitted by `wfb_rx` / Aggregator):

```
<ts_ms> \t RX_ANT  \t <freq>:<mcs>:<bw> \t <ant_id_hex> \t <count>:<rssi_min>:<rssi_avg>:<rssi_max>:<snr_min>:<snr_avg>:<snr_max>
<ts_ms> \t PKT     \t <count_all>:<bytes_all>:<dec_err>:<session>:<data>:<uniq>:<fec_recovered>:<lost>:<bad>:<outgoing>:<outgoing_bytes>:<bursts_recovered>:<holdoff_fired>:<late_after_deadline>
<ts_ms> \t SESSION \t <epoch>:<fec_type>:<k>:<n>[:<interleave_depth>:<contract_version>]
```

Emission schedule:

- `RX_ANT`, `PKT` — every `log_interval` ms (default 1000), emitted by
  `Aggregator::dump_stats()` at [rx.cpp:488-522](../../src/rx.cpp#L488-L522).
- `SESSION` — v1: edge-triggered on session-key change only
  ([rx.cpp:698](../../src/rx.cpp#L698)). **v2: also emitted once per
  `log_interval` for bootstrap** (B2).
- `SESSION` in v2 carries two additional trailing fields:
  `interleave_depth` (uint8 from the TLV, 1 if absent) and
  `contract_version` (uint8, starts at `2`). Parsers keying on the
  first four fields remain compatible.

**TX side** (emitted by `wfb_tx`):

```
<ts_ms> \t TX_ANT \t <ant_id_hex> \t <count>:<lat_min>:<lat_avg>:<lat_max>
<ts_ms> \t PKT    \t <fec_timeouts>:<p_incoming>:<b_incoming>:<p_injected>:<b_injected>:<p_dropped>:<p_truncated>
<ts_ms> \t LISTEN_UDP         \t <port>:<iface_id>
<ts_ms> \t LISTEN_UDP_END
<ts_ms> \t LISTEN_UDP_CONTROL \t <control_port>
<ts_ms> \t LISTEN_UNIX        \t <socket_path>:<iface_id>
<ts_ms> \t LISTEN_UNIX_END
```

Note: TX-side `PKT` has **7** fields; RX-side `PKT` has **14** (11 in
v1 + 3 new counters). They share a record type name but differ in
shape. The adaptive daemon distinguishes them by process, not by field
count.

**Stability commitment:** no field reorder, no delimiter change, no
semantic reinterpretation of existing fields without a
`contract_version` bump. New fields may be appended at the end of any
record. The `contract_version` field on `SESSION` is authoritative.

#### What stays out of scope for wfb-ng (lives in `adaptive-link.md`)

- **TX power:** driver-level (`iw dev <iface> set txpower`).
- **Encoder controls:** bitrate, GOP length, ROI / foveated encoding,
  fps, IDR-on-command.
- **Link-health policy:** state machine, hysteresis, burstiness
  detection, refresh cooldown (v2.1 R1 sets the minimum refresh
  interval at 200 ms; adaptive-link may impose higher hysteresis),
  oscillation detector, watchdog, latency-budget enforcement.
- **`[link_adapt]` config section.**
- **Stream enumeration:** the adaptive daemon reads `master.cfg`.

---

## 3. Benchmark plan — Phase 0 in detail

This is the most important phase. Everything else is justified by its
numbers.

### 3.1 Harness architecture

A standalone Catch2 binary `fec_bench` that:

1. Allocates a (k, n) zfex codec, mirroring [src/fec_test.cpp](../../src/fec_test.cpp).
2. Generates a reference sequence of `NUM_BLOCKS` FEC blocks with
   known payload per fragment.
3. Feeds encoded fragments through a **channel model** (§3.2).
4. For each config, runs two pipelines side by side:
   - **Baseline:** stock behavior — fragments in block-sequential
     order into a software replica of the RX-ring logic.
   - **Interleaved:** same payloads through a **software convolutional
     interleaver** of depth D (§3.3), then through the channel, then
     through a de-interleaver, then the same RX-ring replica.
5. Collects metrics (§3.4) per config and appends one CSV row per run.

### 3.2 Channel models (in `channel_model.hpp`)

Three models, each a pure `bool drop(packet_index)` function:

1. **Uniform random loss** — Bernoulli(p). Sweeps: p ∈ {0.01, 0.05,
   0.10, 0.20, 0.30}.
2. **Gilbert–Elliott two-state burst loss** — good-state p_g ≈ 0,
   bad-state p_b ≈ 1, transition probabilities tuning mean burst
   length and mean gap. Sweeps: mean burst ∈ {2, 5, 10, 20};
   mean gap ∈ {100, 1000}.
3. **Periodic loss** — every P-th fragment dropped. Sweeps: P ∈ {5,
   10, 20} (worst case for short interleavers).

Seeded for reproducibility.

### 3.3 Software block interleaver (in `src/bench/interleaver.hpp`)

(v2.1 R2: the original v2 text called for a "triangular convolutional"
Forney interleaver. §4.2's latency math only balances for a block
(matrix) interleaver, so v2.1 switches to block. Same burst-dispersal
property for burst length ≤ D, lower steady-state memory
`O(D · n)` vs Forney's `O(D · n² / 2)`.)

Standard block interleaver with:

- D × n grid per "D-frame" (D = depth, n = fec_n).
- Row r of the grid = block_idx `b mod D`; column f = fragment_idx.
- Emit order: column-major (fragment 0 of each of D blocks, then
  fragment 1 of each, ..., then fragment n-1 of each).

Formula (derived in [src/bench/interleaver.hpp](../../src/bench/interleaver.hpp)):

```
frame          = b / D
row_in_frame   = b mod D
slot_in_frame  = f * D + row_in_frame
absolute_slot  = frame * (D * n) + slot_in_frame
```

For D = 1 this degenerates to `slot = b * n + f` — identical to
master's wire order, which is what keeps `--interleave-depth 1`
byte-identical. Any burst of up to D consecutive lost slots hits at
most 1 fragment per FEC block (the whole point).

This schedule is the **shared spec** between Phase 0 and Phase 1.
Phase 1's production interleaver must emit fragments in the same order
for equivalent inputs; this is pinned by the unit test in §3.8.

### 3.4 Metrics (one CSV row per config)

```
channel_model, p_or_mean_burst, k, n, depth, blocks,
    block_recovery_rate,
    residual_packet_loss,
    latency_p50_ms, latency_p95_ms, latency_p99_ms,
    cpu_us_per_block_tx,
    cpu_us_per_block_rx,
    mem_bytes_interleaver,
    target_platform,      # laptop | ssc338q | radxa_zero_3w
    seed
```

### 3.5 Parameter sweeps and target platforms

Cartesian product of:

- `(k, n) ∈ {(8, 12), (4, 8), (4, 12), (16, 20)}`
- `depth ∈ {1, 2, 4, 8, 16}` (`depth=1` = baseline)
- Each channel model across its own sweep range.
- `NUM_BLOCKS = 10 000` per config; `seed` varied across 3 runs.

**Target platforms** (new in v2):

- `laptop` — any x86_64 dev machine. For regression detection across
  commits. Fast iteration.
- `ssc338q` — the drone-side SoC (runcam wifilink2 board). TX-side CPU
  numbers are read off this platform.
- `radxa_zero_3w` — ground-station SBC. RX-side CPU numbers are read
  off this platform.

At ≈ 1 ms per block encode+decode+simulate, 10 000 × ~120 configs × 3
seeds ≈ 1 hour on a laptop, proportionally slower on ARM.

### 3.6 Pass / fail criteria for Phase 1 go-ahead

Concrete numbers:

- **X_latency = 20%**: interleaver at depth 2 in zero-loss conditions
  may not increase RX fragment-delivery latency p95 by more than 20%
  relative to baseline at the same (k, n).
- **X_cpu_arm = 15%**: CPU cost per block on the ARM targets may not
  rise by more than 15% relative to baseline. v2 widens v1's 10% bar
  *only* on ARM, in recognition that memcpy-bound workloads have a
  larger ARM/x86 delta than pure compute. Laptop bar stays at 10%.
- **X_cpu_laptop = 10%**: laptop CPU cost may not rise by more than
  10% — used for regression detection only.
- **X_uniform = 0%**: block recovery rate under uniform loss must not
  regress at the same (k, n). Any regression is a correctness bug.
- **Y_burst = 3×**: at a Gilbert–Elliott channel with mean burst = 5
  and 5% average loss, `depth = 4` block-recovery rate must be at
  least 3× the baseline.

**Pass criterion for Phase 0 → Phase 1:** all five bars met across
all swept (k, n), on both ARM targets. **Fail criterion:** any of
X_latency, X_cpu_arm, X_cpu_laptop, X_uniform regresses; or Y_burst is
below 2× at the representative operating point.

### 3.7 Reporting

`scripts/fec_bench_report.py` reads the CSV and prints:

- Per-platform go / no-go per criterion.
- Burst-recovery improvement factor vs. depth, per (k, n).
- CSV is retained so we can diff runs across commits.

### 3.8 Test coverage (new in v2)

Review non-blocking #4. Three distinct layers:

1. **Interleaver schedule unit test.** Catch2; pins the block
   interleaver schedule bit-for-bit (v2.1 R2: was "triangular
   convolutional"). The same test runs in Phase 1 against the
   production interleaver — same expected output, different
   implementation. Prevents drift between the reference and the
   shipping code. Lands in Phase 0.5 (v2.1 R4) rather than Phase 0.
2. **pcap replay test** (Phase 1). Captured TX UDP output from a
   `master` build, replayed through the branch build with
   `--interleave-depth 1`, asserted byte-identical. Guards the
   default-OFF wire invariant.
3. **ASan+UBSan CI job** (Phase 1). Runs `fec_test` and a scripted
   loss pattern under `-fsanitize=address,undefined`. Catches the
   buffer-lifetime and alignment bugs enumerated in §4.5.

---

## 4. Risks and open questions

### 4.1 Wire-format compatibility (B1 resolution)

- **Default OFF:** at `depth == 1` every byte on the wire is identical
  to master. Enforced by the pcap replay test (§3.8).
- **`depth > 1` deliberately breaks stock RX.** Per owner direction,
  we do not try to preserve compatibility. Instead:
  - `wsession_data_t.fec_type = WFB_FEC_VDM_RS_INTERLEAVED (0x2)`
    (v2.1 R3). A
    stock RX rejects the session in its session-packet handler on
    unknown `fec_type`, cleanly and visibly, instead of silently
    scrambling primaries via the `has_fragments == fec_k` flush.
  - `wsession_data_t.tags` carries a `TLV_INTERLEAVE_DEPTH` uint8
    attribute so a v2-aware RX can self-configure without a CLI flag.
- **No "in principle decode" claim.** v1's language here was wrong.

### 4.2 Latency budget

FPV is latency-sensitive. Air-link latency adds directly to
glass-to-glass. Frame intervals:

- 60 fps → 16.7 ms
- 90 fps → 11.1 ms

Air-link budget (owner confirmed "reasonable for FPV, not aggressive
but not slow"):

| Condition | Budget | Reasoning |
|---|---|---|
| Target (good link) | ≤ 20 ms | ~1 frame at 60fps |
| Degraded | ≤ 30 ms | ~2 frames at 60fps |
| Hard cap | ≤ 50 ms | ~3 frames at 60fps; pilot feels lag |

**The Phase 3 controller must refuse any `(k, n)` or depth change that
would push predicted latency above the hard cap.**

#### Latency model

```
latency_block = block_fill_time + block_airtime + fec_decode_time
block_fill_time   = k × inter_packet_interval
block_airtime     = n × per_packet_airtime
fec_decode_time   ≈ 1 ms for (k=8, n=12) at zfex SIMD
latency_total     = latency_block + (depth − 1) × block_duration
```

#### Worked example — 8 Mb/s H.264 on 8812au @ MCS7 40 MHz HT

Per-packet airtime ≈ 80 µs, inter-packet interval ≈ 1.4 ms.

**Bulk stream (k = 8):**

| `(k, n)` | depth | fill (ms) | air (ms) | +interleave (ms) | **total (ms)** |
|---|---|---|---|---|---|
| (8, 10) | 1 | 11.2 | 0.8 | 0 | **12** |
| (8, 12) | 1 | 11.2 | 1.0 | 0 | **12** |
| (8, 12) | 2 | 11.2 | 1.0 | 12 | **24** |
| (8, 14) | 2 | 11.2 | 1.1 | 12 | **25** |
| (8, 14) | 3 | 11.2 | 1.1 | 24 | **37** |
| (8, 14) | 4 | 11.2 | 1.1 | 36 | **49** — at the cap |

**Critical stream (k = 2):**

| `(k, n)` | depth | fill (ms) | air (ms) | +interleave (ms) | **total (ms)** |
|---|---|---|---|---|---|
| (2, 6)  | 1 | 2.8 | 0.5 | 0 | **3** |
| (2, 10) | 2 | 2.8 | 0.8 | 4 | **8** |
| (2, 10) | 4 | 2.8 | 0.8 | 12 | **16** |

#### Implied depth ceilings (tuned to the 50 ms hard cap)

| Stream | 60 fps | 90 fps |
|---|---|---|
| Critical | 4 | 3 |
| Bulk | 3 | 2 |

The per-airframe `[link_adapt]` profile sets the takeoff ceiling; the
applier enforces it independently as defense in depth.

#### Memory footprint of the `RX_RING_SIZE` bump (review non-blocking #7)

With `RX_RING_SIZE` raised 40 → 64 when interleave is active:

- Typical `fec_n = 16`, `MAX_FEC_PAYLOAD` ≈ 1466: 64 × 16 × 1466 ≈ 1.5 MB.
- Pathological `fec_n = 256`: 64 × 256 × 1466 ≈ 24 MB.

Radxa Zero 3W is 1 GB+; fine at either extreme. v2 adds a runtime
refusal: `depth > 1 && fec_n > 32` fails at startup with an explicit
error. This caps worst-case at ~3 MB.

### 4.3 Clock / sequence-counter interactions

- `packet_seq = block_idx * fec_k + fragment_idx` ([rx.cpp:865](../../src/rx.cpp#L865)) is
  `uint32_t` and wraps every ~70 days of continuous run at k=8 /
  714 pps (review non-blocking #1). At wrap, one spurious "packets
  lost" count will fire. Not fixing; individual FPV flights are 5 min
  max. (v2.1 clarification: v2 said "sessions are minutes between
  rekeys," which was wrong — rekeys can fire as often as every 200 ms,
  making the old framing misleading. What matters for `packet_seq`
  wrap is wall-clock flight time, not session length. 5-min flight
  ≪ 70-day wrap, so the wrap is not reachable in operation.)
- The RX deadline timer uses `CLOCK_MONOTONIC`, consistent with
  [wifibroadcast.cpp:50-64](../../src/wifibroadcast.cpp#L50-L64).
- No distributed-clock requirement; RX does not need TX's clock.

### 4.4 Safety-relevant considerations for flight

- `depth > 1` defaults off, requires explicit opt-in per airframe.
- The adaptive controller has a **maximum-depth ceiling** that is
  configured at takeoff and cannot be raised in flight. Depth can drop
  toward 1 at any time.
- On catastrophic feedback oscillation, fall back to a fixed safe
  depth rather than unbounded adjustment.
- UEP: misclassifying a NAL slice as low-priority on a loss event can
  lose the I-frame for the next GOP. The classifier must **fail-safe
  toward high-priority** on any parsing uncertainty.

### 4.5 C-level gotchas to watch for in code review

These are the patterns I expect to see and want the reviewer (and
future me, who is not fluent in C) to flag:

1. **Alignment of interleaver buffers.** Existing TX block slots are
   `posix_memalign`'d to `ZFEX_SIMD_ALIGNMENT`. Any interleaver buffer
   that holds a pointer passed to `fec_encode_simd` /
   `fec_decode_simd` must keep that alignment. A bare `new uint8_t[...]`
   will slow the SIMD kernel and may SIGBUS on strict-alignment ARM
   (both our ARM targets are strict-alignment sensitive in practice).
2. **Packed-struct casts.** `wblock_hdr_t *h = (wblock_hdr_t*)buf;`
   patterns in [tx.cpp:625](../../src/tx.cpp#L625) and [rx.cpp:715](../../src/rx.cpp#L715) — any new code doing the
   same must cast only over a buffer that was freshly allocated or
   `memcpy`'d into.
3. **Endianness.** All multi-byte wire fields go through `htobe*` /
   `be*toh`. The 56+8 nonce format in particular is fragile. If any
   future extension widens `fragment_idx`, it crosses a byte boundary
   and the encode/decode helpers must be written as one function and
   audited together. The `TLV_INTERLEAVE_DEPTH` value added in v2 is
   deliberately uint8 to sidestep this.
4. **Pointer arrays into the block.** `fec_encode_simd(fec_p, block,
   block + fec_k, sz)` at [tx.cpp:686](../../src/tx.cpp#L686) and `fec_decode_simd(...)` at
   [rx.cpp:935](../../src/rx.cpp#L935) pass arrays of pointers. The interleaver must not
   rearrange these arrays between encode and inject — RS internal
   bookkeeping assumes position corresponds to fragment index.
5. **Ownership across the interleaver.** Current `inject_packet`
   builds ciphertext in a stack buffer and `sendmsg()`s it immediately
   ([tx.cpp:624-642](../../src/tx.cpp#L624-L642)); if we interleave, the stack buffer goes out
   of scope before the delayed send. We need a ring of heap-owned
   buffers, freed after transmission.
6. **Integer sizing.** `fragment_idx` is 8-bit on the wire; any
   interleaver state indexing past 255 needs a wider local type, and
   the wire encoder must still mask to 8 bits.
7. **Flush-path replacement at [rx.cpp:795-813](../../src/rx.cpp#L795-L813)** — **the single
   riskiest code edit in the project**. Byte-for-byte behavior when
   `depth == 1` is pinned by the pcap replay test (§3.8).
8. **Ring overflow semantics.** Raising `RX_RING_SIZE` 40 → 64 is
   fine for `int32_t` counters; add a `static_assert` tying the
   constant to `MAX_INTERLEAVE_DEPTH × safety_factor`.
9. **`memcpy` into unaligned `wpacket_hdr_t`.** Every access goes
   through `htobe16` / `be16toh`. New code must not dereference
   `wpacket_hdr_t.packet_size` directly as a host-order `uint16_t`.
10. **libsodium AEAD decrypt failure paths.** On decrypt error
    ([rx.cpp:723-727](../../src/rx.cpp#L723-L727)) the packet is discarded. An interleaver
    before decrypt must not leak the ciphertext buffer on this path.
11. **Drain-before-refresh ordering** (v2.1 R1 rewrite of the
    original B5 drain-before-rekey idiom). On `CMD_SET_FEC` or
    `CMD_SET_INTERLEAVE_DEPTH`, TX must: (a) close any open FEC block
    with FEC-only closers (existing idiom at
    [tx.cpp:874](../../src/tx.cpp#L874)); (b) wait for the
    interleaver buffer to fully drain and the last injected packet to
    be `sendmsg`'d; (c) only *then* reconfigure the FEC codec
    in-place (`fec_new` with new `(k, n)`) and the interleaver (new
    D), and broadcast a session-refresh TLV. **No `init_session`, no
    new `session_key`** — that is now the only way to avoid the
    per-rekey airtime cost at 200 ms refresh intervals.

### 4.6 Remaining open questions

- **`fec_timeout`:** Owner reports never using it and the default is 0
  everywhere. Phase 1 refuses `depth > 1 && fec_timeout > 0` at
  startup. If any operator has it enabled and needs it to coexist
  with interleaving, the interleaver would need to treat FEC-only
  closer packets the same as data fragments (they already have valid
  nonces); deferring until asked.
- **NAL classifier placement for Phase 2:** ahead of or inside
  `wfb_rtsp`? Open for Phase 2 kick-off.
- **`services.py` plug-in point for the Phase 2 classifier / merger
  side-cars:** does the existing service framework take a new
  `service_type` cleanly? Confirm before Phase 2 kick-off.
- **Stats aggregator (`wfb-cli` / `api_port`):** handles arbitrary new
  stream names (e.g. `video_critical`, `video_bulk`)? Confirm before
  Phase 2 kick-off.

### 4.7 RX deadline state machine (new in v2 — B3 resolution)

This subsection commits to a concrete mechanism for the flush-path
replacement.

**State carried per ring slot** (in addition to the existing fields):

- `deadline_ts` (uint64, `CLOCK_MONOTONIC` ms). Set to 0 in
  `rx_ring_push` initialization. Set to `now + hold_off_ms` on arrival
  of the *first* fragment for the block (whichever arrives first, not
  necessarily `fragment_idx == 0`).
- `hold_off_ms = ((fec_n - 1) * depth * inter_packet_interval_ms) + slack_ms`,
  where `slack_ms` defaults to 5 ms (tunable; captures OS scheduling
  jitter). For `depth == 1`, `hold_off_ms = 0` and the current
  behavior is byte-identical.

**On fragment arrival for block B at ring slot `ring_idx`:**

1. If `rx_ring[ring_idx].deadline_ts == 0`, set it to
   `now + hold_off_ms`.
2. Fill fragment, increment `has_fragments`, update `fragment_map`.
3. **Early-emit fast path** ([rx.cpp:774-792](../../src/rx.cpp#L774-L792)):
   - If `depth == 1` **and** `ring_idx == rx_ring_front`: the existing
     gap-free emit loop runs unchanged.
   - If `depth > 1`: the early-emit path is **disabled**. All emits
     go through the deadline / completion path below. (This is why
     `depth > 1` adds worst-case latency — we can't emit until we
     know no more fragments are coming for that block.)
4. **Block-complete path** ([rx.cpp:795-813](../../src/rx.cpp#L795-L813) replacement):
   - If `has_fragments == fec_k` for *this* block (enough primaries
     or fec-recoverable): run `apply_fec` if needed, emit fragments
     of this block in order, remove from ring, advance
     `rx_ring_front` *only if this was the front*. If this block is
     ahead of `rx_ring_front`, mark it "ready" but do not flush older
     blocks; they have their own deadlines.

**Periodic deadline sweep** (driven by the main `poll()` loop's
existing per-iteration timing, or a `ppoll` timeout):

1. For `ring_idx` from `rx_ring_front` forward, while
   `rx_ring_alloc > 0`:
   - If the slot is empty, stop.
   - If `deadline_ts != 0 && now >= deadline_ts` **or** slot is marked
     "ready": run `apply_fec` if needed, emit what primaries we have
     (same as current force-flush behavior), remove from ring,
     `count_holdoff_fired += 1` if fired by deadline.
   - Else stop (next deadline is in the future).

**Late-fragment handling:** a fragment that arrives for a block
already flushed increments `count_late_after_deadline` and is dropped.
`get_block_ring_idx` already returns -1 for blocks
`≤ last_known_block` that are no longer in the ring; the new counter
distinguishes "late because already emitted" from "late because
ancient."

**Equivalence at `depth == 1`:** with `hold_off_ms == 0`, the deadline
fires immediately on the first completeness check, so behavior reduces
to the original fast path + force-flush pair. The pcap replay test
(§3.8) enforces byte-identical output.

**TX-side drain idiom** (v2.1 R1 rewrite; supersedes v2's B5-resolution
drain-then-init_session sequence):

1. Existing `CMD_SET_FEC` drain (`while(t->send_packet(NULL, 0,
   WFB_PACKET_FEC_ONLY));`) at [tx.cpp:874](../../src/tx.cpp#L874) closes the open FEC block.
2. **New:** after that, loop on the interleaver's buffer-empty check
   (`while (interleaver.has_pending()) interleaver.pump(send_fd);`)
   until all scheduled fragments have been emitted.
3. Broadcast a session-refresh TLV with the new `(k, n, depth)` on
   the **existing** `session_key`. NO `init_session` call, NO new
   `session_key`. The codec is re-initialised in place
   (`fec_new(new_k, new_n)` replacing the old `fec_t*`) and the
   interleaver reconfigured to the new D.

Bounded stall: ≤ 1 × block_duration (just closing the open block),
independent of D. Rekey cadence no longer bounds the cost because
there is no per-rekey outage to bound.

**Original v2 idiom retained for historical context:** v2 called
`init_session(fec_k, fec_n, depth)` at step 3, regenerating
`session_key`. Under v2.1 R1 this is dropped. An operator who
explicitly *wants* a fresh `session_key` (e.g. for a new-flight
"power cycle") can restart the `wfb_tx` process; there is no runtime
command that rotates the key.

### 4.8 Accepted risks (new in v2)

- **Control-socket authentication** (review non-blocking #6). The
  localhost UDP control socket is unauthenticated today, and owner
  has declared attacks out of scope ("I dont care about attack, it
  will never happen"). `CMD_SET_INTERLEAVE_DEPTH` widens the blast
  radius of a localhost compromise marginally — a malicious localhost
  process could induce latency/loss by forcing frequent depth changes.
  Under v2.1 R1 each change costs only a small drain (≤ 1
  block-duration), so the worst-case induced loss is modest.
  Accepted.
- **`session_key` freshness lost (v2.1 R1).** Under 1C, the
  `session_key` is set once at TX process start and reused for the
  life of the process. A future flight-long adversary with enough
  known-plaintext could in principle attack key integrity — but
  owner's §4.8 first bullet already accepts that threat model is not
  in scope. Revisit if the deployment model gains real attackers.
- **`fec_timeout > 0` incompatibility.** Refused at startup when
  `depth > 1`. Simpler than supporting the mixed mode; owner confirms
  no operator uses `fec_timeout`.
- **Stock-RX incompatibility at `depth > 1`.** By design (B1). New
  `fec_type` ensures the break is clean, not silent.

---

## 5. Minimal first PR — Phase 0 only

The safest first PR touches **zero** production code paths. It adds a
benchmark harness that imports the existing FEC library and measures
against it.

### 5.1 Files added

- `doc/design/fec-enhancements-v2.md` (this document)
- `src/fec_bench/channel_model.hpp`
- `src/fec_bench/interleaver.hpp` — reference convolutional
  interleaver; the schedule is the spec Phase 1 will re-implement.
- `src/fec_bench/interleaver_schedule_test.cpp` — Catch2 unit tests
  pinning the schedule.
- `src/fec_bench/bench_harness.cpp` — Catch2 binary, extends the
  pattern in [src/fec_test.cpp](../../src/fec_test.cpp).
- `scripts/fec_bench_report.py` — CSV → summary table.

### 5.2 Files modified

- `Makefile` — one new target `fec_bench` depending on
  `src/fec_bench/bench_harness.o src/zfex.o` and the unit test binary.
  **Not** added to `all`. Must cross-compile for the two ARM targets
  as well as native.

### 5.3 Acceptance criteria for the first PR

- `make` produces the same `wfb_tx`, `wfb_rx`, `wfb_tx_cmd` binaries
  as master (byte-identical if the compiler is deterministic).
- `make fec_bench && ./fec_bench --sweep small -o out.csv` runs to
  completion and writes a non-empty CSV. Must complete on **all three**
  platforms (laptop, SSC338Q, Radxa Zero 3W).
- `./interleaver_schedule_test` passes on all three platforms.
- `scripts/fec_bench_report.py out.csv` prints a summary showing
  baseline (depth=1) and at least one interleaved (depth≥2) result
  at the same (k, n).
- Existing `make test` continues to pass.

---

## Appendix A — Config-flag taxonomy

Only wfb-ng-owned knobs are listed here. The `[link_adapt]` profile
and everything it contains is owned by the adaptive-link process; see
[adaptive-link.md](adaptive-link.md).

| Flag | Phase | Lives in | Default | Scope |
|---|---|---|---|---|
| `--interleave-depth N` | 1 | `wfb_tx` / `wfb_rx` CLI + TLV | 1 | Per session |
| `CMD_SET_INTERLEAVE_DEPTH` / `CMD_GET_INTERLEAVE_DEPTH` | 1 / 3 | `tx_cmd.h`, control UDP | — | Runtime (drain+rekey) |
| `classify_critical = [...]` | 2 | `[video_*]` profile | H.264: `[5,7,8,13,15]` | Per stream (video only) |
| `stream_tx` / `stream_rx` | 2 | `[drone]` / `[gs]` streams list | — | Per stream (reuses existing mechanism) |

All flags default to "feature OFF."

## Appendix B — What is deliberately out of scope

- Changing the FEC code itself (zfex → RaptorQ, LDPC, etc.).
- Changing the AEAD (ChaCha20-Poly1305).
- Changing the wire nonce width.
- **Adding authentication to the control UDP socket** — explicitly
  accepted risk per §4.8.
- Re-architecting the single-threaded event loop.
- **UEP for non-video streams** — `mavlink` and `tunnel` are opaque
  byte streams; classification is not meaningful. They stay on stock
  `(k, n)`.
- **Stock-RX compatibility at `depth > 1`** — intentionally broken via
  a new `fec_type`; see §4.1.
- **TLV `len` field endianness cleanup.** The
  [wifibroadcast.hpp:212](../../src/wifibroadcast.hpp#L212) comment
  says wire fields are big-endian, but `tx.cpp:180` and `rx.cpp:558`
  use host byte order for `tlv_hdr_t.len`. Works in practice because
  all targets are little-endian. `TLV_INTERLEAVE_DEPTH` is a
  single-byte value, so the inconsistency does not bite the v2 wire
  addition. Pinning the comment-vs-code mismatch is a separate,
  larger cleanup.

Any of the above is a separate, larger project.

