# Block-FEC Baseline

Phase 1b characterization of the existing block FEC (`WFB_FEC_VDM_RS`)
before Phase 2 introduces the sliding-window variant. Every row of the
claim table below is observable via the harness at
[src/fec_baseline.cpp](../src/fec_baseline.cpp), wired into `make test`.

**Source of truth for claims:** [doc/SLIDING_WINDOW_FEC_DESIGN.md](SLIDING_WINDOW_FEC_DESIGN.md).

**Build/run**:
```sh
make fec_baseline
./fec_baseline                 # all 20 test cases
./fec_baseline '[benchmark]'   # just the timing benchmarks
```

The harness is Catch2 v3 (already a test dep via `fec_test.cpp`). No
production code under `src/` was modified. Mock subclasses use existing
pure-virtual seams: `Transmitter::inject_packet` captures every TX wire
packet; `Aggregator::send_to_socket` captures every delivered payload;
`Aggregator` counters are already public members.

## Claim → test map

All claims cite sections of [SLIDING_WINDOW_FEC_DESIGN.md](SLIDING_WINDOW_FEC_DESIGN.md).

| # | Claim (§) | Test level | Assertion | Status |
|---|---|---|---|---|
| C1 | §1 FM1 — front-block gap stalls same-block tail (rx.cpp:771-791) | mock TX→RX, drop-fragment | gap at frag 3 + drop parity → only 3 deliveries, no FEC | PASS |
| C2 | §1 FM2 — non-front fully-received block held behind stalled front (rx.cpp:780) | mock TX→RX | block 0 stalled, block 1 also incomplete → only block 0's released frags leave | PASS |
| C3 | §1 FM3 — block-boundary burst unrecoverable | mock TX→RX, 16-pkt burst straddling 2 blocks | `count_p_fec_recovered == 0` | PASS |
| C4 | §1/§2 fast-path — zero-latency in-order emission | mock TX→RX, no loss | 8 deliveries in single pipeline pass, `count_p_fec_recovered == 0` | PASS |
| C5 | §1 ring eviction → `count_p_override++` (rx.cpp:440) | mock TX→RX, 41 incomplete blocks | `count_p_override >= 1` | PASS |
| C6 | §2.2/§10.3 `packet_seq = block*fec_k + frag` (rx.cpp:865) | mock TX→RX + PacketLossListener | skip blocks 1-4 → listener gets `(lost=32, last=7, new=40)` | PASS |
| C7 | §2.3/§5.7 fail-closed on unknown `fec_type` (rx.cpp:659-664) | mock RX + **hand-forged** SWIN session packet | forged `fec_type=0x2` → `count_p_dec_err++`, `count_p_session` unchanged | PASS |
| C8 | §5.6 block-FEC nonce layout `(block<<8 \| frag)` unique | mock TX capture | parsed nonces are unique; `block<3, frag<12` after 3 blocks | PASS |
| C9 | §7.4 no `T_flush` / `count_w_flush` in block path | grep `src/rx.cpp` | both absent | PASS |
| C10 | §8.1 RX ring memory `= RX_RING_SIZE · fec_n · MAX_FEC_PAYLOAD` | `static_assert`/arithmetic | `40 · 12 · 3996 = 1,918,080 ≈ 1.83 MiB` | PASS |
| C11 | §8.2 encode — `fec_encode_simd` one call produces all n−k rows | Catch2 `BENCHMARK` | three parameter sweeps; see numbers below | PASS (record) |
| C12 | §8.3 decode — 1-erasure per block | Catch2 `BENCHMARK` | see numbers below | PASS (record) |
| C13 | §10.3 all block-FEC counters increment under a scripted scenario | mock TX→RX + forged session + malformed feed | 12 counters strictly > 0 | PASS |
| C14 | §10.3.1 SESSION IPC hardcodes `WFB_FEC_VDM_RS` at rx.cpp:698 | grep `src/rx.cpp` | `WFB_FEC_VDM_RS` appears inside the SESSION IPC line | PASS |
| C15 | §9.4 `PacketLossListener::on_packet_loss` is `(uint32_t,uint32_t,uint32_t)` | `static_assert` | signature unchanged | PASS (compile) |
| C16 | §11.2 K-sized padding — one outlier inflates all n−k parity | mock TX capture, 7 small + 1 big | parity packets = 1428 B (matches 9 + 3 + 1400 + 16) | PASS |
| C17 | §11.3 single-packet-loss recovery within a block | mock TX→RX, drop frag 7 | `count_p_fec_recovered == 1`; frag 7 reconstructed | PASS |
| C18 | §12.1 partial-block close primitive (tx.cpp:986-992) | mock TX, `WFB_PACKET_FEC_ONLY` loop | 1 real frag + 7 close-calls (last one injects 5 frags) → n=12 data packets | PASS |
| C19 | §5.7 direction-2 — new RX decodes new TX | mock TX→RX smoke | 8 delivered, `count_p_dec_err == 0` | PASS |
| C20 | robustness (not in design, protects harness) | mock RX fed malformed input | `count_p_bad >= 3`; subsequent valid packets still delivered | PASS |

Total at last run: **20 test cases passed, 275,706 assertions.**

## Measured baselines (x86_64 host)

- **Platform**: Linux 6.19.6, AMD Ryzen 9 7900, NixOS
- **Compiler**: gcc 14.3.0, `-O2 -std=gnu++11`
- **FEC acceleration (runtime)**: `noaccel` — despite `-DZFEX_USE_INTEL_SSSE3`
  / `-DZFEX_USE_ARM_NEON` at compile time, `zfex_opt` reports `noaccel` on
  this host. Recording the observation as-is; cross-platform benchmarking
  is explicitly out of scope for Phase 1b.
- **Catch2 samples**: 100 per benchmark (Catch2 default).

### Encode (pure zfex, Catch2 `BENCHMARK`)

| Parameters          | Mean       | Stddev    |
|---------------------|-----------:|----------:|
| k=8 n=12 P=1400     |  10.25 µs  |  0.45 µs  |
| k=4 n=8  P=1400     |   5.18 µs  |  0.18 µs  |
| k=8 n=12 P=3996     |  29.21 µs  |  1.05 µs  |

Design §8.2 reference point (RPi Zero 2W A53, one-row-encode extension):
~14 µs at k=8 n=12 P=1400. **Deferred** — would need on-target run to
compare; this host is amd64. The scaling shape (cost grows roughly
linearly in k·P) is visible across the three points.

### Decode (pure zfex, 1-erasure)

| Parameters          | Mean       | Stddev    |
|---------------------|-----------:|----------:|
| k=8 n=12 P=1400 g=1 |   2.68 µs  |  0.11 µs  |

Design §8.3 reference point (RPi Zero 2W A53): ~7 µs/block. **Deferred**
for the same platform reason.

### End-to-end pipeline (encode + AEAD + ring + decode, 1-erasure)

| Scenario                           | Mean       | Stddev    |
|------------------------------------|-----------:|----------:|
| 1 block, 1 erasure, 1400 B payload |  177.0 µs  | 13.8 µs   |

Includes keypair generation, session establishment, encrypt+decrypt for
all k=8 primaries, and FEC decode of the 1 missing primary. Comparable
to block-FEC handling of a single recoverable block on this host.

### Memory arithmetic (C10)

```
RX_RING_SIZE  * fec_n   * MAX_FEC_PAYLOAD
       40     *   12    *      3996        = 1,918,080 bytes  ≈ 1.83 MiB
```

### Padding size (C16)

A block with 7 small (64 B) payloads and 1 big (1400 B) payload produces
parity packets of **1428 B each** on the wire (= `wblock_hdr_t` (9 B) +
`wpacket_hdr_t` (3 B) + 1400 + AEAD MAC (16 B)). The SIMD round-up only
affects encode scratch size, not on-wire packet size.

## Scope cuts (intentional)

Recorded here so Phase 2 knows what was NOT baselined:

| Claim | Why cut | Where covered |
|-------|---------|---------------|
| §8.3/§8.4 RPi Zero 2W / NanoPi NEO CPU numbers | Dev host is x86_64 | Deferred to on-target Phase 2c benchmarks |
| §12.1 `fec_timeout` timing loop | Lives in `data_source`, needs UDP/poll/stdin machinery | Primitive covered by C18; timing loop is integration-level, belongs in `wfb_ng/tests/` |
| §12.1 `fec_delay` nanosleep pacer | Same as above — `data_source`-level | — |
| Encode scaling curve fit | 3 measured points are enough to show shape; curve fit is not a design claim | — |
| `MAX_BLOCK_IDX` live rekey trigger | 2⁵⁵ blocks is infeasible to drive | tx.cpp:715-721 branch reviewed by inspection |
| §11.3 "block-vs-sliding recovery-latency comparison" | Block side measured via C17's trigger structure; full comparison requires sliding to exist | Becomes regression test in Phase 3 |

## Notes for future work

- `FEC acceleration: noaccel` on this host is worth a follow-up — the
  compile flags set SSSE3 and the CPU clearly supports it, but
  `zfex_opt` reports no acceleration. Not a design issue; a packaging /
  detection one. Out of scope for this harness.
- `src/rx.o` and `src/tx.o` each contain a `main()` (for their CLI
  binaries). The harness Makefile uses `objcopy --redefine-sym main=…`
  to produce `src/rx_lib.o` / `src/tx_lib.o` for linking into
  `fec_baseline`. If either CLI's `main` is renamed in the future,
  update the Makefile accordingly.
- `src/tx.hpp` has inline method bodies that depend on
  `using namespace std;` being in effect AND on several Linux-specific
  system headers (`linux/if_packet.h`, `sys/ioctl.h`, etc.) being
  included first. The harness mirrors tx.cpp's include order. Not a
  bug, but surprises on first include.
- `src/tx.hpp` and `src/rx.hpp` both declare an unqualified global enum
  value `LOCAL` (as part of `tx_mode_t` and `rx_mode_t`). Harness uses
  a `#define LOCAL tx_mode_LOCAL_hack_` / `#undef LOCAL` sleeve around
  `#include "tx.hpp"` to avoid the collision. A structural fix (enum
  class or namespace) would be a minor production-code seam if Phase 2
  wants to include both headers elsewhere.
