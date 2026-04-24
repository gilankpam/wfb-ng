# fec_bench — FEC benchmark harness

Phase 0.5 of [fec-enhancements-v2.md](../doc/design/fec-enhancements-v2.md)
(v2.1 revision block). Measures the stock FEC (the one `wfb_tx` and
`wfb_rx` use today) plus a **reference block interleaver** across
three channel loss models, so we have a reproducible baseline to
compare Phase 1's production interleaver against.

This directory holds the committed baseline CSV. The harness source
is at [../src/bench/](../src/bench/). The reference interleaver
schedule lives in
[../src/bench/interleaver.hpp](../src/bench/interleaver.hpp); the
schedule is pinned by the Catch2 test in
[../src/bench/interleaver_schedule_test.cpp](../src/bench/interleaver_schedule_test.cpp),
which the Phase 1 production code in `src/interleaver.cpp` will have
to pass bit-for-bit.

## TL;DR

```sh
# Build the harness.
make fec_bench

# Sanity-check the harness itself (correctness gates at D=1 and D>1).
./fec_bench --selftest

# Schedule unit test for the reference interleaver.
make interleaver_schedule_test && ./interleaver_schedule_test

# Re-generate the committed baseline on this machine (~3 min).
make bench_baseline

# Read the numbers.
python3 scripts/bench_summary.py bench/baseline.csv
```

`fec_bench` is NOT built by `make` / `make all` and is NOT run by
`make test`. It's opt-in.

## Building

Targets:

- `make fec_bench` — builds `./fec_bench`. Depends on `src/zfex.o` and
  the reference interleaver header.
- `make interleaver_schedule_test` — builds the Catch2 schedule test.
- `make bench_baseline` — builds `fec_bench`, then runs
  `./fec_bench --sweep full --output bench/baseline.csv`.
- `make clean` — removes the above binaries and `bench/baseline.csv`.

No other existing target is changed.

### Under ASan + UBSan

```sh
make clean
make CFLAGS="-g -fno-omit-frame-pointer \
  -fsanitize=address -fsanitize=undefined \
  -fsanitize=pointer-compare -fsanitize=pointer-subtract \
  -fsanitize=leak -fsanitize-address-use-after-scope" \
     LDFLAGS="-static-libasan \
  -fsanitize=address -fsanitize=undefined \
  -fsanitize=pointer-compare -fsanitize=pointer-subtract \
  -fsanitize=leak -fsanitize-address-use-after-scope" \
     fec_bench interleaver_schedule_test
./fec_bench --selftest
./interleaver_schedule_test
```

Both binaries must exit 0 with no sanitizer output. The selftest
exercises both D=1 and D>1 code paths.

## Running

Three modes, mutually exclusive:

- `--selftest` — six built-in correctness gates:
  1. 0% uniform loss → 100% recovery.
  2. 100% uniform loss → 0% recovery.
  3. Mid-loss → decode runs and byte-verify passes.
  4. Same seed → same counts.
  5. Interleaver disperses bursts: `burst_len=5` at D=1 fails, at D=4 recovers.
  6. D=1 matches Step B's pre-refactor harness exactly (regression canary).
- `--sweep <preset>` — runs a preset and writes one CSV row per
  configuration. Presets:
  - `small` — ~15 configs (one `(k, n)`, depths `{1,2,4}`, one seed).
    For quick smoke (~1 s).
  - `full` — 768 configs: 4 `(k, n)` × 4 depths `{1,2,4,8}` × 3 seeds
    × (5 uniform + 8 GE + 3 periodic). ~3 min on a laptop.
- `--single` — one config, for debugging a specific row. Required
  flags include `--channel`, `--interleave-depth D`, `--k K --n N`,
  and the relevant `--loss / --burst-mean / --gap-mean / --period /
  --burst-len` for the channel.

Common flags:

- `--output PATH` — CSV output (default stdout). Progress goes to
  stderr so `--output bench/baseline.csv` writes a clean CSV.
- `--seed N` — master seed (default `0xC0FFEE`). Child seeds are
  derived deterministically; change this to shift all RNG streams.
- `--append` — append to `--output` without re-writing the header.

## CSV schema

One header row, one data row per configuration. Columns:

| column                  | what                                                                        |
|-------------------------|-----------------------------------------------------------------------------|
| `channel_model`         | `uniform` \| `ge` \| `periodic`                                              |
| `param1`, `param2`      | model-dependent, see below                                                  |
| `k`, `n`                | FEC parameters passed to `fec_new(k, n)`                                    |
| `depth`                 | block interleaver depth. `1` = no interleaving (v2.1 R4)                    |
| `blocks`                | how many blocks this config simulated (rounded up to a multiple of `depth`) |
| `seed`                  | the exact seed value that reproduces this row                               |
| `block_recovery_rate`   | fraction of blocks where `≥k` of `n` fragments survived the channel         |
| `residual_packet_loss`  | fraction of primary packets the simulated RX could not deliver              |
| `encode_us_mean`        | mean `fec_encode_simd` time, microseconds                                   |
| `encode_us_p99`         | 99th-percentile encode time, microseconds                                   |
| `decode_us_mean`        | mean `fec_decode_simd` time (empty if no decode ran)                        |
| `decode_us_p99`         | 99th-percentile decode time (empty if no decode ran)                        |
| `peak_mem_bytes`        | sum of explicit heap this config allocated: `D·n·buf + buf + 16·blocks`     |
| `latency_ms`            | modeled delivery latency per plan §4.2 (see "Latency model" below)          |

`param1` / `param2` meaning:

| model      | `param1`                    | `param2`                  |
|------------|-----------------------------|---------------------------|
| `uniform`  | loss probability (0..1)     | (empty)                   |
| `ge`       | mean burst length (packets) | mean gap length (packets) |
| `periodic` | period in packets           | burst length in packets   |

Reproducing a single row: grab its channel+params+k+n+depth+seed and run:

```sh
./fec_bench --single --channel <model> --<param-flag> <v> ... \
            --k <k> --n <n> --interleave-depth <D> \
            --blocks <blocks> --seed <seed>
```

Recovery and residual numbers will match exactly; timing differs
(wall-clock jitter, not a determinism bug).

### Old-schema compatibility

CSVs without the `depth` column (e.g. the original Phase 0
baseline.csv) are loadable by the summary script — every row is
treated as `depth=1`.

## Interpreting

- **`block_recovery_rate`** — primary metric. Pessimistic: a block
  with 6 primaries surviving out of k=8 with no FEC-recoverable
  parity counts as "not recovered", even though RX could still
  forward the 6 primaries. See `residual_packet_loss` for the
  packet-level angle.
- **`residual_packet_loss`** — fraction of the original `k · blocks`
  primary packets that the simulated RX could not deliver.
- **Encode / decode timings** — `CLOCK_MONOTONIC`, per call. Sanitizer
  builds disable zfex's SIMD kernel, so ASan timing is ~5-10× slower
  than production and not comparable to the committed baseline.
- **`peak_mem_bytes`** — constant given `(k, n, D, blocks)`. Scales
  as `D · n · buf_size`; at `D=8, n=20, buf≈1472`: ~235 KB.

### What this harness does NOT measure

- **Realized delivery latency / tail jitter.** The `latency_ms`
  column is a theoretical model (see "Latency model" below), not a
  measurement. Phase 1's RX deadline state machine (§4.7) will
  produce real measured latency.
- **Session rekey / drain cost.** See plan v2.1 R1: under the 1C
  design, refresh cost is ≤ 1 block-duration and is
  operationally small. Not modeled here.
- **On-ARM numbers.** x86-64 laptop substrate. Plan §3.5 originally
  required SSC338Q and Radxa Zero 3W runs; v2.1 R6 defers them. If
  ARM measurement changes the picture, the plan is revised then.
- **Actual UDP output.** The channel runs in-process. Phase 1 adds
  an on-wire byte-identity test for the `depth=1` path.

## Latency model (plan §4.2)

The `latency_ms` column carries a **theoretical** end-to-end
delivery latency, computed per the plan §4.2 formula:

```
block_duration_ms = k × ipi_ms + n × airtime_ms
latency_ms        = depth × block_duration_ms + slack_ms
```

`ipi_ms` is the inter-packet interval (how often TX gets a new
primary from upstream), `airtime_ms` is per-packet wire-time at
the configured MCS, `slack_ms` is the plan §4.7 RX deadline
hold-off slack. The decode-time term is folded out of the model:
every harness run has `decode_us_mean ≤ 30 µs` in the CSV, which
is ~0.2% of the smallest `block_duration` we care about.

Default values match the plan §4.2 reference operating point
(8812au radio, MCS7, 40 MHz HT, ~8 Mb/s H.264):

| parameter    | default | meaning                        |
|--------------|---------|--------------------------------|
| `--ipi-ms`   | 1.4     | IPI between primaries from upstream encoder |
| `--airtime-us` | 80    | per-packet airtime at the reference MCS |
| `--slack-ms` | 5.0     | RX deadline slack (§4.7)       |

Override via CLI flags if the deployment target uses a different
radio config. The `latency_ms` column re-computes accordingly; no
channel behavior changes.

**Budget (§4.2):**

| Tier          | Budget | Meaning                   |
|---------------|--------|---------------------------|
| Target        | ≤ 20 ms | one frame at 60 fps      |
| Degraded      | ≤ 30 ms | two frames at 60 fps     |
| Hard cap      | ≤ 50 ms | pilot starts feeling lag |

### Pre-computed at defaults for the swept (k, n, D)

From `bench/baseline.csv`'s `latency_ms` column:

| (k, n)    | block_duration | D=1       | D=2       | D=4        | D=8         |
|-----------|----------------|-----------|-----------|------------|-------------|
| (4, 8)    | 6.2 ms         | **11 ms** | **17 ms** | 30 ms      | **55 ms** ⚠️ |
| (4, 12)   | 6.6 ms         | **12 ms** | **18 ms** | 31 ms      | **57 ms** ⚠️ |
| (8, 12)   | 12.2 ms        | **17 ms** | 29 ms     | 54 ms ⚠️   | **102 ms** ⚠️⚠️ |
| (16, 20)  | 24.0 ms        | 29 ms     | 53 ms ⚠️  | **101 ms** ⚠️⚠️ | **197 ms** ⚠️⚠️ |

Cells over the 50 ms cap are marked. D=8 is above the cap for every
codec swept and is retained only for regression tracking, not as an
operating depth. D=4 is usable for the narrow codecs (4, 8) and
(4, 12); marginal at (8, 12); over cap at (16, 20).

### Reading latency together with recovery

The adaptive daemon (Phase 3) picks an operating point by
crossing recovery (from `block_recovery_rate`) and latency
(from `latency_ms`) at the current observed channel. Two patterns
show up in the committed baseline:

1. **D>1 helps a lot when bursts fit within D × parity.** Example:
   (8, 12) on GE burst=5, gap=100:
   - D=1: 95.26% recovery at 17 ms
   - D=4: 98.77% recovery at 54 ms
   - D=8: 99.84% recovery at 102 ms
   The operator picks the smallest D that meets the recovery floor
   they need, subject to the latency cap.

2. **D>1 *hurts* when bursts exceed D × parity.** Example:
   (16, 20) on GE burst=20, gap=100:
   - D=1: 76.50% recovery at 29 ms
   - D=4: 70.28% recovery at 101 ms (both worse AND over cap)

   At heavy bursts the interleaver converts "some bad blocks" into
   "more mediocre blocks." Adaptive daemon must detect long-burst
   conditions and NOT raise D in response.

## The `scripts/bench_summary.py` report

Stdlib-only Python 3. Prints:

1. Recovery rate by uniform loss rate, per `(k, n, D)`.
2. Recovery rate by GE burst length, one sub-table per gap value,
   per `(k, n, D)`.
3. Recovery rate by periodic period, one sub-table per burst-length,
   per `(k, n, D)`.
4. CPU cost per block, per `(k, n, D)`.
5. Modeled delivery latency, per `(k, n, D)`.
6. Peak explicit heap per config, per `(k, n, D)`.
7. **Plan §3.6 Y_burst indicator:** at GE (burst=5, gap=100), shows
   loss(D=1), loss(D=4), and `loss(D=1) / loss(D=4)` ratio. Plan's
   bar says ratio ≥ 3× for PASS.

Reads one CSV. Does not persist anything.

## Phase 1 A/B comparison

The `bench/phase1.csv` file is produced by re-running the full sweep
with the production interleaver (`src/interleaver.cpp`) wired in:

```sh
./fec_bench --sweep full --output bench/phase1.csv --use-prod-interleaver
```

This measures the **production push+drain CPU cost per block** in a
new `interleaver_us_mean` / `interleaver_us_p99` column. Recovery
numbers are guaranteed bit-identical to `bench/baseline.csv` because
the schedule test pins production = reference (16,442 assertions).

### Diffing against baseline

```sh
python3 scripts/bench_summary.py bench/phase1.csv \
    --compare bench/baseline.csv \
    --check-36-gates
```

The comparison section (`A/B comparison`) reports, per `(k, n, D)`:
- `recov_Δ` — should be exactly `+0.000%` if schedules match.
- `enc_Δ%` / `dec_Δ%` — wall-clock jitter between runs (typically
  single-digit percents; not a real regression).
- `int_A` — the production interleaver's per-block push+drain cost
  (only present when the `A` CSV was produced with
  `--use-prod-interleaver`).
- `int_%_of_enc` — that cost as a percentage of encode time. Should
  stay well under the 10% X_cpu bar.

### Plan §3.6 pass-bar gate

`--check-36-gates` asserts:
- **Y_burst** at GE burst=5, gap=100 — loss at D=4 must be ≤ 1/3 of
  loss at D=1 for each codec. Verdict per `(k, n)`.
- **X_cpu** — encode CPU at D>1 must not exceed D=1 by more than 10%
  for each codec+depth.
- **depth-sanity** (informational) — recovery at D>1 must not
  regress by more than 1% vs D=1 under uniform loss. At high uniform
  loss rates (p ≥ 0.2), variance can push individual points slightly
  negative; this is expected property of the interleaver (dampens
  per-block loss variance) and is NOT the plan's strict X_uniform
  bar. The strict X_uniform is a production-vs-reference equivalence
  assertion, already verified by the A/B diff's `recov_Δ = 0.000%`.

### Measured at Phase 1 commit (laptop x86-64):

- Production interleaver per-block cost: **0.27-0.74 µs**, which is
  **1.9-3.4% of encode time**. Well under 10%.
- Recovery bit-identical to reference.
- Y_burst passes at D=4 for (4,8), (4,12), (8,12); fails for (16,20)
  per Phase 0.5's documented finding — (16,20) at D=4 is outside
  §4.2's latency envelope (101 ms) anyway. Passes at D=8 (ratio 7.61×).
- X_cpu passes for every swept configuration.
