# fec_bench — FEC benchmark harness

Phase 0 of [fec-enhancements-v2.md](../doc/design/fec-enhancements-v2.md).
Measures the stock FEC (the one `wfb_tx` and `wfb_rx` use today) under
three channel loss models, so we have a reproducible baseline to
compare Phase 1's interleaver against.

This directory holds the committed baseline CSV. The harness source
is at [../src/bench/](../src/bench/).

## TL;DR

```sh
# Build the harness.
make fec_bench

# Sanity-check the harness itself (built-in correctness gates).
./fec_bench --selftest

# Re-generate the committed baseline on this machine (~1 minute).
make bench_baseline

# Read the numbers.
python3 scripts/bench_summary.py bench/baseline.csv
```

`fec_bench` is NOT built by `make` / `make all` and is NOT run by
`make test`. It's opt-in.

## Building

Targets:

- `make fec_bench` — builds `./fec_bench`. Depends on `src/zfex.o` (the
  same object `wfb_tx` / `wfb_rx` use — no fork of the FEC code).
- `make bench_baseline` — builds `fec_bench`, then runs
  `./fec_bench --sweep full --output bench/baseline.csv`.
- `make clean` — removes `./fec_bench` and `bench/baseline.csv`.

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
     fec_bench
./fec_bench --selftest
```

Must exit 0 with no sanitizer output. (These are the exact flags the
`check:` target in the root `Makefile` uses for the rest of the tree.)

## Running

Three modes, mutually exclusive:

- `--selftest` — runs four built-in correctness gates (0% loss →
  100% recovery; 100% loss → 0% recovery; mid-loss → decode runs and
  byte-verify passes; same seed → same counts). Exits non-zero on any
  gate failure.
- `--sweep <preset>` — runs a preset and writes one CSV row per
  configuration. Presets:
  - `small` — 5 configs, 1000 blocks each, one seed. For quick smoke
    checks (~seconds). Only the `(k, n) = (8, 12)` point.
  - `full` — 192 configs, 10 000 blocks each, 3 seeds per config.
    The committed baseline. ~1 minute on a laptop.
- `--single` — one config, for debugging a specific row. See
  `./fec_bench --help` for the parameter flags.

Common flags:

- `--output PATH` — CSV output (default stdout). Progress goes to
  stderr either way, so `--output bench/baseline.csv` leaves a clean
  CSV even while the progress counter scrolls past on your terminal.
- `--seed N` — master seed (default `0xC0FFEE`). Every other seed used
  in a sweep is derived deterministically from this one; changing it
  shifts all RNG streams together, not pairwise.
- `--append` — append to `--output` without re-writing the header.

## CSV schema

One header row, one data row per configuration. Columns:

| column                  | what                                                                |
|-------------------------|---------------------------------------------------------------------|
| `channel_model`         | `uniform` \| `ge` \| `periodic`                                      |
| `param1`, `param2`      | model-dependent, see below                                          |
| `k`, `n`                | FEC parameters passed to `fec_new(k, n)`                            |
| `blocks`                | how many blocks this config simulated                               |
| `seed`                  | the exact seed value that reproduces this row                       |
| `block_recovery_rate`   | fraction of blocks where `≥k` of `n` fragments survived the channel |
| `residual_packet_loss`  | fraction of primary packets the simulated RX could not deliver      |
| `encode_us_mean`        | mean `fec_encode_simd` time, microseconds                           |
| `encode_us_p99`         | 99th-percentile encode time, microseconds                           |
| `decode_us_mean`        | mean `fec_decode_simd` time, microseconds (empty if no decode ran)  |
| `decode_us_p99`         | 99th-percentile decode time, microseconds (empty if no decode ran)  |
| `peak_mem_bytes`        | sum of explicit heap this config allocated (deterministic)          |

`param1` / `param2` meaning:

| model      | `param1`       | `param2`                |
|------------|----------------|-------------------------|
| `uniform`  | loss probability (0..1) | (empty)      |
| `ge`       | mean burst length (packets) | mean gap length (packets) |
| `periodic` | period in packets | burst length in packets |

Reproducing a single row: grab its `channel_model`, `param1`, `param2`,
`k`, `n`, `blocks`, and `seed` from the CSV, then:

```sh
./fec_bench --single --channel <model> --<param-flag> <v> ... \
            --k <k> --n <n> --blocks <blocks> --seed <seed>
```

Recovery and residual loss numbers will match exactly; timing
numbers will differ (wall-clock jitter, not a determinism bug).

## Interpreting

What each metric is telling you:

- **`block_recovery_rate`** — primary metric. This is what the RX
  user-space actually cares about: did we deliver an intact block?
  It's a pessimistic count: a block with 6 primaries out of k=8
  plus 0 parity survivors is NOT "recovered" here, even though the
  6 primaries would still reach userspace. See `residual_packet_loss`
  for the other angle.
- **`residual_packet_loss`** — fraction of the original k primaries
  that the RX couldn't deliver. Counts the 6-of-8 example above as
  2/8 lost.
- **`encode_us_*` / `decode_us_*`** — wall-clock measured with
  `CLOCK_MONOTONIC`, per call, over ≥1000 samples per config.
  Sanitizer builds of zfex disable the SIMD kernel (zfex-side config),
  so numbers from an ASan run are ~5-10x slower than production and
  not comparable to the baseline CSV.
- **`peak_mem_bytes`** — the explicit heap allocations the harness
  made for this config: `n × aligned(block_size)` fragment buffers
  plus bookkeeping. Constant given `(k, n, block_size, blocks)`.
  Phase 0 only. Becomes interesting in Phase 1 when the interleaver
  ring buffer is introduced.

### What Phase 0 does NOT measure

- **Delivery latency.** Without an interleaver, delivery latency is
  `fec_decode_time + a fixed function of the channel model` — it
  doesn't move when we change anything interesting. The columns
  will be added in the Phase 1 PR, where they start carrying signal.
- **Interleaver depth.** Doesn't exist yet. No `depth` column yet.
- **On-ARM numbers.** This harness runs on x86 in CI and on the
  branch owner's laptop. Plan §3.5 calls for running it on the
  SSC338Q (drone TX SoC) and Radxa Zero 3W (ground-station RX SBC)
  too; that's a hardware step taken outside this PR.
- **Actual UDP output.** The channel models run in-process. The
  Phase 1 PR adds a pcap replay test to pin the wire format at
  `depth == 1` byte-for-byte against `master`.

## The `scripts/bench_summary.py` report

Stdlib-only Python 3 (no pandas / numpy). Prints:

1. Recovery rate by uniform loss rate (per `(k, n)`).
2. Recovery rate by Gilbert-Elliott burst length (per gap × per `(k, n)`).
3. Recovery rate by periodic period (per burst_len × per `(k, n)`).
4. CPU cost per block (encode/decode mean + max p99 per `(k, n)`).
5. Peak explicit heap per config per `(k, n)`.

Reads one CSV. Does not persist anything.

## How a future PR compares against this baseline

The Phase 1 PR will:

1. Add a `depth` column to the CSV schema (appended at the end, so
   Phase 0 readers keep working).
2. Extend both sweep presets to iterate depth ∈ {1, 2, 4, 8, 16}.
3. Re-run `make bench_baseline` and overwrite `bench/baseline.csv`
   with the new grid (which is a strict superset at `depth == 1`).
4. Extend `scripts/bench_summary.py` to take two CSVs and print
   recovery-rate delta and CPU-cost delta per configuration — the
   A/B report the plan's §3.6 go/no-go gates key on.

At that point `bench/baseline.csv` starts functioning as a
regression gate: CI runs the sweep against the branch build, diffs
against the committed baseline, and fails on any row that regresses
beyond the plan's tolerances.
