# Bench: frame-aware FEC measurement rig

Loopback measurement rig for deciding whether to ship the `-X rtp_frame_aware`
feature. Does *not* require a radio — uses `wfb_tx -D` debug-UDP mode and a
Python bridge that injects controllable packet loss.

## Files

- `rig.py` — orchestrator. Spawns `wfb_tx`/`wfb_rx` as subprocesses, runs an
  in-process synthetic RTP feeder, a lossy UDP bridge, and an RTP sink. Writes
  per-run CSVs and stats logs to an output directory.
- `analyze.py` — reads a single run's CSVs and stats logs, emits `metrics.json`.
  Key metrics: per-packet latency, tail-of-frame latency (last packet per RTP
  timestamp group), frame completion rate, wire amplification, FEC recovery.
- `compare.py` — reads a matrix's `summary.csv`, prints A/B table, exits
  non-zero if any of the plan success criteria fail.
- `run_matrix.sh` — 20-cell matrix driver (2 × rtp_frame_aware, 2 × fec_k,
  5 × loss). Writes a `summary.csv` joining all runs. Configurable via
  `REPS` and `DURATION` env vars.

## Quick run

```
# build binaries first
make wfb_tx wfb_rx wfb_keygen
./wfb_keygen   # creates gs.key + drone.key

# single smoke run (~20s)
python3 bench/rig.py --outdir /tmp/smoke --duration 15 --loss 0.03 --rtp-frame-aware 1
python3 bench/analyze.py /tmp/smoke

# full matrix (~6 min for 15s per cell; multiply by REPS for stable stats)
REPS=1 DURATION=15 bench/run_matrix.sh /tmp/results
python3 bench/compare.py /tmp/results
```

## Success criteria (from measurement plan)

The comparison tool checks these automatically:

1. At 1–5% loss: tail-p95 latency drops by ≥ half a 60fps frame period
   (≥ 8.3 ms).
2. Frame completion rate does not regress at any loss level.
3. Wire amplification (`on_arm / off_arm`) is ≤ 1.25×.
4. No regression at 0% loss (completion rate, tail latency).

## Gotchas

- The rig uses loopback ports 15600-15603; don't run two rigs concurrently.
- `wfb_tx` in debug-UDP mode reports `injected=0` in its PKT IPC line — the
  airtime proxy comes from `bridge.csv` counts instead.
- The `tx_frame_closures` counter increments once per FEC_ONLY padding packet
  sent (not once per frame), so with small P-frames it's several times the
  frame rate. Use it to estimate airtime overhead attributable to the feature;
  don't treat it as a frame-event count.
- The synthetic feeder's I/P-frame packet counts (`--iframe-pkts`,
  `--pframe-pkts`) don't model actual encoder output — replace with pcap replay
  before trusting decision-rule output for production.
