# Bench: frame-aware FEC measurement rig

Two rigs live here:

- **Layer 1 — synthetic loopback** (`rig.py` + friends). Spawns `wfb_tx`/`wfb_rx`
  on one machine, injects controllable packet loss via an in-process Python
  bridge, and measures with a synthetic RTP feeder. Does not require a radio.
- **Layer 2 — GS-side hardware A/B** (`gs_monitor.py`, `gs_compare.py`). Run on
  the ground station during a real drone session. Listens on the GS's duplicate
  RTP output port (5602 by default), captures arrival timestamps, and optionally
  tails `wfb_rx` / `wfb_tx` stdout logs for IPC metrics.

## Layer 1 files

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

## Layer 2 files

- `gs_monitor.py` — runs on the GS for one A/B arm. Listens on UDP `--port`
  (default 5602), records every RTP packet's seq/rtp_ts/mbit/pt/arrival_ns to
  `packets.csv`. Optionally tails local `wfb_rx` log and remote `wfb_tx` log
  via SSH (`--wfb-rx-log`, `--wfb-tx-ssh`, `--wfb-tx-log`). At the end of
  `--duration` seconds, writes `summary.json` with derived RTP and IPC metrics.
- `gs_compare.py` — reads two or more off-arm and on-arm `summary.json` files,
  prints a side-by-side metric table, and checks the 5 plan success criteria.
  Exits 0 if all pass.

## Layer 1 quick run

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

## Layer 2 quick run (on the GS, during a real session)

Assumes you've already set up drone + GS with wfb-ng and the GS forwards decoded
RTP to port 5601 (video player) and 5602 (metrics). We consume 5602.

```
# Arm 1 — OFF. Ensure drone config has rtp_frame_aware=0.
python3 bench/gs_monitor.py --arm off1 --duration 600 --outdir /tmp/ab/off1 \
    --port 5602 \
    --wfb-rx-log /var/log/wfb-ng/wfb_rx.log \
    --wfb-tx-ssh drone@192.168.1.2 \
    --wfb-tx-log /var/log/wfb-ng/wfb_tx.log

# Hot-swap config on drone: rtp_frame_aware=1; restart wfb-ng service

# Arm 2 — ON.
python3 bench/gs_monitor.py --arm on1 --duration 600 --outdir /tmp/ab/on1 ...

# Repeat off/on for ABAB pattern, then compare:
python3 bench/gs_compare.py \
    --off /tmp/ab/off1/summary.json /tmp/ab/off2/summary.json \
    --on  /tmp/ab/on1/summary.json  /tmp/ab/on2/summary.json \
    --encoder-fps 60
```

If `gs_compare.py` exits 0 with PASS, proceed to flight test. If FAIL, the
output identifies which criterion failed and suggests a specific fix.

## Success criteria (from measurement plan)

The comparison tool checks these automatically:

1. At 1–5% loss: tail-p95 latency drops by ≥ half a 60fps frame period
   (≥ 8.3 ms).
2. Frame completion rate does not regress at any loss level.
3. Wire amplification (`on_arm / off_arm`) is ≤ 1.25×.
4. No regression at 0% loss (completion rate, tail latency).

## Gotchas

- Layer 1 rig uses loopback ports 15600–15603; don't run two rigs concurrently.
- `wfb_tx` in debug-UDP mode reports `injected=0` in its PKT IPC line — the
  Layer 1 airtime proxy comes from `bridge.csv` counts instead. On real
  hardware (Layer 2), `injected_bytes` is populated normally.
- `wfb_tx` does not emit a feature-specific IPC counter (intentional: keeps the
  drone binary identical to upstream IPC format). "Did the feature fire?" is
  answered on the GS by counting M-bit-set packets in the RTP stream via
  `gs_monitor.py`'s `mbit_per_s` metric.
- The synthetic feeder's I/P-frame packet counts (`--iframe-pkts`,
  `--pframe-pkts`) don't model actual encoder output — replace with pcap replay
  before trusting Layer 1 decision-rule output for production.
- `gs_monitor.py` runs with regular user permissions (no root needed) as long
  as the GS duplicates RTP to a userland port (5602) via socat or the wfb-ng
  services config.
