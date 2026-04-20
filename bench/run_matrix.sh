#!/usr/bin/env bash
# Run the A/B matrix for frame-aware FEC block closing.
#
# Matrix: rtp_frame_aware in {0,1}  x  fec_k in {4,8}  x  loss in {0,0.01,0.03,0.05,0.10}
# Repetitions: configurable via REPS env var (default 1).
# Duration per cell: DURATION env var (default 15 seconds).
#
# Usage:
#   bench/run_matrix.sh [results-dir]
#   REPS=3 DURATION=60 bench/run_matrix.sh results-20260420
#
# Each cell writes a subdirectory; the script writes a summary CSV at the end.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTROOT="${1:-$REPO_ROOT/bench-results-$(date +%Y%m%d-%H%M%S)}"
REPS="${REPS:-1}"
DURATION="${DURATION:-15}"

mkdir -p "$OUTROOT"
echo "Results directory: $OUTROOT"
echo "Duration per cell: ${DURATION}s, reps: $REPS"

summary="$OUTROOT/summary.csv"
echo "rtp_frame_aware,fec_k,fec_n,loss,rep,packets_sent,packets_recv,frames_complete_rate,tail_p50_us,tail_p95_us,tail_p99_us,wire_amplification,rx_fec_recovered,rx_lost,tx_frame_padding,tx_frame_closes" > "$summary"

total_cells=0
for aware in 0 1; do
  for k in 4 8; do
    for loss in 0 0.01 0.03 0.05 0.10; do
      for rep in $(seq 1 "$REPS"); do
        total_cells=$((total_cells + 1))
      done
    done
  done
done

cell_idx=0
for aware in 0 1; do
  for k in 4 8; do
    n=$((k + 2))
    for loss in 0 0.01 0.03 0.05 0.10; do
      for rep in $(seq 1 "$REPS"); do
        cell_idx=$((cell_idx + 1))
        name="aware${aware}_k${k}_loss${loss}_rep${rep}"
        outdir="$OUTROOT/$name"
        printf '[%d/%d] %s\n' "$cell_idx" "$total_cells" "$name"
        python3 "$REPO_ROOT/bench/rig.py" \
          --outdir "$outdir" \
          --rtp-frame-aware "$aware" \
          --fec-k "$k" --fec-n "$n" \
          --loss "$loss" \
          --duration "$DURATION" \
          --seed "$((42 + rep))" 2>&1 | tail -1

        python3 "$REPO_ROOT/bench/analyze.py" "$outdir" > "$outdir/metrics.txt"

        python3 - "$outdir/metrics.json" "$aware" "$k" "$n" "$loss" "$rep" "$summary" <<'PY'
import json, sys
m_path, aware, k, n, loss, rep, summary = sys.argv[1:]
m = json.load(open(m_path))
def f(v):
    return '' if v is None else v
row = [aware, k, n, loss, rep,
       m['packets_sent'], m['packets_recv'],
       f(m['frames_complete_rate']),
       f(m['tail_latency_us_p50']), f(m['tail_latency_us_p95']), f(m['tail_latency_us_p99']),
       f(m['wire_amplification_pkts']),
       m['rx_fec_recovered'], m['rx_lost'], m['tx_frame_padding'], m['tx_frame_closes']]
with open(summary, 'a') as fh:
    fh.write(','.join(str(x) for x in row) + '\n')
PY
      done
    done
  done
done

echo
echo "Summary: $summary"
column -s, -t "$summary" | head -60
