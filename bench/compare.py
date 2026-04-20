#!/usr/bin/env python3
"""
Compare frame-aware ON vs OFF cells in a matrix run and check success criteria.

Usage:
  bench/compare.py <results-dir>

Reads summary.csv produced by run_matrix.sh, joins each (fec_k, loss, rep) across
the two rtp_frame_aware arms, computes deltas, and prints a human-readable table.
Exit code 0 if all four plan success criteria are met, 1 otherwise.
"""

import csv
import sys
from collections import defaultdict
from pathlib import Path


def load(path):
    rows = []
    with open(path) as f:
        for row in csv.DictReader(f):
            for k in ('packets_sent', 'packets_recv', 'rx_fec_recovered',
                     'rx_lost', 'tx_frame_padding', 'tx_frame_closes'):
                row[k] = int(row[k])
            for k in ('fec_k', 'fec_n', 'rep'):
                row[k] = int(row[k])
            for k in ('loss', 'frames_complete_rate', 'tail_p50_us',
                     'tail_p95_us', 'tail_p99_us', 'wire_amplification'):
                row[k] = float(row[k]) if row[k] else None
            row['rtp_frame_aware'] = int(row['rtp_frame_aware'])
            rows.append(row)
    return rows


def avg(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


def pct_change(old, new):
    if old is None or new is None or old == 0:
        return None
    return (new - old) / old * 100.0


def main():
    results_dir = Path(sys.argv[1])
    rows = load(results_dir / 'summary.csv')

    # Group by (fec_k, loss); aggregate over reps; split by frame-aware
    grouped = defaultdict(lambda: {0: [], 1: []})
    for r in rows:
        grouped[(r['fec_k'], r['loss'])][r['rtp_frame_aware']].append(r)

    print()
    print(f"{'k':>2}  {'loss':>5}  {'frames_complete':>30}  {'tail_p95_us':>24}  {'wire_amp':>18}  {'fec_recov':>18}")
    print(f"{'':>2}  {'':>5}  {'  off        on        Δ%':>30}  {'  off      on      Δ%':>24}  {'off   on   Δ%':>18}  {'off    on':>18}")

    failures = []
    frame_period_us_60fps = 1e6 / 60.0

    for (k, loss), arms in sorted(grouped.items()):
        off = arms[0]
        on = arms[1]
        if not off or not on:
            continue
        fc_off = avg([r['frames_complete_rate'] for r in off])
        fc_on = avg([r['frames_complete_rate'] for r in on])
        t95_off = avg([r['tail_p95_us'] for r in off])
        t95_on = avg([r['tail_p95_us'] for r in on])
        wa_off = avg([r['wire_amplification'] for r in off])
        wa_on = avg([r['wire_amplification'] for r in on])
        fec_off = sum(r['rx_fec_recovered'] for r in off)
        fec_on = sum(r['rx_fec_recovered'] for r in on)

        fc_delta = pct_change(fc_off, fc_on)
        t95_delta = pct_change(t95_off, t95_on)
        wa_delta = pct_change(wa_off, wa_on)

        print(f"{k:>2}  {loss:>5.2f}  "
              f"{fc_off or 0:>6.3f}  {fc_on or 0:>6.3f}  {fmt_delta(fc_delta):>10}  "
              f"{int(t95_off or 0):>7}  {int(t95_on or 0):>7}  {fmt_delta(t95_delta):>6}  "
              f"{wa_off or 0:>5.2f} {wa_on or 0:>5.2f} {fmt_delta(wa_delta):>6}  "
              f"{fec_off:>5}  {fec_on:>5}")

        # Success criteria checks (for this k,loss cell)
        # 1) Tail p95 latency drops by >=50% of one frame period at 1-5% loss
        if 0.01 <= loss <= 0.05 and t95_off and t95_on:
            delta_abs = t95_off - t95_on
            if delta_abs < frame_period_us_60fps * 0.5:
                failures.append(f"tail-p95 win insufficient at k={k} loss={loss}: "
                                f"dropped {delta_abs:.0f}us vs target {frame_period_us_60fps*0.5:.0f}us")
        # 2) frame_complete_rate: on >= off at every loss level
        if fc_off is not None and fc_on is not None and fc_on < fc_off - 0.01:
            failures.append(f"frame completion regressed at k={k} loss={loss}: "
                            f"{fc_off:.3f} -> {fc_on:.3f}")
        # 3) wire amplification: on / off <= 1.25
        if wa_off and wa_on and wa_on / wa_off > 1.25:
            failures.append(f"airtime overhead too high at k={k} loss={loss}: "
                            f"amp {wa_off:.2f} -> {wa_on:.2f} (ratio {wa_on/wa_off:.2f})")
        # 4) No regression at 0% loss
        if loss == 0.0:
            if fc_off is not None and fc_on is not None and fc_on < fc_off - 0.001:
                failures.append(f"clean-link regression at k={k}: fc {fc_off:.3f} -> {fc_on:.3f}")
            if t95_off and t95_on and t95_on > t95_off * 1.2:
                failures.append(f"clean-link latency regression at k={k}: "
                                f"tail-p95 {t95_off:.0f} -> {t95_on:.0f}us")

    print()
    if failures:
        print("FAIL — success criteria not met:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("PASS — all plan success criteria met.")
        sys.exit(0)


def fmt_delta(x):
    if x is None:
        return 'n/a'
    sign = '+' if x >= 0 else ''
    return f'{sign}{x:.1f}%'


if __name__ == '__main__':
    main()
