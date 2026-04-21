#!/usr/bin/env python3
"""
Compare two or more gs_monitor.py arms and check Phase 2e success criteria.

Usage:
  # ABAB pattern: two off arms and two on arms
  python3 bench/gs_compare.py \\
      --off /path/to/off1/summary.json /path/to/off2/summary.json \\
      --on  /path/to/on1/summary.json  /path/to/on2/summary.json \\
      --encoder-fps 60

Prints a side-by-side metric table and an all-pass / fail verdict per the plan:

  1. frame_assembly_ms_p95 improves by >=3 ms OR >=30%
  2. frame_complete_rate on >= off - 0.005  AND  frame_assembly_ms_p50 on <= off + 1
  3. inter_frame_ms_stdev on <= off * 1.25
  4. tx injected_bytes_per_s on <= off * 1.30  (if tx_ipc available in both)
  5. mbit_per_s on >= encoder_fps * 0.95  (verifies the stream carries M-bit
     at frame rate so the feature has something to react to; derived from the
     RTP stream observed on GS, not from any drone-side counter)

Exit code: 0 if all pass, 1 otherwise.
"""

import argparse
import json
import statistics
import sys
from pathlib import Path


def load_many(paths):
    return [json.load(open(p)) for p in paths]


def avg(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


def stdev_of(xs):
    xs = [x for x in xs if x is not None]
    return statistics.stdev(xs) if len(xs) >= 2 else None


def getavg(summaries, key, subkey=None):
    if subkey is None:
        return avg([s.get(key) for s in summaries])
    return avg([(s.get(key) or {}).get(subkey) for s in summaries])


def getstd(summaries, key, subkey=None):
    if subkey is None:
        return stdev_of([s.get(key) for s in summaries])
    return stdev_of([(s.get(key) or {}).get(subkey) for s in summaries])


def fmt(v, unit='', digits=3):
    if v is None:
        return 'n/a'
    if isinstance(v, float):
        return f'{v:.{digits}f}{unit}'
    return f'{v}{unit}'


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--off', nargs='+', required=True, help='summary.json paths for OFF arms')
    p.add_argument('--on', nargs='+', required=True, help='summary.json paths for ON arms')
    p.add_argument('--encoder-fps', type=float, default=60.0,
                   help='expected encoder frame rate (for criterion 5)')
    args = p.parse_args()

    off = load_many(args.off)
    on = load_many(args.on)

    rows = []
    def row(name, off_val, on_val, lower_is_better=True, unit=''):
        if off_val is None or on_val is None:
            rows.append((name, fmt(off_val, unit), fmt(on_val, unit), 'n/a'))
            return
        delta = on_val - off_val
        pct = (delta / off_val * 100) if off_val else None
        sign = '+' if delta >= 0 else ''
        rows.append((name,
                     fmt(off_val, unit),
                     fmt(on_val, unit),
                     f'{sign}{fmt(delta, unit, 3)} ({sign}{pct:.1f}%)' if pct is not None else f'{sign}{fmt(delta, unit, 3)}'))

    # Core RTP metrics
    fa_p50_off = getavg(off, 'frame_assembly_ms_p50')
    fa_p50_on = getavg(on, 'frame_assembly_ms_p50')
    fa_p95_off = getavg(off, 'frame_assembly_ms_p95')
    fa_p95_on = getavg(on, 'frame_assembly_ms_p95')
    fa_p99_off = getavg(off, 'frame_assembly_ms_p99')
    fa_p99_on = getavg(on, 'frame_assembly_ms_p99')
    fc_off = getavg(off, 'frame_complete_rate')
    fc_on = getavg(on, 'frame_complete_rate')
    if_std_off = getavg(off, 'inter_frame_ms_stdev')
    if_std_on = getavg(on, 'inter_frame_ms_stdev')
    loss_off = getavg(off, 'packet_loss_rate')
    loss_on = getavg(on, 'packet_loss_rate')
    jitter_off = getavg(off, 'rfc3550_jitter_ms')
    jitter_on = getavg(on, 'rfc3550_jitter_ms')
    reorder_off = getavg(off, 'reorder_rate')
    reorder_on = getavg(on, 'reorder_rate')

    # IPC metrics
    tx_bytes_off = getavg(off, 'tx_ipc', 'injected_bytes_per_s')
    tx_bytes_on = getavg(on, 'tx_ipc', 'injected_bytes_per_s')
    mbit_off = getavg(off, 'mbit_per_s')
    mbit_on = getavg(on, 'mbit_per_s')
    rx_fec_off = getavg(off, 'rx_ipc', 'fec_recovered_per_s')
    rx_fec_on = getavg(on, 'rx_ipc', 'fec_recovered_per_s')
    rx_lost_off = getavg(off, 'rx_ipc', 'lost_per_s')
    rx_lost_on = getavg(on, 'rx_ipc', 'lost_per_s')

    row('frame_assembly_ms_p50', fa_p50_off, fa_p50_on, unit='ms')
    row('frame_assembly_ms_p95', fa_p95_off, fa_p95_on, unit='ms')
    row('frame_assembly_ms_p99', fa_p99_off, fa_p99_on, unit='ms')
    row('frame_complete_rate',   fc_off, fc_on, unit='')
    row('inter_frame_ms_stdev',  if_std_off, if_std_on, unit='ms')
    row('packet_loss_rate',      loss_off, loss_on, unit='')
    row('rfc3550_jitter_ms',     jitter_off, jitter_on, unit='ms')
    row('reorder_rate',          reorder_off, reorder_on, unit='')
    row('tx_injected_bytes/s',   tx_bytes_off, tx_bytes_on, unit='B/s')
    row('mbit_per_s',            mbit_off, mbit_on, unit='/s')
    row('rx_fec_recovered/s',    rx_fec_off, rx_fec_on, unit='/s')
    row('rx_lost/s',             rx_lost_off, rx_lost_on, unit='/s')

    # Between-arm stability (sanity): stdev across off arms should be small
    # relative to the on-vs-off delta. If not, signal < noise.
    fa_p95_off_stdev = getstd(off, 'frame_assembly_ms_p95')

    # Print table
    w_name = max(len(r[0]) for r in rows)
    w_off = max(len(r[1]) for r in rows)
    w_on = max(len(r[2]) for r in rows)
    print()
    print(f'{"metric":<{w_name}}  {"off":>{w_off}}  {"on":>{w_on}}  delta')
    print('-' * (w_name + w_off + w_on + 20))
    for name, o, n, d in rows:
        print(f'{name:<{w_name}}  {o:>{w_off}}  {n:>{w_on}}  {d}')
    print()
    if fa_p95_off_stdev is not None:
        print(f'Sanity: off-arm stdev of frame_assembly_ms_p95 = {fa_p95_off_stdev:.3f} ms')
        print(f'        on-vs-off delta                        = {(fa_p95_on - fa_p95_off):.3f} ms' if (fa_p95_on is not None and fa_p95_off is not None) else '')
        print()

    # Success criteria
    failures = []

    # 1) frame_assembly_ms_p95 improves by >=3 ms OR >=30%
    if fa_p95_off is not None and fa_p95_on is not None:
        abs_improve = fa_p95_off - fa_p95_on
        rel_improve = abs_improve / fa_p95_off if fa_p95_off > 0 else 0
        if abs_improve < 3 and rel_improve < 0.30:
            failures.append(f'(1) p95 frame assembly win insufficient: Δ={abs_improve:.2f} ms ({rel_improve*100:.1f}%)')
    else:
        failures.append('(1) missing frame_assembly_ms_p95')

    # 2) no regression: frame_complete_rate and p50 latency
    if fc_off is not None and fc_on is not None:
        if fc_on < fc_off - 0.005:
            failures.append(f'(2) frame_complete_rate regressed: {fc_off:.4f} -> {fc_on:.4f}')
    if fa_p50_off is not None and fa_p50_on is not None:
        if fa_p50_on > fa_p50_off + 1.0:
            failures.append(f'(2) p50 frame assembly regressed: {fa_p50_off:.2f} -> {fa_p50_on:.2f} ms')

    # 3) jitter stable
    if if_std_off is not None and if_std_on is not None and if_std_off > 0:
        if if_std_on > if_std_off * 1.25:
            failures.append(f'(3) inter-frame jitter grew: {if_std_off:.2f} -> {if_std_on:.2f} ms ({(if_std_on/if_std_off - 1)*100:.1f}%)')

    # 4) airtime bounded
    if tx_bytes_off is not None and tx_bytes_on is not None and tx_bytes_off > 0:
        if tx_bytes_on > tx_bytes_off * 1.30:
            failures.append(f'(4) tx injected bytes/s grew: {tx_bytes_off:.0f} -> {tx_bytes_on:.0f} (+{(tx_bytes_on/tx_bytes_off - 1)*100:.1f}%)')
    else:
        print('(4) skipped: no tx_ipc data (need --wfb-tx-ssh/--wfb-tx-log on gs_monitor)')

    # 5) M-bit seen at encoder fps on the on-arm stream
    if mbit_on is not None:
        if mbit_on < args.encoder_fps * 0.95:
            failures.append(f'(5) mbit_per_s below encoder fps on on-arm: {mbit_on:.1f} vs expected {args.encoder_fps:.0f} (encoder may not be setting M-bit)')
    else:
        print('(5) skipped: no mbit data (empty packets.csv?)')

    if failures:
        print('FAIL — do not ship:')
        for f in failures:
            print(f'  - {f}')
        sys.exit(1)
    else:
        print('PASS — all applicable success criteria met.')
        sys.exit(0)


if __name__ == '__main__':
    main()
