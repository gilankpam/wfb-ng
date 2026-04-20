#!/usr/bin/env python3
"""
Analyze a single bench/rig.py run directory and print JSON metrics.

Inputs (all in the run outdir):
  tx.csv, rx.csv, bridge.csv, tx_stats.log, rx_stats.log, params.json

Outputs:
  metrics.json in the outdir + prints the summary to stdout.

Metrics:
  packets_sent                 rows in tx.csv
  packets_recv                 rows in rx.csv
  packets_loss_rate            1 - packets_recv/packets_sent
  per_pkt_latency_us_p50/95/99
  tail_latency_us_p50/95/99    latency of the last packet per RTP timestamp group
  frames_total                 unique RTP timestamps on TX side
  frames_complete              fraction of frames where every TX packet arrived at RX
  bridge_forwarded             count from bridge.csv
  bridge_dropped               count from bridge.csv
  rx_fec_recovered             last value from rx_stats.log PKT lines
  rx_lost                      last value from rx_stats.log PKT lines
  tx_frame_closures            sum over tx_stats.log PKT lines
  tx_incoming_pkts             sum
  tx_incoming_bytes            sum
  wire_amplification           bridge_forwarded / packets_sent  (approximate airtime cost)
"""

import csv
import json
import statistics
import sys
from pathlib import Path


def pct(values, p):
    if not values:
        return None
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round(p / 100.0 * (len(s) - 1)))))
    return s[k]


def load_csv(path):
    rows = []
    with open(path) as f:
        r = csv.DictReader(f)
        for row in r:
            rows.append(row)
    return rows


def parse_tx_stats(path):
    """Sum the relevant TX PKT counters across all log lines."""
    totals = dict(fec_timeouts=0, incoming=0, incoming_bytes=0, injected=0,
                  injected_bytes=0, dropped=0, truncated=0, frame_closures=0)
    keys = list(totals.keys())
    for line in open(path):
        parts = line.rstrip('\n').split('\t')
        if len(parts) != 3 or parts[1] != 'PKT':
            continue
        vals = parts[2].split(':')
        if len(vals) < len(keys):
            # older tx (no frame_closures); pad
            vals = vals + ['0'] * (len(keys) - len(vals))
        for k, v in zip(keys, vals[:len(keys)]):
            totals[k] += int(v)
    return totals


def parse_rx_stats(path):
    """Sum the relevant RX PKT counters across all log lines."""
    keys = ['all_pkt', 'all_bytes', 'decrypt_err', 'session_pkt', 'data_pkt',
            'unique_pkt', 'fec_recovered', 'lost', 'bad', 'outgoing', 'out_bytes']
    totals = {k: 0 for k in keys}
    for line in open(path):
        parts = line.rstrip('\n').split('\t')
        if len(parts) != 3 or parts[1] != 'PKT':
            continue
        vals = parts[2].split(':')
        if len(vals) != len(keys):
            continue
        for k, v in zip(keys, vals):
            totals[k] += int(v)
    return totals


def analyze(outdir):
    outdir = Path(outdir)
    params = json.loads((outdir / 'params.json').read_text())

    tx_rows = load_csv(outdir / 'tx.csv')
    rx_rows = load_csv(outdir / 'rx.csv')
    bridge_rows = load_csv(outdir / 'bridge.csv')

    tx_by_seq = {int(r['seq']): r for r in tx_rows}
    # Handle wraparound: if duplicate seq seen, disambiguate by rtp_ts. Use (seq, rtp_ts).
    tx_keyed = {}
    for r in tx_rows:
        key = (int(r['seq']), int(r['rtp_ts']))
        tx_keyed[key] = r
    rx_keyed = {}
    for r in rx_rows:
        key = (int(r['seq']), int(r['rtp_ts']))
        rx_keyed[key] = r

    # Per-packet latency (us)
    per_pkt_lat = []
    for key, tx_r in tx_keyed.items():
        rx_r = rx_keyed.get(key)
        if rx_r is None:
            continue
        lat_us = (int(rx_r['recv_ns']) - int(tx_r['send_ns'])) / 1000.0
        per_pkt_lat.append(lat_us)

    # Frame-level: group by rtp_ts on TX side.
    tx_by_frame = {}
    for r in tx_rows:
        tx_by_frame.setdefault(int(r['rtp_ts']), []).append(r)
    rx_by_frame = {}
    for r in rx_rows:
        rx_by_frame.setdefault(int(r['rtp_ts']), []).append(r)

    frames_total = len(tx_by_frame)
    frames_complete = 0
    tail_latencies_us = []  # last-packet-of-frame, all frames
    tail_latencies_complete_us = []  # only for complete frames

    for ts, tx_pkts in tx_by_frame.items():
        rx_pkts = rx_by_frame.get(ts, [])
        tx_seqs = {int(r['seq']) for r in tx_pkts}
        rx_seqs = {int(r['seq']) for r in rx_pkts}
        tx_pkts_sorted = sorted(tx_pkts, key=lambda r: int(r['send_ns']))
        last_tx_ns = int(tx_pkts_sorted[-1]['send_ns'])

        if tx_seqs.issubset(rx_seqs):
            frames_complete += 1
            # tail latency = arrival of last TX packet at RX
            last_rx_ns = max(int(r['recv_ns']) for r in rx_pkts if int(r['seq']) in tx_seqs)
            lat = (last_rx_ns - last_tx_ns) / 1000.0
            tail_latencies_complete_us.append(lat)
            tail_latencies_us.append(lat)
        else:
            # incomplete frame: skip from tail latency (no meaningful last-pkt time)
            pass

    # Bridge stats
    bridge_fwd = sum(1 for r in bridge_rows if r['action'] == 'forward')
    bridge_drop = sum(1 for r in bridge_rows if r['action'] == 'drop')

    # TX/RX IPC
    tx_stats = parse_tx_stats(outdir / 'tx_stats.log')
    rx_stats = parse_rx_stats(outdir / 'rx_stats.log')

    n_sent = len(tx_rows)
    n_recv = len(rx_rows)

    metrics = dict(
        params=params,
        packets_sent=n_sent,
        packets_recv=n_recv,
        packets_loss_rate=(1 - n_recv / n_sent) if n_sent else None,
        per_pkt_latency_us_p50=pct(per_pkt_lat, 50),
        per_pkt_latency_us_p95=pct(per_pkt_lat, 95),
        per_pkt_latency_us_p99=pct(per_pkt_lat, 99),
        tail_latency_us_p50=pct(tail_latencies_complete_us, 50),
        tail_latency_us_p95=pct(tail_latencies_complete_us, 95),
        tail_latency_us_p99=pct(tail_latencies_complete_us, 99),
        frames_total=frames_total,
        frames_complete=frames_complete,
        frames_complete_rate=(frames_complete / frames_total) if frames_total else None,
        bridge_forwarded=bridge_fwd,
        bridge_dropped=bridge_drop,
        bridge_drop_rate=(bridge_drop / (bridge_fwd + bridge_drop)) if (bridge_fwd + bridge_drop) else None,
        tx_frame_closures=tx_stats['frame_closures'],
        tx_incoming_pkts=tx_stats['incoming'],
        tx_incoming_bytes=tx_stats['incoming_bytes'],
        rx_fec_recovered=rx_stats['fec_recovered'],
        rx_lost=rx_stats['lost'],
        rx_outgoing_pkts=rx_stats['outgoing'],
        # airtime proxy: wire packets pushed / rtp packets ingested
        wire_amplification_pkts=(bridge_fwd + bridge_drop) / n_sent if n_sent else None,
    )

    (outdir / 'metrics.json').write_text(json.dumps(metrics, indent=2))
    return metrics


def main():
    if len(sys.argv) < 2:
        print('usage: analyze.py <run-outdir>', file=sys.stderr)
        sys.exit(2)
    m = analyze(sys.argv[1])
    print(json.dumps(m, indent=2))


if __name__ == '__main__':
    main()
