#!/usr/bin/env python3
"""
GS-side metrics collector for the Phase 2 hardware A/B test.

Listens on the GS's duplicate RTP output port (default 5602) for one arm of the
A/B test and records every packet's arrival timestamp. Optionally tails wfb_rx
stdout (and wfb_tx stdout via SSH) to capture PKT IPC lines.

At the end of the arm, writes:
  packets.csv    seq,rtp_ts,mbit,pt,arrival_ns         (one row per RTP packet)
  wfb_rx.log     raw PKT/RX_ANT/SESSION lines from wfb_rx stdout
  wfb_tx.log     raw PKT/TX_ANT lines from wfb_tx stdout (if --wfb-tx-ssh given)
  summary.json   derived metrics (see below)

Derived metrics in summary.json:
  arm                 label (A/B or off/on)
  duration_s
  packets             total RTP packets received
  frames              total unique rtp_ts groups
  frames_complete     frames with no seq gap within [min_seq, max_seq]
  packet_loss_rate    missing seq / expected seq
  reorder_rate        count of seq < prev_seq / total
  frame_assembly_ms   {p50, p95, p99}
  inter_frame_ms      {p50, p95, p99, stdev}
  rfc3550_jitter_ms   final value of the RFC 3550 jitter estimator
  tx_ipc              {injected_bytes_per_s, incoming_pkts_per_s, frame_padding_per_s,
                       frame_closes_per_s}  (if wfb_tx log captured)
  rx_ipc              {fec_recovered_per_s, lost_per_s, decrypt_err_rate, outgoing_per_s}
                      (if wfb_rx log captured)

Usage:
  # Simple: just listen on port and write results
  python3 bench/gs_monitor.py --arm off --duration 600 --outdir /tmp/arm-off

  # With wfb_rx stdout tailed from a file (existing log)
  python3 bench/gs_monitor.py --arm on --duration 600 --outdir /tmp/arm-on \\
      --wfb-rx-log /var/log/wfb-ng/wfb_rx.log

  # With wfb_tx PKT IPC pulled from drone via SSH
  python3 bench/gs_monitor.py --arm on --duration 600 --outdir /tmp/arm-on \\
      --wfb-tx-ssh drone@192.168.1.2 \\
      --wfb-tx-log /var/log/wfb-ng/wfb_tx.log
"""

import argparse
import csv
import json
import math
import signal
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path


RTP_CLOCK_HZ_VIDEO = 90000  # default for H.264/H.265


def monotonic_ns():
    return time.monotonic_ns()


# --------------------------------------------------------------------------- #
# Packet listener
# --------------------------------------------------------------------------- #

def listen_rtp(port, stop_event, out_csv):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    sock.settimeout(0.2)

    csv_f = open(out_csv, 'w', buffering=1)
    csv_f.write('seq,rtp_ts,mbit,pt,arrival_ns\n')
    try:
        while not stop_event.is_set():
            try:
                data, _ = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            ns = monotonic_ns()
            if len(data) < 12:
                continue
            b0, b1, seq, rtp_ts, _ssrc = struct.unpack('!BBHII', data[:12])
            if (b0 >> 6) != 2:
                continue
            mbit = (b1 >> 7) & 1
            pt = b1 & 0x7F
            csv_f.write(f'{seq},{rtp_ts},{mbit},{pt},{ns}\n')
    finally:
        csv_f.close()
        sock.close()


# --------------------------------------------------------------------------- #
# IPC log tailers
# --------------------------------------------------------------------------- #

def tail_file(path, stop_event, out_path):
    """Tail an existing log file, append new lines to out_path. POSIX-only."""
    with open(out_path, 'w', buffering=1) as dst:
        try:
            src = open(path, 'r')
        except FileNotFoundError:
            dst.write(f'# file not found: {path}\n')
            return
        src.seek(0, 2)  # jump to end; we only want new content during the arm
        try:
            while not stop_event.is_set():
                line = src.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                dst.write(line)
        finally:
            src.close()


def tail_ssh(host, path, stop_event, out_path):
    """SSH into host and tail -F the given file. Captures to out_path."""
    cmd = ['ssh', '-o', 'BatchMode=yes', '-o', 'ServerAliveInterval=30',
           host, f'tail -n 0 -F {path}']
    with open(out_path, 'w', buffering=1) as dst:
        try:
            proc = subprocess.Popen(cmd, stdout=dst, stderr=subprocess.STDOUT)
        except FileNotFoundError:
            dst.write('# ssh binary not found\n')
            return
        try:
            while not stop_event.is_set():
                if proc.poll() is not None:
                    break
                time.sleep(0.2)
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    proc.kill()


# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #

def pct(values, p):
    if not values:
        return None
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round(p / 100.0 * (len(s) - 1)))))
    return s[k]


def seq_diff(a, b):
    """RTP seq is 16-bit; handle wraparound."""
    d = (a - b) & 0xFFFF
    return d if d < 0x8000 else d - 0x10000


def compute_rtp_metrics(csv_path, clock_hz):
    rows = []
    with open(csv_path) as f:
        for row in csv.DictReader(f):
            rows.append((int(row['seq']), int(row['rtp_ts']), int(row['mbit']),
                         int(row['pt']), int(row['arrival_ns'])))
    if not rows:
        return None

    n = len(rows)

    # Packet-level: detect loss and reorder.
    # Use RTP seq with wraparound handling. Sort by arrival order, compute
    # seq-advance relative to previous packet seen.
    total_advance = 0
    reorder = 0
    max_seq_seen = None
    min_seq_seen = None
    seqs_seen = set()
    for seq, *_ in rows:
        seqs_seen.add(seq)
        if max_seq_seen is None:
            max_seq_seen = seq
            min_seq_seen = seq
        else:
            # Track forward progress; reorder = seq arrived < last max seen
            d = seq_diff(seq, max_seq_seen)
            if d > 0:
                total_advance += d
                max_seq_seen = seq
            elif d < 0:
                reorder += 1
    expected = max(n, total_advance + 1)
    missing = max(0, expected - n)

    # Frame-level: group by rtp_ts
    by_frame = {}
    for seq, rtp_ts, mbit, pt, ns in rows:
        by_frame.setdefault(rtp_ts, []).append((seq, mbit, ns))

    frame_assembly = []
    frames_complete = 0
    mbit_times = []  # arrival time of the M-bit packet per frame
    for ts, pkts in by_frame.items():
        pkts_sorted = sorted(pkts, key=lambda p: p[2])
        first_ns = pkts_sorted[0][2]
        last_ns = pkts_sorted[-1][2]
        frame_assembly.append((last_ns - first_ns) / 1e6)  # ms
        # completeness: within min..max seq, every seq present?
        seqs = sorted({p[0] for p in pkts})
        if not seqs:
            continue
        span = seq_diff(seqs[-1], seqs[0]) + 1 if seqs[-1] != seqs[0] else 1
        if len(seqs) == span:
            frames_complete += 1
        # pick M-bit arrival (may be absent if that packet was lost)
        for p in pkts:
            if p[1] == 1:
                mbit_times.append(p[2])
                break

    # Inter-frame interval
    inter_ms = []
    mbit_times.sort()
    for i in range(1, len(mbit_times)):
        inter_ms.append((mbit_times[i] - mbit_times[i - 1]) / 1e6)

    # RFC 3550 jitter estimator, ms
    # D(i, i-1) = (R_i - R_{i-1}) - (S_i - S_{i-1}) where R is wall-clock (sec),
    # S is RTP timestamp (sec) = rtp_ts / clock_hz.
    # J_i = J_{i-1} + (|D| - J_{i-1}) / 16
    # We iterate in arrival order.
    jitter = 0.0
    prev_arrival = None
    prev_rtp_ts = None
    for seq, rtp_ts, mbit, pt, ns in rows:
        if prev_arrival is not None:
            arrival_delta_s = (ns - prev_arrival) / 1e9
            rtp_delta_s = ((rtp_ts - prev_rtp_ts) & 0xFFFFFFFF) / clock_hz
            # handle potential wraparound: clamp very large deltas
            if abs(rtp_delta_s - arrival_delta_s) < 10:
                d = arrival_delta_s - rtp_delta_s
                jitter += (abs(d) - jitter) / 16.0
        prev_arrival = ns
        prev_rtp_ts = rtp_ts

    duration_s = (rows[-1][4] - rows[0][4]) / 1e9

    return {
        'duration_s': duration_s,
        'packets': n,
        'frames': len(by_frame),
        'frames_complete': frames_complete,
        'frame_complete_rate': frames_complete / len(by_frame) if by_frame else None,
        'packet_loss_rate': missing / expected if expected else None,
        'reorder_rate': reorder / n if n else None,
        'frame_assembly_ms_p50': pct(frame_assembly, 50),
        'frame_assembly_ms_p95': pct(frame_assembly, 95),
        'frame_assembly_ms_p99': pct(frame_assembly, 99),
        'inter_frame_ms_p50': pct(inter_ms, 50),
        'inter_frame_ms_p95': pct(inter_ms, 95),
        'inter_frame_ms_stdev': statistics.stdev(inter_ms) if len(inter_ms) >= 2 else None,
        'rfc3550_jitter_ms': jitter * 1000.0,
    }


# --------------------------------------------------------------------------- #
# PKT log parsers
# --------------------------------------------------------------------------- #

TX_KEYS = ['fec_timeouts', 'incoming', 'incoming_bytes', 'injected',
           'injected_bytes', 'dropped', 'truncated', 'frame_padding', 'frame_closes']

RX_KEYS = ['all_pkt', 'all_bytes', 'decrypt_err', 'session_pkt', 'data_pkt',
           'unique_pkt', 'fec_recovered', 'lost', 'bad', 'outgoing', 'out_bytes']


def sum_pkt_lines(path, keys):
    if not path.exists():
        return None
    totals = {k: 0 for k in keys}
    lines = 0
    try:
        for line in open(path):
            parts = line.rstrip('\n').split('\t')
            if len(parts) < 3 or parts[1] != 'PKT':
                continue
            vals = parts[2].split(':')
            if len(vals) < len(keys):
                vals = vals + ['0'] * (len(keys) - len(vals))
            for k, v in zip(keys, vals[:len(keys)]):
                try:
                    totals[k] += int(v)
                except ValueError:
                    pass
            lines += 1
    except FileNotFoundError:
        return None
    if lines == 0:
        return None
    return totals


def tx_metrics(path, duration_s):
    t = sum_pkt_lines(path, TX_KEYS)
    if t is None:
        return None
    return {
        'incoming_pkts_per_s': t['incoming'] / duration_s,
        'incoming_bytes_per_s': t['incoming_bytes'] / duration_s,
        'injected_pkts_per_s': t['injected'] / duration_s,
        'injected_bytes_per_s': t['injected_bytes'] / duration_s,
        'dropped_per_s': t['dropped'] / duration_s,
        'frame_padding_per_s': t['frame_padding'] / duration_s,
        'frame_closes_per_s': t['frame_closes'] / duration_s,
    }


def rx_metrics(path, duration_s):
    r = sum_pkt_lines(path, RX_KEYS)
    if r is None:
        return None
    fec_r = r['fec_recovered']
    lost = r['lost']
    return {
        'all_pkt_per_s': r['all_pkt'] / duration_s,
        'decrypt_err_rate': r['decrypt_err'] / r['all_pkt'] if r['all_pkt'] else None,
        'fec_recovered_per_s': fec_r / duration_s,
        'lost_per_s': lost / duration_s,
        'fec_recovery_rate': fec_r / (fec_r + lost) if (fec_r + lost) else None,
        'outgoing_per_s': r['outgoing'] / duration_s,
        'outgoing_bytes_per_s': r['out_bytes'] / duration_s,
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--arm', required=True, help='label for this arm (e.g. off, on, A, B)')
    p.add_argument('--duration', type=float, required=True, help='seconds to record')
    p.add_argument('--outdir', required=True)
    p.add_argument('--port', type=int, default=5602, help='GS RTP port (default 5602)')
    p.add_argument('--rtp-clock-hz', type=int, default=RTP_CLOCK_HZ_VIDEO)
    p.add_argument('--wfb-rx-log', help='local file path to tail for wfb_rx stdout')
    p.add_argument('--wfb-tx-log', help='remote file path on the drone for wfb_tx stdout')
    p.add_argument('--wfb-tx-ssh', help='user@host for SSH to drone; used with --wfb-tx-log')
    return p.parse_args()


def main():
    a = parse_args()
    outdir = Path(a.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    stop = threading.Event()
    threads = []

    # Graceful stop on SIGINT/SIGTERM
    def handle_sig(signum, frame):
        stop.set()
    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    # RTP listener
    t = threading.Thread(target=listen_rtp, args=(a.port, stop, outdir / 'packets.csv'))
    t.start()
    threads.append(t)

    # Local wfb_rx log tail (if given)
    if a.wfb_rx_log:
        t = threading.Thread(target=tail_file, args=(a.wfb_rx_log, stop, outdir / 'wfb_rx.log'))
        t.start()
        threads.append(t)

    # Remote wfb_tx log tail over SSH (if given)
    if a.wfb_tx_ssh and a.wfb_tx_log:
        t = threading.Thread(target=tail_ssh, args=(a.wfb_tx_ssh, a.wfb_tx_log, stop, outdir / 'wfb_tx.log'))
        t.start()
        threads.append(t)

    print(f'[gs_monitor] arm={a.arm} port={a.port} duration={a.duration}s outdir={outdir}', file=sys.stderr)
    t_start = time.time()
    while time.time() - t_start < a.duration and not stop.is_set():
        time.sleep(0.5)
    stop.set()
    for t in threads:
        t.join(timeout=5.0)

    # Compute summary
    rtp = compute_rtp_metrics(outdir / 'packets.csv', a.rtp_clock_hz) or {}
    duration_s = rtp.get('duration_s', a.duration)
    summary = {
        'arm': a.arm,
        **rtp,
        'tx_ipc': tx_metrics(outdir / 'wfb_tx.log', duration_s),
        'rx_ipc': rx_metrics(outdir / 'wfb_rx.log', duration_s),
    }
    (outdir / 'summary.json').write_text(json.dumps(summary, indent=2, default=str))
    print(json.dumps(summary, indent=2, default=str))


if __name__ == '__main__':
    main()
