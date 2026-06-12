#!/usr/bin/env python3
"""
Loopback measurement rig for wfb_tx / wfb_rx.

Topology:
    feeder (synthetic RTP) --UDP--> wfb_tx -u INPUT -D WIRE_OUT
                                          --UDP--> bridge (loss injection)
                                                   --UDP--> wfb_rx -a WIRE_IN -u RTP_OUT
                                                                   --UDP--> sink

All four roles (feeder, bridge, sink, and the wfb_tx/wfb_rx subprocesses) run in this
script. Outputs per run:
  <outdir>/tx.csv        seq,rtp_ts,mbit,send_ns
  <outdir>/rx.csv        seq,rtp_ts,mbit,recv_ns
  <outdir>/bridge.csv    wire_pkt_idx,action (forward/drop),wire_ns
  <outdir>/tx_stats.log  raw stdout of wfb_tx (contains PKT IPC lines)
  <outdir>/rx_stats.log  raw stderr of wfb_rx (contains PKT IPC lines)
  <outdir>/params.json   the run parameters for later joining
"""

import argparse
import json
import os
import random
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Ports. Kept distinct from test_txrx.py so they can run simultaneously.
PORT_RTP_IN   = 15600   # feeder -> wfb_tx input
PORT_WIRE_OUT = 15601   # wfb_tx debug -> bridge
PORT_WIRE_IN  = 15602   # bridge -> wfb_rx aggregator
PORT_RTP_OUT  = 15603   # wfb_rx -> sink


def monotonic_ns():
    return time.monotonic_ns()


# --------------------------------------------------------------------------- #
# Feeder: synthetic RTP generator
# --------------------------------------------------------------------------- #

def build_rtp(seq, rtp_ts, marker, ssrc, payload):
    """Build minimal RTP v2 header + payload.
    Byte 0: V=2, P=0, X=0, CC=0 -> 0x80
    Byte 1: M<<7 | PT (96 dynamic)
    Bytes 2..3: seq (big-endian)
    Bytes 4..7: timestamp
    Bytes 8..11: ssrc
    """
    b0 = 0x80
    b1 = (0x80 if marker else 0x00) | 96
    return struct.pack('!BBHII', b0, b1, seq & 0xFFFF, rtp_ts & 0xFFFFFFFF, ssrc) + payload


def feeder(params, stop_event, tx_csv_path):
    """Generate synthetic RTP stream to PORT_RTP_IN.

    Frame pattern: every `gop` frames is an I-frame (iframe_pkts packets),
    others are P-frames (pframe_pkts packets). M-bit on last packet of each frame.
    Frame period = 1/fps seconds. RTP timestamp increments by ts_step per frame.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dst = ('127.0.0.1', PORT_RTP_IN)

    fps = params['fps']
    frame_period = 1.0 / fps
    gop = params['gop']
    iframe_pkts = params['iframe_pkts']
    pframe_pkts = params['pframe_pkts']
    pkt_size = params['pkt_size']
    duration_s = params['duration_s']
    ssrc = 0x12345678
    ts_step = 90000 // fps  # 90kHz clock typical for video

    csv = open(tx_csv_path, 'w', buffering=1)
    csv.write('seq,rtp_ts,mbit,send_ns\n')

    seq = random.randint(0, 0xFFFF)
    rtp_ts = random.randint(0, 0xFFFFFFFF)
    frame_idx = 0
    deadline = time.monotonic()
    end_time = time.monotonic() + duration_s

    while not stop_event.is_set() and time.monotonic() < end_time:
        is_iframe = (frame_idx % gop) == 0
        n_pkts = iframe_pkts if is_iframe else pframe_pkts
        for i in range(n_pkts):
            marker = 1 if i == n_pkts - 1 else 0
            payload = bytes(pkt_size - 12)  # 12-byte RTP header
            pkt = build_rtp(seq, rtp_ts, marker, ssrc, payload)
            ns = monotonic_ns()
            try:
                sock.sendto(pkt, dst)
            except OSError:
                pass
            csv.write(f'{seq},{rtp_ts},{marker},{ns}\n')
            seq = (seq + 1) & 0xFFFF
        rtp_ts = (rtp_ts + ts_step) & 0xFFFFFFFF
        frame_idx += 1
        deadline += frame_period
        sleep = deadline - time.monotonic()
        if sleep > 0:
            time.sleep(sleep)

    csv.close()
    sock.close()


# --------------------------------------------------------------------------- #
# Bridge: forward wire packets from wfb_tx to wfb_rx with controllable loss
# --------------------------------------------------------------------------- #

def bridge(params, stop_event, bridge_csv_path):
    sock_in = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_in.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_in.bind(('127.0.0.1', PORT_WIRE_OUT))
    sock_in.settimeout(0.1)
    sock_out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dst = ('127.0.0.1', PORT_WIRE_IN)

    loss_p = params['loss_p']
    rng = random.Random(params.get('seed', 0))

    csv = open(bridge_csv_path, 'w', buffering=1)
    csv.write('idx,action,ns\n')
    idx = 0

    while not stop_event.is_set():
        try:
            data, _ = sock_in.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            break
        ns = monotonic_ns()
        if loss_p > 0 and rng.random() < loss_p:
            csv.write(f'{idx},drop,{ns}\n')
        else:
            try:
                sock_out.sendto(data, dst)
            except OSError:
                pass
            csv.write(f'{idx},forward,{ns}\n')
        idx += 1

    csv.close()
    sock_in.close()
    sock_out.close()


# --------------------------------------------------------------------------- #
# Sink: receive decoded RTP from wfb_rx and log
# --------------------------------------------------------------------------- #

def sink(stop_event, rx_csv_path):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', PORT_RTP_OUT))
    sock.settimeout(0.1)

    csv = open(rx_csv_path, 'w', buffering=1)
    csv.write('seq,rtp_ts,mbit,recv_ns\n')

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
        csv.write(f'{seq},{rtp_ts},{mbit},{ns}\n')

    csv.close()
    sock.close()


# --------------------------------------------------------------------------- #
# wfb process launchers
# --------------------------------------------------------------------------- #

def launch_wfb_tx(params, outdir):
    """wfb_tx reads keys relative to CWD; we ensure gs.key/drone.key exist in repo root."""
    cmd = [
        str(REPO_ROOT / 'wfb_tx'),
        '-K', str(REPO_ROOT / 'gs.key'),
        '-k', str(params['fec_k']),
        '-n', str(params['fec_n']),
        '-u', str(PORT_RTP_IN),
        '-D', str(PORT_WIRE_OUT),
        '-l', '500',  # log every 500ms for tighter stats
        '-T', '0',    # fec_timeout off; only measure the feature + natural k-fill
        '-R', str(512 * 1024),
        '-s', str(512 * 1024),
        '-X', str(params['rtp_frame_aware']),
        'wlan0',
    ]
    fout = open(outdir / 'tx_stats.log', 'w')
    ferr = open(outdir / 'tx_stderr.log', 'w')
    p = subprocess.Popen(cmd, stdout=fout, stderr=ferr, cwd=str(REPO_ROOT))
    return p, fout, ferr


def launch_wfb_rx(params, outdir):
    cmd = [
        str(REPO_ROOT / 'wfb_rx'),
        '-K', str(REPO_ROOT / 'drone.key'),
        '-a', str(PORT_WIRE_IN),
        '-c', '127.0.0.1',
        '-u', str(PORT_RTP_OUT),
        '-l', '500',
        '-R', str(512 * 1024),
        '-s', str(512 * 1024),
        'wlan0',
    ]
    fout = open(outdir / 'rx_stats.log', 'w')
    ferr = open(outdir / 'rx_stderr.log', 'w')
    p = subprocess.Popen(cmd, stdout=fout, stderr=ferr, cwd=str(REPO_ROOT))
    return p, fout, ferr


# --------------------------------------------------------------------------- #
# Run a single cell of the matrix
# --------------------------------------------------------------------------- #

def run_cell(params, outdir):
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    (outdir / 'params.json').write_text(json.dumps(params, indent=2))

    stop = threading.Event()
    threads = []

    # Start sink first so it's listening when wfb_rx forwards anything.
    t_sink = threading.Thread(target=sink, args=(stop, outdir / 'rx.csv'))
    t_sink.start()
    threads.append(t_sink)

    # Bridge: listens on wire_out, forwards to wire_in.
    t_bridge = threading.Thread(target=bridge, args=(params, stop, outdir / 'bridge.csv'))
    t_bridge.start()
    threads.append(t_bridge)

    # Give sockets a moment to bind.
    time.sleep(0.2)

    # Start wfb_rx, then wfb_tx (so rx is ready for first wire packet).
    rx_proc, rx_out, rx_err = launch_wfb_rx(params, outdir)
    time.sleep(0.3)
    tx_proc, tx_out, tx_err = launch_wfb_tx(params, outdir)
    time.sleep(0.5)  # let session key propagate

    # Feeder generates traffic for params['duration_s'] then exits.
    t_feeder = threading.Thread(target=feeder, args=(params, stop, outdir / 'tx.csv'))
    t_feeder.start()
    threads.append(t_feeder)

    # Wait for feeder to finish sending.
    t_feeder.join()

    # Drain: let inflight packets reach sink, and let wfb_tx emit one more PKT line.
    time.sleep(1.0)

    # Stop worker threads.
    stop.set()
    for t in threads:
        t.join(timeout=2.0)

    # Terminate wfb processes.
    for p in (tx_proc, rx_proc):
        try:
            p.send_signal(signal.SIGTERM)
            p.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=1.0)

    for f in (tx_out, tx_err, rx_out, rx_err):
        f.close()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--outdir', required=True)
    p.add_argument('--rtp-frame-aware', type=int, default=0)
    p.add_argument('--fec-k', type=int, default=8)
    p.add_argument('--fec-n', type=int, default=12)
    p.add_argument('--loss', type=float, default=0.0, help='fraction 0..1')
    p.add_argument('--duration', type=float, default=15.0, help='seconds')
    p.add_argument('--fps', type=int, default=60)
    p.add_argument('--gop', type=int, default=30)
    p.add_argument('--iframe-pkts', type=int, default=30)
    p.add_argument('--pframe-pkts', type=int, default=3)
    p.add_argument('--pkt-size', type=int, default=1200, help='bytes including RTP header')
    p.add_argument('--seed', type=int, default=42)
    return p.parse_args()


def main():
    a = parse_args()
    params = dict(
        rtp_frame_aware=a.rtp_frame_aware,
        fec_k=a.fec_k,
        fec_n=a.fec_n,
        loss_p=a.loss,
        duration_s=a.duration,
        fps=a.fps,
        gop=a.gop,
        iframe_pkts=a.iframe_pkts,
        pframe_pkts=a.pframe_pkts,
        pkt_size=a.pkt_size,
        seed=a.seed,
    )
    run_cell(params, a.outdir)
    print(f'done: {a.outdir}', file=sys.stderr)


if __name__ == '__main__':
    main()
