#!/usr/bin/env python3
"""Receive decoded payloads from wfb_rx and verify against the
deterministic sender in send_udp.py.

Exits 0 if every received payload byte-matches its expected form AND
no expected sequence is missing.
Exits non-zero on any mismatch or missing packet. Prints a concise
diagnosis to stderr.
"""

import argparse
import socket
import struct
import sys


def expected(seq: int, body_size: int) -> bytes:
    hdr = struct.pack("!H", seq & 0xFFFF)
    body = bytes((seq * 31 + i * 17) & 0xFF for i in range(body_size))
    return hdr + body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("-n", "--count", type=int, required=True,
                    help="number of packets the sender is producing")
    ap.add_argument("--body-size", type=int, default=64)
    ap.add_argument("--timeout", type=float, default=5.0,
                    help="seconds with no packet before we declare the test done")
    args = ap.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((args.host, args.port))
    s.settimeout(args.timeout)

    got = {}
    mismatches = 0
    while True:
        try:
            pkt, _ = s.recvfrom(65535)
        except socket.timeout:
            break
        if len(pkt) < 2:
            print(f"FAIL: received short packet, len={len(pkt)}", file=sys.stderr)
            return 2
        seq, = struct.unpack("!H", pkt[:2])
        exp = expected(seq, args.body_size)
        if pkt != exp:
            mismatches += 1
            if mismatches <= 3:
                print(f"FAIL: mismatch at seq={seq} len_got={len(pkt)} "
                      f"len_exp={len(exp)}", file=sys.stderr)
        got[seq] = pkt

    s.close()

    missing = [s for s in range(args.count) if s not in got]
    extra = [s for s in sorted(got) if s >= args.count]

    print(f"received {len(got)}/{args.count}  "
          f"missing={len(missing)}  extra={len(extra)}  "
          f"mismatches={mismatches}",
          file=sys.stderr)

    if missing or extra or mismatches:
        if missing:
            print(f"first missing seqs: {missing[:10]}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
