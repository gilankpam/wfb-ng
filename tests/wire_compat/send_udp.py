#!/usr/bin/env python3
"""Send N deterministic UDP payloads to a port.

Each payload is a 2-byte big-endian sequence number + 64 bytes of
content derived from that seq. Deterministic so the receiver can
verify by regenerating and comparing.

Used by the wire-compat gate: branch wfb_tx ingests these, runs them
through its FEC + encryption pipeline, and emits on its -D debug port
as UDP-to-loopback. Master wfb_rx (from a git worktree) consumes that,
decrypts, FEC-decodes, and re-emits the plaintext on another UDP port.
If the final plaintext equals what we sent, wire compatibility holds.
"""

import argparse
import socket
import struct
import sys
import time


def payload_for(seq: int, body_size: int = 64) -> bytes:
    # Two-byte big-endian seq + body_size bytes derived from seq.
    # The body is an arbitrary deterministic function of seq so that
    # the receiver can regenerate the same bytes for comparison.
    hdr = struct.pack("!H", seq & 0xFFFF)
    body = bytes((seq * 31 + i * 17) & 0xFF for i in range(body_size))
    return hdr + body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("-n", "--count", type=int, default=100)
    ap.add_argument("--body-size", type=int, default=64)
    ap.add_argument("--pace-ms", type=int, default=2,
                    help="gap between sends to avoid overflowing wfb_tx's "
                         "per-block fill window")
    args = ap.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for seq in range(args.count):
        s.sendto(payload_for(seq, args.body_size), (args.host, args.port))
        if args.pace_ms > 0:
            time.sleep(args.pace_ms / 1000.0)
    s.close()
    print(f"sent {args.count} packets of {2 + args.body_size} bytes each",
          file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
