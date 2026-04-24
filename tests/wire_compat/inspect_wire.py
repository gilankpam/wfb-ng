#!/usr/bin/env python3
"""Capture UDP packets emitted by wfb_tx's wlan-emulation mode and
print the (block_idx, fragment_idx) sequence for each DATA packet.

Used by the Phase 1 Step C visual gate to eyeball that depth>1
produces the interleaved emission order, and that depth=1 produces
block-sequential order.

Each wfb_tx -D <port> UDP packet layout:

   wrxfwd_t envelope   (sizeof=17 bytes, random RSSI/antenna fields)
   wblock_hdr_t:       packet_type (1 byte) + data_nonce (8 bytes BE)
                       data_nonce = (block_idx << 8) | fragment_idx
   ciphertext...

We skip sizeof(wrxfwd_t) = 17, read packet_type, and if it's
WFB_PACKET_DATA (0x2) we decode data_nonce to extract
(block_idx, fragment_idx).
"""

import argparse
import socket
import struct
import sys


WRXFWD_SIZE = 17
# These match src/wifibroadcast.hpp; I had them backwards in the
# first draft -- DATA=1, SESSION=2.
WFB_PACKET_DATA = 0x1
WFB_PACKET_SESSION = 0x2


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("-n", "--count", type=int, default=50,
                    help="capture this many DATA packets then exit")
    ap.add_argument("--timeout", type=float, default=5.0)
    args = ap.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", args.port))
    s.settimeout(args.timeout)

    session_count = 0
    data = []
    while len(data) < args.count:
        try:
            pkt, _ = s.recvfrom(65535)
        except socket.timeout:
            break
        if len(pkt) < WRXFWD_SIZE + 1 + 8:
            continue
        body = pkt[WRXFWD_SIZE:]
        ptype = body[0]
        if ptype == WFB_PACKET_SESSION:
            session_count += 1
            continue
        if ptype != WFB_PACKET_DATA:
            continue
        (nonce,) = struct.unpack("!Q", body[1:9])
        block = nonce >> 8
        fragment = nonce & 0xFF
        data.append((block, fragment))

    s.close()
    print(f"session_packets={session_count} data_packets={len(data)}",
          file=sys.stderr)
    for block, fragment in data:
        print(f"({block},{fragment})")


if __name__ == "__main__":
    sys.exit(main())
