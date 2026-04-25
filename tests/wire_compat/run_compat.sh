#!/bin/bash
# Wire-compatibility gate for the Phase 1 Step A plumbing edits.
#
# Starts master's wfb_rx and the branch's wfb_tx on a UDP loopback.
# Feeds deterministic UDP payloads through the pipeline and verifies
# they come out the other side unchanged.
#
# Master's wfb_rx is built from /tmp/wfb-master (a git worktree).
# The branch's wfb_tx must be pre-built at $PWD/wfb_tx (i.e. `make
# wfb_tx` before running this script).
#
# Pipeline (UDP loopback, no WiFi):
#
#   send_udp.py --port 5600                    (deterministic sender)
#         |
#         v
#   wfb_tx -u 5600 -D 12000   (branch build; at depth=1 this must be
#   -K drone.key               wire-compatible with master)
#         |
#         v UDP 127.0.0.1:12000
#         |
#   wfb_rx -a 12000 -K gs.key -u 5601 -c 127.0.0.1   (master build)
#         |
#         v UDP 127.0.0.1:5601
#         |
#   recv_udp.py --port 5601   (verifier -- exits 0 iff every packet
#                              arrived exactly)

set -u   # stop on unset var; don't set -e because we want to trap exit codes

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
MASTER="/tmp/wfb-master"

BRANCH_TX="$ROOT/wfb_tx"
MASTER_RX="$MASTER/wfb_rx"
DRONE_KEY="$HERE/keys/drone.key"
GS_KEY="$HERE/keys/gs.key"

INGRESS_PORT=${INGRESS_PORT:-5600}
LOOPBACK_PORT=${LOOPBACK_PORT:-12000}
EGRESS_PORT=${EGRESS_PORT:-5601}
COUNT=${COUNT:-200}
BODY_SIZE=${BODY_SIZE:-64}

# TX / RX args. We use (k=8, n=12) — the default. Epoch 0 is fine.
# -D <port> puts wfb_tx into "wlan emulation" mode: it writes to
# UDP 127.0.0.1:<port> (with a wrxfwd_t envelope) instead of pcap.
# -a <port> puts wfb_rx into "aggregator" mode: it reads from UDP
# <port> (with wrxfwd_t envelope) instead of a WiFi interface.

require() {
    if [ ! -x "$1" ]; then
        echo "FAIL: missing executable $1 -- did you run 'make wfb_tx' in \$ROOT / \$MASTER?" >&2
        exit 2
    fi
}
require "$BRANCH_TX"
require "$MASTER_RX"
if [ ! -f "$DRONE_KEY" ] || [ ! -f "$GS_KEY" ]; then
    echo "FAIL: keys missing under $HERE/keys/ -- regenerate with: (cd $HERE/keys && /tmp/wfb-master/wfb_keygen)" >&2
    exit 2
fi

# Start the verifier first so it's listening when wfb_rx begins emitting.
echo "[wire-compat] launching receiver on :$EGRESS_PORT"
python3 "$HERE/recv_udp.py" --port "$EGRESS_PORT" -n "$COUNT" \
    --body-size "$BODY_SIZE" --timeout 5.0 >/tmp/recv.log 2>&1 &
RECV_PID=$!

# Start master's wfb_rx (aggregator mode).
echo "[wire-compat] launching master wfb_rx"
"$MASTER_RX" -a "$LOOPBACK_PORT" -K "$GS_KEY" \
    -c 127.0.0.1 -u "$EGRESS_PORT" -l 60000 \
    >/tmp/rx.log 2>&1 &
RX_PID=$!

# Give wfb_rx a moment to open its UDP socket.
sleep 0.2

# Start branch's wfb_tx (wlan emulation mode).
echo "[wire-compat] launching branch wfb_tx"
"$BRANCH_TX" -u "$INGRESS_PORT" -K "$DRONE_KEY" \
    -k 8 -n 12 -p 0 \
    -D "$LOOPBACK_PORT" lo \
    >/tmp/tx.log 2>&1 &
TX_PID=$!

# Give wfb_tx a moment to send the first SESSION packet.
sleep 0.5

# Send payloads.
echo "[wire-compat] sending $COUNT payloads to :$INGRESS_PORT"
python3 "$HERE/send_udp.py" --port "$INGRESS_PORT" -n "$COUNT" \
    --body-size "$BODY_SIZE" --pace-ms 2

# Wait for the receiver to decide. It exits on its timeout.
wait $RECV_PID
RECV_RC=$?

# Tear down.
kill "$TX_PID" 2>/dev/null
kill "$RX_PID" 2>/dev/null
wait "$TX_PID" 2>/dev/null
wait "$RX_PID" 2>/dev/null

echo "[wire-compat] receiver summary:"
tail -n5 /tmp/recv.log

if [ "$RECV_RC" -ne 0 ]; then
    echo "[wire-compat] FAIL (rc=$RECV_RC)"
    echo "  tx log: /tmp/tx.log  (last 5 lines:)"
    tail -n5 /tmp/tx.log
    echo "  rx log: /tmp/rx.log  (last 5 lines:)"
    tail -n5 /tmp/rx.log
    exit "$RECV_RC"
fi

echo "[wire-compat] PASS"
exit 0
