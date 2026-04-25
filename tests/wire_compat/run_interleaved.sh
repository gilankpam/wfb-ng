#!/bin/bash
# End-to-end test: branch TX at depth=D -> branch RX at depth=D,
# zero injected loss. Verifies the Phase 1 Step D deadline state
# machine on the RX can reassemble interleaved blocks correctly.
#
# Payload count is chosen to be a multiple of D*k so the last
# D-frame completes at TX and all fragments reach the wire. Without
# that alignment, the trailing D-frame's last block stays open on
# TX forever (no force-close for fec_timeout=0) and the RX would
# miss the last D*k payloads -- correct behavior, just a test
# artifact.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

TX="$ROOT/wfb_tx"
RX="$ROOT/wfb_rx"
DRONE_KEY="$HERE/keys/drone.key"
GS_KEY="$HERE/keys/gs.key"

DEPTH="${DEPTH:-2}"
K="${K:-8}"
N="${N:-12}"
FRAMES="${FRAMES:-12}"        # number of complete D-frames to send
COUNT=$((FRAMES * DEPTH * K))

INGRESS_PORT=${INGRESS_PORT:-5600}
LOOPBACK_PORT=${LOOPBACK_PORT:-12000}
EGRESS_PORT=${EGRESS_PORT:-5601}

require() {
    if [ ! -x "$1" ]; then
        echo "FAIL: missing $1 (build branch wfb_tx + wfb_rx first)" >&2
        exit 2
    fi
}
require "$TX"
require "$RX"

echo "[interleaved] D=$DEPTH k=$K n=$N frames=$FRAMES count=$COUNT"

python3 "$HERE/recv_udp.py" --port "$EGRESS_PORT" -n "$COUNT" \
    --body-size 64 --timeout 5.0 >/tmp/recv.log 2>&1 &
RECV_PID=$!

"$RX" -a "$LOOPBACK_PORT" -K "$GS_KEY" \
    -c 127.0.0.1 -u "$EGRESS_PORT" -l 60000 \
    >/tmp/rx.log 2>&1 &
RX_PID=$!
sleep 0.2

"$TX" -u "$INGRESS_PORT" -D "$LOOPBACK_PORT" -K "$DRONE_KEY" \
    -k "$K" -n "$N" -p 0 -X "$DEPTH" lo \
    >/tmp/tx.log 2>&1 &
TX_PID=$!
sleep 0.5

python3 "$HERE/send_udp.py" --port "$INGRESS_PORT" -n "$COUNT" \
    --body-size 64 --pace-ms 2

wait $RECV_PID
RC=$?
kill "$TX_PID" "$RX_PID" 2>/dev/null
wait "$TX_PID" "$RX_PID" 2>/dev/null

echo "[interleaved] receiver:"
tail -1 /tmp/recv.log

if [ "$RC" -ne 0 ]; then
    echo "[interleaved] FAIL (D=$DEPTH)"
    echo "  tx log: $(tail -3 /tmp/tx.log)"
    echo "  rx log: $(grep -E '\t(PKT|SESSION)\t' /tmp/rx.log | tail -3)"
    exit "$RC"
fi

echo "[interleaved] PASS (D=$DEPTH)"
