# tests/wire_compat — wire-compatibility gate for Phase 1

## What this tests

Phase 1 adds `--interleave-depth N` to `wfb_tx`. Plan §4.1 requires
that the `depth == 1` code path on the wire is **unchanged** from
master — an older master-built `wfb_rx` must still be able to decode
a Phase 1 branch-built `wfb_tx` at `depth == 1`. This directory
provides the gate test for that.

The test is NOT a byte-for-byte diff (session-key is regenerated on
every TX start, so ciphertext differs run-to-run). Instead:

  1. Start a **master-built `wfb_rx`** (aggregator mode).
  2. Start the **branch-built `wfb_tx`** (UDP wlan-emulation mode,
     `-D` flag) pointing at the master RX.
  3. Send 200 deterministic UDP payloads through the branch TX.
  4. Assert every payload arrives byte-identical at the master RX's
     egress port, in order, with zero loss.

If master RX cannot decode branch TX's frames, wire compatibility
has broken.

## How to run

```sh
# One-time setup: build master's wfb_rx in a git worktree.
git worktree add /tmp/wfb-master master
(cd /tmp/wfb-master && make wfb_rx wfb_keygen)

# One-time setup: generate the shared keypair.
(cd tests/wire_compat/keys && /tmp/wfb-master/wfb_keygen)

# Build the branch's wfb_tx.
make wfb_tx

# Run the gate.
bash tests/wire_compat/run_compat.sh
```

Expected final line: `[wire-compat] PASS`.

## Files

- `run_compat.sh` — orchestrator. Starts master RX, starts branch TX,
  runs sender and receiver, tears down on exit.
- `send_udp.py` — deterministic UDP sender. Seq-number-indexed
  payloads; reproducible across runs.
- `recv_udp.py` — verifier. Recv every payload, check each against
  the expected form; exits 0 iff every expected seq arrived intact.
- `keys/drone.key`, `keys/gs.key` — **test fixture** keypair. NOT a
  production secret — regenerate locally if you prefer, the test
  only needs any valid pair. Committed so the test is runnable
  without a manual setup step.

## Why not a pcap byte-identity test?

The original Phase 1 plan called for a byte-for-byte pcap replay
against a captured master TX stream. To make that work you have to
pin the session_key across both runs (libsodium's `randombytes_buf`
fills it from a non-deterministic source on startup). Pinning the
key means patching both the master build and the branch build to
read session_key from env or a test hook — significant infrastructure
to assert a property that's weaker than what this loopback test
gives you. Decoded output from master RX = wire-format compatible,
full stop.

## What this gate catches

- Any change to `wblock_hdr_t` / `wsession_hdr_t` / `wsession_data_t`
  layout at `depth == 1`.
- Any change to fragment-ordering at `depth == 1` (interleaver
  accidentally firing).
- Any change to the `WFB_FEC_VDM_RS` value at `depth == 1`.
- Any nonce-construction change that prevents master RX from
  decrypting.
- Any crypto-scheme change (AEAD swap, nonce width change, etc.).

## What it does NOT catch

- Behavior at `depth > 1` — that's the end-to-end test landed in
  Step D.
- Byte-level layout changes that master RX happens to tolerate —
  acceptable; those are by definition compatible.
