# Adaptive Link — Design Document

**Status:** Draft, pre-implementation. Companion to
[fec-enhancements-v2.md](fec-enhancements-v2.md). A v1.1 revision
block sits directly below — read it first, it corrects several
assumptions the v1 body was written against.
**Scope:** Design only. No source files are modified by this document.
**Relationship to wfb-ng:** The adaptive-link process is a **separate
binary** that lives above wfb-ng. It consumes wfb-ng's stats output,
calls wfb-ng's control API, and additionally controls encoder / radio
/ OS knobs that are outside wfb-ng's scope. It is not part of the
`wfb_tx` / `wfb_rx` binaries.

---

## Changes in v1.1 — post-Phase-1-ship revisions

The original v1 of this document was written against the v1 numbering
of `fec-enhancements.md` and against master's pre-1C rekey semantics.
Between then and now:

- Phase 1 of fec-enhancements (interleaver + control-plane plumbing)
  shipped on branch `feat/interleaving_uep`.
- `fec-enhancements-v2.md` with its v2.1 revision block supersedes v1.
- The rekey design changed from v1 "rotate session_key on every
  `CMD_SET_FEC`" to v2.1 R1 (option 1C) "session_key is
  process-lifetime-constant; refresh keeps the key."
- UEP (v1 Phase 3, v2.1 Phase 2) was deferred; Phase 1's
  single-stream interleaver + adaptive control is being tried on its
  own first.

The following revisions align this doc with the state Phase 1 ships
in. The rest of the document is edited in-place; the R-numbered items
below explain *what changed and why* so a reader diffing against v1
has a fast on-ramp.

**R1 — "Why the controller is slow by design" is wrong under 1C.**
v1 §4 (line ~223) argued the state machine must hunt slowly because
`CMD_SET_FEC` rekeys the session, and during the rekey window RX
decryption fails. That stopped being true at Phase 1 Step C: under
1C the session_key is constant; `CMD_SET_FEC` calls
`refresh_session()` which closes the current FEC block, drains the
interleaver, reconfigures the codec in place, and re-broadcasts
SESSION on the *same* key. RX detects the `(k, n)` change against
the same key and calls `init_fec` without wiping the session.
Observed refresh cost is ≤ 1 block-duration, not the "brief gap in
decryptable data" the v1 text budgets for. The minimum-cooldown
number in §4 and §6 is tightened from 5 s to 200 ms to match the
real floor the TX imposes.

**R2 — IPC contract in §3 shows the master layout, not Phase 1's.**
v1 §3 documents an 11-field RX `PKT` line and a 4-field `SESSION`
line. Phase 1 Step A / Step D shipped a 14-field `PKT` (adds
`bursts_recovered`, `holdoff_fired`, `late_after_deadline`) and a
6-field `SESSION` (adds `interleave_depth`, `contract_version`).
§3 is rewritten; the three new RX-side counters are the most
informative burst-detection signals the daemon has and they sit
directly in the IPC stream.

**R3 — Link target and phase numbering.**
All references to `fec-enhancements.md` now point at
`fec-enhancements-v2.md`. Phase numbering in v1 referred to v1's
five-phase plan (Phase 2 = interleaver, Phase 3 = UEP, Phase 4 =
control-plane). Under v2.1 those are Phase 1, Phase 2, Phase 3
respectively — renumbered in §4, §7 "Phased plan", and §11
"Dependencies."

**R4 — Body rewritten around single-stream.**
v1 §4 "Policy engine" presented the critical/bulk two-stream picture
as the default. In practice UEP (fec-enhancements Phase 2) is
deferred, and the first version of this daemon runs against the
single video stream that fec-enhancements Phase 1 produces. v1.1
restructures §4 so the single-stream case is the primary path. The
two-stream extension is retained as an optional section flagged
"applies when fec-enhancements Phase 2 is enabled." Same for §6
config defaults and §5 safe_defaults.

**R5 — Burstiness metric replaced with RX-side counters.**
v1 §3 derived `burstiness = max_consecutive_lost_in_window /
total_lost_in_window`. That needs per-packet arrival tracking, which
the RX doesn't expose in its 1-second IPC summary — so the daemon
would have to re-derive it from scratch. Phase 1's
`count_bursts_recovered` and `count_holdoff_fired` are better
signals: the RX already knows when a block's losses clustered
together (recovered via FEC from clumped losses) and when its
deadline expired with fragments still in flight (late bursts). The
daemon reads these directly.

**Unchanged:** the safety model in §5, the latency budget in §4,
the phased plan's big-picture shape, the platform backends story.
Those all held up through Phase 1 implementation.

---

## 1. Scope

### In scope

- A single process ("the adaptive-link daemon") that runs per side
  (one on the drone, one on the GCS) and:
  - Consumes link-health signals (stdout `IPC_MSG` from each `wfb_rx`,
    plus any other telemetry operators plumb in).
  - Runs a control loop against a state machine with hysteresis.
  - Drives wfb-ng knobs via `tx_cmd` (get/set FEC, radio params,
    interleave depth).
  - Drives external knobs via pluggable **backends**: radio driver,
    video encoder, OS.
  - Enforces a latency budget and refuses changes that would exceed it.
  - Coordinates between the two UEP streams (Phase 2 of
    fec-enhancements-v2.md; v1.1 scope runs single-stream until
    Phase 2 ships).
- Configuration surface for per-airframe tuning.
- A clear failure model.

### Out of scope

- C changes to `wfb_tx` / `wfb_rx`. Everything this daemon needs from
  wfb-ng is specified in
  [fec-enhancements-v2.md Phase 3](fec-enhancements-v2.md#phase-3--control-plane-api-for-an-external-adaptive-link-process)
  and landed on `feat/interleaving_uep` via Phase 1 Steps A and C
  (the IPC contract is stable, the control commands are implemented).
- The FEC / interleaver / UEP implementations themselves.
- Flight-controller integration (MAVLink RTH triggers, etc.) — we
  expose a `budget_exhausted` signal but the flight stack decides
  what to do with it.

### What this daemon actually decides, concretely

1. Per UEP stream `(k, n)`.
2. Per UEP stream interleaver depth.
3. Radio `mcs_index`, `short_gi`, `bandwidth` (via `CMD_SET_RADIO`).
4. TX power (via radio backend, e.g. `iw`).
5. Encoder bitrate.
6. Encoder GOP length.
7. Encoder ROI (foveated encoding) — where the hardware supports it.
8. Encoder fps.
9. "Emit IDR now" (one-shot request to the encoder).

Items 1–3 reach wfb-ng via `tx_cmd`. Item 4 reaches the radio driver.
Items 5–9 reach the encoder pipeline.

---

## 2. Architecture — one process, pluggable backends

```
                    adaptive-link daemon
                   +---------------------+
    stdout IPC --> |  signal collector   |
    from wfb_rx    +---------+-----------+
                             |
                             v
                   +---------+-----------+
                   |  policy engine      |
                   |  (state machine,    |
                   |   hysteresis,       |
                   |   latency budget)   |
                   +---------+-----------+
                             |
        decision vector      |
                             v
              +--------------+--------------+
              |                             |
        +-----v------+  +---------+  +------v-------+
        | wfb-ng     |  | radio   |  | encoder      |
        | backend    |  | backend |  | backend      |
        | (tx_cmd)   |  | (iw)    |  | (GStreamer / |
        +------------+  +---------+  |  v4l2 / RPC) |
                                     +--------------+
```

### Why a plugin model for backends

Each non-wfb-ng backend is highly platform-specific:

- **Radio backend.** 8812au vs 8812eu vs ath9k_htc vs rtl88x2bu —
  different chipsets, different `iw` options, different regulatory
  concerns. The backend abstracts these behind a tiny interface
  (`set_tx_power(dBm)`, `get_link_stats()`).
- **Encoder backend.** GStreamer pipeline vs. custom ffmpeg pipeline
  vs. v4l2 direct vs. vendor RPC (Rockchip MPP, Allwinner CedarX,
  etc.). The backend exposes a common shape
  (`set_bitrate(bps)`, `set_gop(frames)`, `set_fps(hz)`,
  `set_roi(x, y, w, h, qp_delta)`, `request_idr()`).
- **OS backend.** Optional. Things like CPU governor pinning or
  sysctl tweaks if an airframe ever needs them.

A backend is a Python class (or a subprocess with a documented
stdin/stdout protocol) loaded at startup from the `[link_adapt]`
profile. Unsupported operations return a well-defined "not supported"
code so the policy engine can degrade gracefully.

### Process topology

- **One daemon per side** (drone and GCS).
- **GCS daemon** is where the primary controller runs. It has the
  freshest view of RX stats because those come from the local
  `wfb_rx` processes.
- **Drone daemon** is mostly an executor — it applies commands sent
  from the GCS over the existing return link (stock `mavlink` or
  `tunnel` streams in
  [wfb_ng/conf/master.cfg](../../wfb_ng/conf/master.cfg#L132-L154)).
- The drone daemon also enforces safety independently: it sanity-
  checks every command against its local `[link_adapt]` config and
  rejects anything outside the airframe's ceiling, even if the GCS
  says to do it. Defense in depth.

---

## 3. Signals

### Primary — stdout `IPC_MSG` from `wfb_rx`

Per the contract stabilised in
[fec-enhancements-v2.md Phase 3 §2.1](fec-enhancements-v2.md#21-stable-ipc_msg-contract-rewritten-from-v1)
and landed in Phase 1 Step A, lines on stdout at `log_interval`
cadence (default 1000 ms):

```
<ts> \t RX_ANT  \t <freq:mcs:bw> \t <ant_id> \t <count>:<rssi_min>:<rssi_avg>:<rssi_max>:<snr_min>:<snr_avg>:<snr_max>
<ts> \t PKT     \t <all>:<all_bytes>:<dec_err>:<session>:<data>:<uniq>:<fec_recovered>:<lost>:<bad>:<outgoing>:<outgoing_bytes>:<bursts_recovered>:<holdoff_fired>:<late_after_deadline>
<ts> \t SESSION \t <epoch>:<fec_type>:<k>:<n>:<interleave_depth>:<contract_version>
```

Fields #12–#14 of `PKT` are v1.1 additions (Phase 1 Step D),
documenting RX-side deadline-state-machine activity. Fields #5–#6
of `SESSION` are also v1.1 additions (Phase 1 Step A) —
`interleave_depth` tells the daemon the currently-advertised depth
without a round-trip to `wfb_tx_cmd`, and `contract_version`
identifies this schema as v2 (bumps if fields are reordered or
reinterpreted; plan §2.1 stability commitment).

`SESSION` is now emitted **every `log_interval`** in addition to
on-change (Phase 1 Step A "B2 bootstrap"), so a mid-stream restart
of the daemon sees the current `(k, n, depth)` on the next tick
without waiting for a 1C refresh.

We spawn each `wfb_rx` as a child process of the daemon and read its
stdout line-by-line. Simple, zero new IPC code needed. If this proves
fragile the daemon falls back to a future `CMD_GET_STATS` RX-side
command (deferred).

### Derived metrics per stream, per 1 s window

```
health        = 1 - (count_p_lost + count_p_fec_recovered) / count_p_data
packet_rate   = count_p_data / window_sec

burst_rate    = count_bursts_recovered / window_sec
holdoff_rate  = count_holdoff_fired / window_sec
late_rate    = count_late_after_deadline / window_sec
```

- `health` → drives `(k, n)` (raise `n` on sustained loss).
- `burst_rate` → drives interleaver depth (v1.1 R5 replacement for
  v1's `max_consecutive_lost_in_window` which required per-packet
  arrival tracking the RX doesn't expose). `count_bursts_recovered`
  is RX's count of blocks where FEC recovered ≥ ⌈(n-k)/2⌉ primaries
  in one go — a direct "the channel just dumped a clump on us and
  FEC saved it" signal. Rising → link is getting bursty → raise
  depth to disperse further.
- `holdoff_rate` → deadline fires when the RX gave up waiting for
  fragments. Non-zero means the current `(hold_off_ms)` window is
  too tight for observed inter-arrival jitter, OR the link is
  losing so many fragments the block never completes. Rising under
  sustained depth means the adaptive daemon should either lower
  depth (reduce hold-off) or raise `n` (more parity so fewer
  recoveries hit the wall).
- `late_rate` → fragments arriving after their deadline. Non-zero
  means the TX's hold-off model isn't matching RX's expectation
  (e.g. radio-driver injection delays). Informational; the block
  is already emitted without these late arrivals, but persistent
  non-zero means the hold-off window should grow.
- `packet_rate` → sanity: reject windows with < 100 packets as too
  sparse for reliable statistics.

### Secondary — radio backend

Per-backend: RSSI / SNR / noise floor, bitrate estimate. Cross-checks
what `IPC_MSG RX_ANT` reports — useful for detecting wfb-ng stat
anomalies.

### Tertiary — encoder / telemetry

Bitrate actually achieved, frame-drop counters, encoder queue depth,
external signals like battery voltage, altitude, GCS distance. Not
required for the core loop; useful for sophisticated policies.

---

## 4. Policy engine

### v1.1 scope — single stream

v1 of this doc assumed UEP (fec-enhancements Phase 2) would land
first, so the policy engine ran two independent streams (critical /
bulk). UEP was deferred; the first version of this daemon runs
against the single video stream that fec-enhancements Phase 1
produces. The rest of this section presents the single-stream
controller; the multi-stream extension is in §4A below and kicks
in only if UEP ever ships.

### `(k, n)` policy — single video stream

Four redundancy steps keyed off the state machine below. The
defaults match the master.cfg `[video]` floor of `(k=8, n=12)`:

| State | `(k, n)` | Redundancy | Comment |
|---|---|---|---|
| GOOD       | `(8, 12)` | 50%  | Floor. Most of a flight lives here. |
| DEGRADED   | `(8, 14)` | 75%  | +2 parity. Cheap, one 1C refresh. |
| BAD        | `(8, 16)` | 100% | Twice the parity. |
| VERY_BAD   | `(6, 12)` | 100% | Drop `k` only as last resort (see below). |

**Design choice: keep `k` fixed, vary `n`.** Changing `k` changes
block-fill latency (TX collects `k` primaries before closing a
block); changing only `n` adds parity at the tail without touching
primary collection. The VERY_BAD step drops `k` because once
`n = 16` isn't enough protection the channel is too lossy for FEC
expansion alone; reducing the data-per-block ratio is the next move.

### Interleaver depth policy — single video stream

Ceilings per the FPV latency budget in
[fec-enhancements-v2.md §4.2](fec-enhancements-v2.md#42-latency-budget):

| Floor | 60 fps ceiling | 90 fps ceiling |
|---|---|---|
| 1 | 3 | 2 |

(v1 of this doc had per-stream ceilings of 4 for critical and 3
for bulk. With only one stream and `k=8`, bulk's tighter limit
applies. One depth step at `(k=8, n=12)` costs ~12 ms — depth 3
total latency ~42 ms at the reference operating point, just under
the 50 ms cap.)

### State machine

```
            health < 0.95 for 2s             health < 0.80 for 2s
STATE_GOOD -----------------> STATE_DEGRADED -----------------> STATE_BAD
     ^                                |  ^                        |
     | health > 0.99 for 10s          |  | health > 0.97 for 10s  |
     +--------------------------------+  +------------------------+

                                                health < 0.50 for 4s
                                       STATE_BAD ------------------> STATE_VERY_BAD
                                            ^                             |
                                            | health > 0.90 for 20s       |
                                            +-----------------------------+
```

**Asymmetric hysteresis — step up fast, step down slow.** 2 s to
degrade, 10 s to recover (20 s from VERY_BAD). Health thresholds are
tighter than v1's because the wfb-ng floor is already `(8, 12)` at
50% redundancy — a GOOD link routinely clears 0.99 health.

### Knob selection within a state transition

- `burst_rate` is low (< 1 burst-recovery per second) → raise `n`.
  Losses are uniform; FEC parity budget is the right answer.
- `burst_rate` is rising AND `holdoff_rate > 0` → raise depth.
  Losses clumping + RX missing deadlines = interleaver is sized
  too small.
- Otherwise → raise both one step.

On step-down (link recovering), lower depth first (reclaims the most
latency), then lower `n`. Never lower depth and `n` in the same tick.

### Why the controller cadence can be fast (1C design)

(v1.1 R1: v1 argued the controller must hunt slowly because
`CMD_SET_FEC` rekeys. That's no longer true.)

Phase 1 Step C replaced `init_session` with `refresh_session` under
plan v2.1 R1 (option 1C). `CMD_SET_FEC` and `CMD_SET_INTERLEAVE_DEPTH`
now:

1. Close the currently-open FEC block with FEC-only closers.
2. Flush the interleaver (partial D-frame discarded).
3. Reconfigure FEC + interleaver in place.
4. Broadcast a session-refresh TLV on the **same** `session_key`.

Measured refresh cost: **≤ 1 block-duration** (~12 ms at
`(k=8, n=12)`, regardless of depth). The RX detects same-key-but-
different-`(k, n)` and calls `init_fec` without wiping the session.
No decryption gap.

**Cooldowns can be tight.** The floor of 200 ms matches the
operator-observed minimum interval between real-flight `(k, n, depth)`
changes (obstacle transitions, range-driven bitrate adjustments — see
fec-enhancements-v2.md UNDECIDED-1 v2.1 decision). Going below 200 ms
would start eating non-trivial airtime (each refresh costs ~12 ms =
6% of 200 ms) and offers no control-loop benefit (the state machine's
hysteresis runs on second-scale signals anyway). Going above 1 s
leaves the controller unable to react to burst-behind-trees
transitions. 200 ms is where the plan's cost analysis bottoms out.

Rules:

- Minimum **200 ms** cooldown between any two `CMD_SET_FEC` calls.
- Minimum **200 ms** cooldown between any two
  `CMD_SET_INTERLEAVE_DEPTH` calls.
- Minimum **50 ms** cooldown between a `CMD_SET_FEC` and a
  `CMD_SET_INTERLEAVE_DEPTH` targeting the same stream (the TX
  serialises them, but the RX needs a tick to absorb each refresh
  TLV cleanly).
- State-machine steps fire at most one knob change per tick.

### Latency budget enforcement

Every proposed decision goes through a predictor (see
[fec-enhancements-v2.md §4.2](fec-enhancements-v2.md#42-latency-budget)):

```
latency_total = block_fill_time + block_airtime + fec_decode_time
              + (depth − 1) × block_duration
```

If `latency_total > max_latency_ms`, **the decision is refused**.
The state machine stays at the current level, logs
`budget_exhausted`, and the condition is surfaced to the GCS operator
(and optionally the flight controller). Rationale: beyond the FPV
latency budget the link is unflyable regardless of how reliably the
bytes arrive.

### Encoder-side knobs (when and why)

The adaptive-link doctrine prefers **FEC first, bitrate second,
resolution never** for in-flight degradation. The full escalation
ladder:

1. Raise FEC `n` (cheap on bandwidth).
2. Raise interleaver depth (costs latency, not bandwidth).
3. Drop MCS / widen guard interval (more robust modulation).
4. Drop encoder bitrate (lowers quality but preserves framerate).
5. Drop encoder fps (90 → 60 → 30). Noticeable but flyable.
6. Apply ROI / foveated encoding (center gets budget, edges starve).
7. Drop resolution (pilot-feels-very-wrong; last resort).

Request-IDR-on-command fires whenever the controller transitions
GOOD → DEGRADED or DEGRADED → BAD, so the decoder gets a fresh
keyframe as soon as protection ramps up. (v1 tied this to "critical
stream failure burst" which only made sense under UEP.)

### §4A — UEP extension (applies only if fec-enhancements Phase 2 ships)

If two-stream UEP lands later, the single-stream picture above
extends to two parallel state machines (critical + bulk) sharing
these constraints:

- **Total latency budget** applies to whichever stream dominates
  end-to-end delivery (typically bulk). Never let the combined
  merger-side latency exceed `max_latency_ms`.
- **Critical-stream protection must monotonically increase** as the
  link degrades. If the controller wants to drop critical `n` while
  bulk is still in `STATE_BAD`, it refuses. Critical follows bulk
  on the way down (recovery), not the way up.

v1's per-stream `(k, n)` and depth tables are retained below as the
UEP extension:

| Stream   | Floor          | Step 1          | Step 2          | Step 3 (worst)  |
|----------|----------------|-----------------|-----------------|-----------------|
| Critical | `(2, 6)` 200%  | `(2, 8)` 300%   | `(2, 10)` 400%  | `(1, 6)` 500%   |
| Bulk     | `(8, 10)` 25%  | `(8, 12)` 50%   | `(8, 14)` 75%   | `(6, 12)` 100%  |

| Stream   | Floor | 60 fps ceiling | 90 fps ceiling |
|----------|-------|----------------|----------------|
| Critical | 1     | 4              | 3              |
| Bulk     | 1     | 3              | 2              |

---

## 5. Safety model

Five specific failsafes. These are non-negotiable and enforced at
the applier (drone side) independently of whatever the GCS daemon
sends.

1. **Watchdog on the GCS link.** If no decision packet arrives from
   the GCS daemon for `health_timeout_ms` (default 10 s), the drone
   applier pushes `safe_defaults` once and stops touching the TX
   until a fresh decision arrives. The drone never gets stuck at
   an aggressive setting because the GCS fell off the air.
2. **Oscillation detector.** If the daemon would emit the same
   command > 4 times in 30 s, it locks at the highest recent `n`
   for 60 s. Thrashing is worse than miscalibration. (Under v1
   two-stream: "the same stream's command.")
3. **Never decrease `n` mid-IDR.** UEP-only failsafe; applies when
   fec-enhancements Phase 2 is enabled and the encoder classifier
   is running. The applier buffers any lower-`n` command while the
   classifier reports a critical access unit in progress, applies
   it after the AU boundary. In v1.1 single-stream mode this
   failsafe doesn't trigger (no AU-boundary signal from the
   classifier), but the cooldowns in §4 already throttle `n`
   changes to > 200 ms, and the encoder IDR request pattern in §4
   covers the picture-recovery side.
4. **Never exceed the latency cap.** Predicted-latency check per
   §4 above. Refuse, don't degrade latency.
5. **Safety ceiling enforced locally.** Drone applier independently
   rejects any command whose `(k, n, depth)` is above the per-
   airframe ceiling, even if the GCS signed off on it. If the GCS
   daemon is compromised, the drone still flies inside its envelope.

### What a watchdog-triggered fallback looks like

Single-stream (v1.1 default):

```
safe_defaults = {
    video: (k=8, n=12),   # 50% overhead; matches master.cfg [video] floor
    depth: 1,             # depth 1 = no interleaving, lowest latency
}
```

Two-stream (UEP, fec-enhancements Phase 2 only):

```
safe_defaults = {
    critical: (k=2, n=10),    # mid-aggressive, sane for a drifting link
    bulk:     (k=8, n=12),    # 50% overhead; absorbs moderate loss
    depth:    1,              # depth 1 = no interleaving, lowest latency
}
```

Chosen so that the drone survives until a human (or the flight stack)
reacts.

---

## 6. Config surface — `[link_adapt]` profile

Lives in `master.cfg` in the same style as other wfb-ng profiles.
Not read by wfb-ng itself; consumed by the adaptive-link daemon.
(v1.1: single-stream defaults; two-stream extension keys are kept
commented out until fec-enhancements Phase 2 ships.)

```
[link_adapt]
adaptive_link = false             # master off-switch; default OFF

# Airframe calibration
video_framerate = 60              # 60 or 90; drives depth ceilings
per_packet_airtime_us = 80        # platform-measured; used in predictor

# Latency budget (§4.2 of fec-enhancements-v2.md)
max_latency_ms = 50               # hard cap; refuse changes that exceed

# Hard bounds -- applier enforces these regardless of daemon decisions.
# v1.1 single-stream video defaults:
video_n_min = 12                  # matches master.cfg [video] floor
video_n_max = 16                  # 100% overhead ceiling
video_k_min = 6                   # allows a k=6 drop on VERY_BAD
depth_video_max = 3               # at 60 fps; 2 at 90 fps

# Controller timing. v1.1 tightened under plan v2.1 R1 (option 1C).
min_change_interval_ms_fec = 200      # per-stream cooldown on CMD_SET_FEC
min_change_interval_ms_depth = 200    # per-stream cooldown on depth
min_change_interval_ms_cross = 50     # between a SET_FEC and SET_DEPTH same stream
health_timeout_ms = 10000             # GCS-link watchdog

# Fallback (single-stream video)
safe_defaults = {video: (8, 12), depth: 1}

# Backend plugins
radio_backend   = 'iw'                          # or 'none', or custom
encoder_backend = 'gstreamer'                   # or 'v4l2', 'rpc', ...
encoder_rpc_url = 'unix:///var/run/enc.sock'    # backend-specific

# --- Two-stream UEP extension (fec-enhancements Phase 2 only) ---
# Uncomment and set `uep_enabled = true` when Phase 2 ships.
#uep_enabled = false
#critical_n_min = 6
#critical_n_max = 12
#bulk_n_min = 10
#bulk_n_max = 16
#depth_critical_max = 4
#depth_bulk_max = 3
#safe_defaults_uep = {critical: (2, 10), bulk: (8, 12), depth: 1}
```

`adaptive_link = false` is the default; no behavior change for
operators who don't opt in.

---

## 7. Phased plan

Each phase independently shippable, behind the master off-switch.

### Phase 0 — Observer mode (log-only)

- Daemon runs on GCS only.
- Reads `wfb_rx` stdout (parses the Phase-1-Step-A 14-field PKT and
  6-field SESSION; see §3), computes `health`, `burst_rate`,
  `holdoff_rate`, runs state machine.
- **Emits no commands.** Prints decisions to stdout / file so operators
  can validate the controller's choices match what they would have
  picked by hand.
- Optional: overlay decisions in the OSD (read-only).
- **Files added (net-new):**
  - `<daemon_name>/daemon.py` (or equivalent single-process binary).
  - `<daemon_name>/policy.py` — state machine, hysteresis, knob
    selector.
  - `<daemon_name>/ipcmsg.py` — stdout parser (14-field PKT,
    6-field SESSION per §3).
  - `<daemon_name>/predictor.py` — latency predictor mirroring
    fec-enhancements-v2.md §4.2.
  - `wfb_ng/conf/master.cfg` — new `[link_adapt]` profile with
    `adaptive_link = false`.
- **Risk:** zero to the live link.
- **Verification:** run during a real flight; log output matches
  pilot's subjective "link quality" judgement.

### Phase 1 — wfb-ng backend only

- Daemon starts issuing `CMD_SET_FEC` and
  `CMD_SET_INTERLEAVE_DEPTH`. Both commands already exist in
  `wfb_tx` (fec-enhancements Phase 1 Step C) and in the
  `wfb_tx_cmd` CLI (integration commit); no wfb-ng C changes are
  needed. The daemon shells out to `wfb_tx_cmd` or talks to the
  control UDP socket directly via `src/tx_cmd.h` wire format.
- Drone-side applier added; return link piggybacks on the existing
  `tunnel` stream.
- All four safety failsafes active.
- No encoder/radio backends yet — those knobs stay at their static
  config values.
- **Rollback:** set `adaptive_link = false`.

### Phase 2 — Radio backend

- Add `iw`-based radio backend: TX power adjustment.
- Integrate with state machine as step in escalation ladder.

### Phase 3 — Encoder backend

- Per-platform encoder backend(s): bitrate, fps, GOP, IDR-request.
- ROI / foveated encoding only on hardware that supports it.
- **Biggest variability phase.** Each supported platform is its own
  integration mini-project.

### Phase 4 — Airframe tuning and flight validation

- Per-airframe `[link_adapt]` calibration.
- Controlled-degradation flight test (attenuator sweep, distance
  sweep, urban interference).
- Oscillation detector tuning.
- Sign-off on safe_defaults per airframe.

---

## 8. Example timeline at a realistic burst

60 fps, `max_latency_ms = 50`, attenuation rises over 30 s as drone
flies away and then recovers.

```
t=0s     health 0.99  critical=(2,6)  d=1   bulk=(8,10) d=1   lat 12ms   # floor
t=15s    health 0.75  (2 s degraded, burstiness low → raise n)
t=17s    STATE_DEG.   critical=(2,8)  d=1   bulk=(8,12) d=1   lat 12ms   # +n only
t=22s    health 0.45  (2 s bad, burstiness rising → raise n and depth)
t=24s    STATE_BAD    critical=(2,10) d=2   bulk=(8,14) d=2   lat 25ms
         ...drone turns around, link still poor briefly...
t=29s    cooldown elapsed; daemon raises bulk depth one more step
         STATE_BAD    critical=(2,10) d=2   bulk=(8,14) d=3   lat 37ms   # at ceiling
t=34s    daemon would raise bulk d=4 — refused by depth_bulk_max=3
         (60 fps ceiling). Log budget_exhausted. Stay at current level.
         STATE_BAD    critical=(2,10) d=2   bulk=(8,14) d=3   lat 37ms
t=40s    health 0.90  (recovery starts; 10 s of good needed)
t=50s    STATE_DEG.   critical=(2,8)  d=1   bulk=(8,12) d=2   lat 24ms
t=55s    health 0.98
t=65s    STATE_GOOD   critical=(2,6)  d=1   bulk=(8,10) d=1   lat 12ms   # floor
```

Seven events over 65 s; each separated by ≥ 2 s. The
`budget_exhausted` at t=34 s is the key safety behavior: the
controller refuses to protect harder because doing so would push
latency past the FPV budget and the pilot would lose control-feel
faster than video would improve. The condition is a signal to
return home.

---

## 9. Risks

1. **Oscillation.** Asymmetric hysteresis + cooldown + detector are
   the three-layer defense. Still requires tuning per airframe.
2. **Rekey storm.** A sick stream at the cooldown edge could emit a
   command every 5 s indefinitely. Oscillation detector catches.
3. **Stale telemetry.** The decision packet travels over a stream
   that may itself be failing. Budget one-way telemetry age at ≤ 2 s
   normally; > 2 s → the drone applier considers the GCS down.
4. **Misclassification of burstiness.** `max_consecutive_lost` is a
   rough proxy. Reject windows with < 100 packets.
5. **Backend failure modes.** Each plugin backend can fail
   independently. The daemon must tolerate "encoder backend reports
   error" without crashing; degrade to wfb-ng-only control.
6. **Drone applier and GCS daemon disagreement.** Applier rejects
   commands outside its ceiling. The GCS daemon sees the reject and
   must not re-issue immediately — rate-limit retries.
7. **Priority inversion.** If the daemon itself gets starved (CPU
   overload, disk I/O blocking on stdout parse), decisions lag.
   Daemon runs with a soft real-time priority and avoids disk I/O
   on the hot path.

---

## 10. Open questions

- **Where does this daemon live in the repo?** Options: a `wfb_ng`
  sub-package (Python, reuses the existing Twisted service model),
  a sibling repo (loose coupling, independent lifecycle), or a new
  top-level directory in wfb-ng. Suggest: Python sub-package of
  wfb-ng for Phases 0–1, promote to a sibling repo when encoder
  backends proliferate in Phase 3.
- **Return-link protocol.** Raw UDP packet format over the existing
  `tunnel` stream, or ride MAVLink as a custom message type? Raw UDP
  is simpler; MAVLink couples to flight-stack conventions. Operators
  likely prefer one over the other — decide with the airframe owner.
- **Multi-drone / multi-GCS topologies.** Currently the design
  assumes 1:1. If you ever run one GCS for multiple drones,
  per-drone state must be keyed by `link_id`. Not hard, but worth
  getting right up front.
- **ROI encoding support survey.** Which target SoCs / encoders
  actually support ROI? Design the feature as optional per backend.
- **IDR-on-command cadence.** Should we also throttle IDR requests
  (e.g., no more than one per 500 ms) to avoid a flood of IDRs
  during a sustained bad-link period eating all bandwidth?
- **Flight-controller integration for `budget_exhausted`.** MAVLink
  STATUSTEXT? Custom message? Left open; the daemon just raises
  the signal on a well-known channel.

---

## 11. Dependencies

(v1.1: dependencies that v1 flagged as pre-reqs for Phase 0/Phase 1
of this daemon are all shipped on branch `feat/interleaving_uep`.)

- **Fec-enhancements Phase 1** (interleaver + `CMD_SET_INTERLEAVE_DEPTH`
  + 1C refresh semantics + 14-field `PKT` + 6-field `SESSION`).
  **Status: shipped.** Commits `e71b317` through `d08a94e` on
  `feat/interleaving_uep`. Enables depth as a runtime knob, tight
  rekey cooldowns (§4), and the counter-derived metrics (§3).
- **Stable `IPC_MSG` contract.** **Status: shipped** as part of
  Phase 1 Step A (plan §2.1 `WFB_IPC_CONTRACT_VERSION = 2`).
- **Fec-enhancements Phase 2** (UEP two-stream architecture).
  **Status: deferred.** Without it the daemon runs the
  single-stream policy in §4. If Phase 2 ever ships, the UEP
  extension in §4A + the commented-out keys in §6 activate.

All dependencies needed for this daemon's Phase 0 (observer) and
Phase 1 (wfb-ng backend active) are in place today.
