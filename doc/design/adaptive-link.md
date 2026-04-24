# Adaptive Link — Design Document

**Status:** Draft, pre-implementation. Companion to
[fec-enhancements-v2.md](fec-enhancements-v2.md).
**Scope:** Design only. No source files are modified by this document.
**Relationship to wfb-ng:** Two components, by language and by host.

- **GS controller — Python, inside wfb-ng.** A Twisted service
  sub-package of `wfb_ng` (see §3). It subscribes to wfb-ng's
  stats callbacks, runs the state machine, decides `(k, n, depth)`
  plus encoder / radio knobs, and either applies them directly
  (for GS-local wfb_tx and GS-local radio) or ships them over the
  return link for the drone to apply.
- **Drone applier — C, alongside `wfb_tx`.** A small standalone C
  binary (not linked into `wfb_tx`) that listens for decision
  packets on the drone's return-link endpoint, validates each
  against a local safety ceiling, and applies via the `wfb_tx`
  control UDP socket (wire format: `src/tx_cmd.h`), plus invokes
  platform-specific helpers for encoder / radio where relevant.
  The drone runs no Python and no wfb-ng Python service — the
  applier plus `wfb_tx` / `wfb_rx` / `wfb_tun` is the entire
  adaptive-link footprint there.

Neither component modifies the `wfb_tx` / `wfb_rx` C binaries
themselves; both talk to them through the existing control socket
and existing stats plumbing.

---

## 1. Scope

### In scope

**GS controller (Python, Twisted service inside wfb-ng):**

- Consumes link-health signals via wfb-ng's existing `wfb_rx` stats
  callbacks (`ant_stat_cb.update_rx_stats`; see §3), plus any other
  telemetry operators plumb in.
- Runs a control loop against a state machine with hysteresis.
- Enforces a latency budget and refuses decisions that would exceed it.
- For GS-local knobs (its own `wfb_tx`, its own radio): drives
  directly via the local `wfb_tx` control UDP socket and local
  backends.
- For drone-side knobs: emits decision packets over the existing
  return link (`tunnel` stream) to the drone applier.
- Runs against fec-enhancements Phase 1's single video stream.

**Drone applier (C, standalone binary):**

- Listens on a local UDP socket for decision packets arriving
  through the return-link `tunnel`.
- Validates each decision against per-airframe limits from a local
  `[link_adapt]` config file (the safety ceiling).
- Applies accepted decisions:
  - FEC / depth via the local `wfb_tx` control UDP socket (wire
    format: `src/tx_cmd.h`).
  - Radio parameters via platform helpers (`iw`, `CMD_SET_RADIO`).
  - Encoder parameters via a platform-specific helper (subprocess
    or RPC; see §2 backends).
- Enforces the four failsafes of §5 independently of the GS.

**Shared:**

- Configuration surface for per-airframe tuning (§6): master.cfg
  `[link_adapt]` on the GS side; a small drone-side
  `/etc/wfb-link-adapt.conf` (or equivalent) on the drone.
- A clear failure model (§5, §9).

### Out of scope

- C changes to `wfb_tx` / `wfb_rx`. Everything this daemon needs from
  wfb-ng is specified in
  [fec-enhancements-v2.md Phase 3](fec-enhancements-v2.md#phase-3--control-plane-api-for-an-external-adaptive-link-process)
  and landed on `feat/interleaving_uep` via Phase 1 Steps A and C
  (the IPC contract is stable, the control commands are implemented).
- The FEC / interleaver implementations themselves.
- Flight-controller integration (MAVLink RTH triggers, etc.) — we
  expose a `budget_exhausted` signal but the flight stack decides
  what to do with it.

### What the controller actually decides, concretely

The GS controller picks values for these knobs; the drone applier
(for items that live on the drone) validates and applies. Two
control loops own the knobs (see §4):

| # | Knob                               | Loop (§4) | Primary signal        | Applied by                       |
|---|------------------------------------|-----------|-----------------------|----------------------------------|
| 1 | Radio `mcs_index`                  | Leading   | `rssi` / `snr`        | drone applier → `wfb_tx` ctrl    |
| 2 | Radio `bandwidth`                  | Leading   | `rssi` / `snr`        | drone applier → `wfb_tx` ctrl    |
| 3 | TX power                           | Leading (inner) | `rssi` gap from `rssi_target` | drone applier → `iw` helper |
| 4 | Encoder bitrate                    | Leading   | coupled to MCS row    | drone applier → encoder helper   |
| 5 | Encoder fps                        | Leading   | coupled to MCS row (last-resort) | drone applier → encoder helper |
| 6 | Encoder ROI (foveated)             | Leading   | last-resort row only  | drone applier → encoder helper   |
| 7 | `(k, n)` for the video stream      | Trailing  | `k` per MCS row (§4.1 table / §6.1 profile); `n` escalates on `residual_loss`, `fec_work` | drone applier → `wfb_tx` ctrl |
| 8 | Interleaver depth for the video stream | Trailing | `burst_rate`, `holdoff_rate` | drone applier → `wfb_tx` ctrl |
| 9 | Encoder GOP length                 | Both      | transition into protective | drone applier → encoder helper |
|10 | "Emit IDR now" one-shot            | Trailing  | any escalation        | drone applier → encoder helper   |

`short_gi` is deliberately **not** a controlled knob in this
design. The long guard interval (`short_gi = false`, 800 ns) is
more robust against delay spread at flying altitudes and
distances; the ~11 % throughput we give up by avoiding short GI
is a cheap trade for removing one source of PHY-level
instability. `short_gi` is pinned to `false` at the TX and never
changed. Revisit if operator feedback says otherwise.

All knobs are decided on the GS, shipped over the return link as
decision packets, and executed on the drone. The GS's own
`wfb_tx` (return-link FEC) is out of scope — this design leaves
the return link at its static master.cfg defaults.

---

## 2. Architecture — GS controller + drone applier

```
  GS side (Python, inside wfb-ng)          Drone side (C binaries)
  +--------------------------------+       +------------------------------+
  |                                |       |                              |
  |  wfb_rx child (existing)       |       |  wfb_tx (existing)           |
  |    │ stdout IPC_MSG            |       |    ^                         |
  |    v                           |       |    │ tx_cmd.h UDP ctrl       |
  |  protocols.py parser (existing)|       |    │                         |
  |    │ ant_stat_cb                |       |  +-+--------------------+   |
  |    v                           |       |  |                      |   |
  |  +---------------------------+ |       |  | wfb-la-applier       |   |
  |  | adaptive-link service     | |       |  |   (net-new, C)       |   |
  |  |  (net-new, Python)        | |       |  |                      |   |
  |  |                           | |       |  |  - decision parser   |   |
  |  |   signal collector        | |       |  |  - ceiling check     |   |
  |  |        │                  | |       |  |  - 4 failsafes       |   |
  |  |        v                  | |       |  |  - dispatcher        |   |
  |  |   policy engine           | |       |  +--+-------+--------+--+   |
  |  |   (state machine,         | |       |     |       |        |      |
  |  |    hysteresis,            | |       |     v       v        v      |
  |  |    latency budget)        | |       |  +------+ +-----+ +------+  |
  |  |        │                  | |       |  | iw   | | enc | | wfb- |  |
  |  |        v decision         | |       |  | help | | help| |  tun |  |
  |  |   dispatch                | |       |  +------+ +-----+ +---+--+  |
  |  +--+----+-----------+-------+ |       |                       ^     |
  |     │    │           │          |       |  tunnel UDP payload   │     |
  |     │    │           │          |       |  (decision packets)   │     |
  |     │    │           │  return  |       |                             |
  |     │    │           └──link────┼─ → ──>│                             |
  |     │    │  (via wfb_tun/tunnel)|       |                             |
  |     │    v                      |       |                             |
  |     │  (GS-local iw / backends; |       |                             |
  |     │   TX-power etc. on GS TX) |       |                             |
  |     v                           |       |                             |
  |  GS-local wfb_tx ctrl           |       |                             |
  |  (return-link FEC; static       |       |                             |
  |   defaults in this design)      |       |                             |
  +--------------------------------+       +------------------------------+
```

### Why the asymmetry (Python GS / C drone)

- **GS is resource-rich.** A full laptop or SBC running wfb-ng's
  Twisted service, GStreamer decoding, and the OSD renderer.
  Python fits in naturally and reuses wfb-ng's parser / stats /
  control-socket plumbing. The policy engine is second-scale,
  hysteresis-driven — no real-time constraint.
- **Drone is resource-tight.** Typical targets (Radxa Zero 3W,
  OpenIPC SoCs) boot a minimal image without Python. The drone
  applier's job is small: parse decisions, check bounds, issue
  `tx_cmd.h` packets to the local `wfb_tx`. C keeps the runtime
  footprint ~100 KB and avoids adding Python to the drone image.
- **Safety-critical path stays local.** The drone applier
  independently enforces the per-airframe ceiling (§5 failsafe 4)
  and the GS-link watchdog (§5 failsafe 1). A compromised or
  crashing GS cannot push the drone outside its envelope — the
  enforcement is in the drone's own process, in a language with
  no runtime to crash.

### Backends on the drone

Each backend is platform-specific; the C applier uses a tiny
dispatch table with a uniform interface:

```
struct wla_backend {
    const char *name;
    int  (*apply)(const struct wla_command *cmd);
    int  (*probe)(void);      // returns 0 if supported on this platform
};
```

- **Radio backend.** 8812au vs 8812eu vs ath9k_htc vs rtl88x2bu.
  Implementation: the applier either calls `iw` via
  `posix_spawn` (simple; no libnl dep) or links libnl directly on
  platforms where the overhead matters.
- **Encoder backend.** GStreamer pipeline vs. custom ffmpeg
  pipeline vs. v4l2 direct vs. vendor RPC (Rockchip MPP,
  Allwinner CedarX, etc.). The backend exposes `set_bitrate`,
  `set_gop`, `set_fps`, `set_roi`, `request_idr`. Because encoder
  control paths vary widely by platform, the applier typically
  talks to a separate per-platform encoder helper over a local
  Unix socket — keeping the applier itself small and
  platform-agnostic.
- **OS backend.** Optional. CPU governor pinning or sysctl tweaks.

Unsupported operations return `WLA_ENOTSUP` so the policy engine
on the GS, informed via the MAVLink status channel (§10), can
degrade gracefully.

### Process topology

- **GS (Python, Twisted service inside wfb-ng).** One adaptive-link
  service per wfb-ng instance. Primary controller lives here: it
  has the freshest view of RX stats because those come from the
  local `wfb_rx` processes.
- **Drone (C, standalone binary `wfb-la-applier`).** Spawned by
  the drone's init system alongside `wfb_tx`. Pure executor:
  receives decisions, validates, dispatches. Holds no policy
  state of its own beyond the ceiling check and the watchdog
  timer.
- **Return link.** Asymmetric by design (§10):
  - *GS → drone (decision path).* Raw UDP, fixed-size struct,
    explicit endianness, carried over the existing `tunnel`
    stream protocol profile at
    [wfb_ng/conf/master.cfg:282](../../wfb_ng/conf/master.cfg#L282).
    Keeps the drone-side C parser trivially small (one struct,
    no library deps).
  - *Drone → GS (status path).* MAVLink messages over the
    existing `mavlink` stream
    ([master.cfg:261](../../wfb_ng/conf/master.cfg#L261)):
    `STATUSTEXT` for human-readable events, a lightweight
    custom message for structured rejections. Co-locates with
    the flight-controller telemetry the operator already
    reads.

  Both streams are wired into `[drone]` and `[gs]` at
  [master.cfg:132-154](../../wfb_ng/conf/master.cfg#L132-L154).

- **Drone-local OSD sink.** The applier also writes a compact
  text line describing the current adaptive-link state to
  `/tmp/MSPOSD.msg` (default path), which
  [OpenIPC/msposd](https://github.com/OpenIPC/msposd) picks up
  as a custom OSD message and overlays on the outgoing video
  before encoding. No MAVLink dependency — msposd's custom
  message feature is a simple file-drop interface. See §6 drone
  config for the update rate and format knobs, §4B for the line
  format. This is the lowest-friction way to let the pilot see
  the controller's decisions in real time through the same
  video feed they're flying on; no GS OSD plumbing needed on
  top of wfb-ng's existing renderer.

---

## 3. Signals

(All signal consumption is GS-side. The drone applier takes
already-decided commands over the return link; it does not parse
any stats itself.)

### Signal classification

Two primary signals drive the controller, playing different roles:

- **RSSI / SNR (from `RX_ANT`)** — *leading, feed-forward*. The
  physical-layer signal moves before packet loss appears: when
  the link fades, SNR drops seconds before the PER exceeds the
  FEC budget. Drives MCS, TX power, and encoder bitrate — i.e.
  the knobs that set the *link margin*. The goal is to keep RSSI
  well above the MCS sensitivity floor so loss never starts.
- **residual_loss (from `PKT`)** — *trailing, safety-critical*.
  Counts primaries the consumer never saw. In FPV one lost block
  is a visible video glitch; glitches are unacceptable. The rule
  isn't "watch residual_loss trend," it's "any residual_loss > 0
  for even one 100 ms window triggers an immediate protective
  escalation." The feed-forward loop is supposed to prevent this
  from ever firing; when it does fire, the feed-forward loop was
  too slow or had bad calibration.

Everything else (`fec_work_rate`, `burst_rate`, `holdoff_rate`,
`late_rate`) is secondary — useful for picking *which* knob to
turn within an escalation, not for deciding *whether* to escalate.

FPV-specific doctrine: **prefer blocky or slower video over
glitchy video.** That means dropping encoder bitrate, coarsening
MCS, or reducing fps is always preferable to letting
residual_loss become non-zero. The policy engine in §4 enforces
that ordering explicitly.

### Primary source — stdout `IPC_MSG` from `wfb_rx`

Per the contract stabilised in
[fec-enhancements-v2.md Phase 3 §2.1](fec-enhancements-v2.md#21-stable-ipc_msg-contract-rewritten-from-v1)
and landed in Phase 1 Step A, lines on stdout at `log_interval`
cadence (stock default 1000 ms; this design sets it to **100 ms**
— see the "Derived metrics" section below):

```
<ts> \t RX_ANT  \t <freq:mcs:bw> \t <ant_id> \t <count>:<rssi_min>:<rssi_avg>:<rssi_max>:<snr_min>:<snr_avg>:<snr_max>
<ts> \t PKT     \t <all>:<all_bytes>:<dec_err>:<session>:<data>:<uniq>:<fec_recovered>:<lost>:<bad>:<outgoing>:<outgoing_bytes>:<bursts_recovered>:<holdoff_fired>:<late_after_deadline>
<ts> \t SESSION \t <epoch>:<fec_type>:<k>:<n>:<interleave_depth>:<contract_version>
```

Fields #12–#14 of `PKT` (Phase 1 Step D) document RX-side
deadline-state-machine activity. Fields #5–#6 of `SESSION`
(Phase 1 Step A): `interleave_depth` tells the daemon the
currently-advertised depth without a round-trip to `wfb_tx_cmd`,
and `contract_version` identifies this schema as v2 (bumps if
fields are reordered or reinterpreted; plan §2.1 stability
commitment).

`SESSION` is now emitted **every `log_interval`** in addition to
on-change (Phase 1 Step A "B2 bootstrap"), so a mid-stream restart
of the daemon sees the current `(k, n, depth)` on the next tick
without waiting for a 1C refresh. Caveat: the periodic emit is
gated on `session_established` ([src/rx.cpp:572](../../src/rx.cpp#L572)),
so cold start waits up to one `SESSION_KEY_ANNOUNCE_MSEC` (1 s)
before the first `SESSION` line arrives.

**How the GS controller consumes these lines.** wfb-ng already
spawns `wfb_rx` from
[wfb_ng/services.py:174](../../wfb_ng/services.py#L174) (and three
other sites in the same file) and already parses the 14-field
`PKT` and 6-field `SESSION` layouts at
[wfb_ng/protocols.py:392-449](../../wfb_ng/protocols.py#L392-L449).
A separate Python process that also spawned `wfb_rx` would double
the stats pipeline, contend on the radio interface, and split the
view of the link. The GS controller therefore lives **inside**
wfb-ng (§2 "Process topology"): a Twisted service subscribing to
the existing stats callback at
[protocols.py:438](../../wfb_ng/protocols.py#L438)
(`ant_stat_cb.update_rx_stats`). The drone applier never runs
this path — it does not parse IPC_MSG or spawn `wfb_rx`; all of
§3 describes GS-side behaviour only.

### Derived metrics per 100 ms window (10 Hz)

FPV drones move fast (≥ 20 m/s in sport modes, higher in freestyle);
obstacle transitions and antenna-orientation changes can move the
RSSI operating point several dB in under 300 ms. A 1 s metric
window is too slow to react. The GS controller samples at **10 Hz**
(100 ms per window).

To get 10 Hz counters out of `wfb_rx`, set `log_interval = 100` in
the `[common]` section of
[wfb_ng/conf/master.cfg:26](../../wfb_ng/conf/master.cfg#L26).
This is a wfb-ng-wide setting — all consumers (wfb-cli, tuntap
keepalive, the adaptive-link service) will see the faster cadence.
`wfb_rx` / `wfb_tx` `dump_stats()` at the new cadence is cheap; the
practical cost is that `wfb-cli` tables animate 10x faster (display
concern only, no correctness impact — wfb-cli divides byte counts
by `log_interval` to derive rates, so its numbers stay right).

#### Per-window raw counters

Each 100 ms PKT line yields:

```
residual_loss_w  = count_p_lost / (count_p_outgoing + count_p_lost)
fec_work_rate_w  = count_p_fec_recovered / (count_p_outgoing + count_p_lost)
packet_rate_w    = count_p_data / 0.1          # fragments/sec

burst_rate_w     = count_bursts_recovered / 0.1     # events/sec
holdoff_rate_w   = count_holdoff_fired / 0.1
late_rate_w      = count_late_after_deadline / 0.1
```

Each 100 ms RX_ANT line (one per antenna key) yields radio-layer
samples. Reduce across antennas to a single channel estimate:

```
# Per window, taken across all RX_ANT lines in the window:
rssi_min_w   = min_{ant} rssi_min       # worst-case across antennas
rssi_avg_w   = avg_{ant} rssi_avg       # diversity-combined estimate
snr_min_w    = min_{ant} snr_min
snr_avg_w    = avg_{ant} snr_avg
```

`rssi_min_w` is the operational driver — the RSSI the weakest
antenna saw in the window is the margin-limiting number. On
diversity setups a per-antenna failure (obstructed, disconnected)
must not hide the fact that the surviving antenna is being
operated near its sensitivity floor.

At 8 Mbps video on MCS7 40 MHz HT
(`inter_packet_interval ≈ 1.4 ms`, per fec-enhancements-v2.md §4.2),
a healthy link sees **~70 primaries per 100 ms window** and
**~100 data fragments** (primaries + parity at `(k=8, n=12)`).
That's enough packets to spot a state change, but few enough that
single-window outliers matter — a single lost fragment in a window
with 70 primaries reads `residual_loss_w ≈ 0.014`, which would
cross the DEGRADE threshold on its own.

#### EWMA-smoothed controller inputs

Raw per-window values are jittery; smooth via EWMA before the
policy engine consumes them. Smoothing varies by role:

```
# Leading feed-forward signal — want fast reaction, but not
# every fading spike. Half-second time constant.
rssi            = ewma(rssi_min_w,        α = 0.2)   # ≈ 500 ms
snr             = ewma(snr_min_w,         α = 0.2)

# Trailing protective signal — intentionally *not* EWMA-smoothed.
# In FPV, a single-window block loss is already a video glitch;
# reacting on the raw per-window value is the correct behaviour.
residual_loss   = residual_loss_w                   # no smoothing

# Headroom + pattern signals — infrequent events, slower EWMA.
fec_work        = ewma(fec_work_rate_w,   α = 0.2)   # ≈ 500 ms
burst_rate      = ewma(burst_rate_w,      α = 0.1)   # ≈ 1 s
holdoff_rate    = ewma(holdoff_rate_w,    α = 0.1)
late_rate       = ewma(late_rate_w,       α = 0.1)
```

Rationale:

- **`rssi` / `snr`** drive the leading feed-forward loop (§4).
  Half-second smoothing damps single-window fades without masking
  sustained attenuation — perfect for setting MCS and encoder
  bitrate in anticipation of channel changes.
- **`residual_loss`** is *not* smoothed. One lost block in a
  100 ms window is a glitch the pilot will see; the protective
  response must fire on the raw value. Smoothing would delay the
  reaction and amortise multiple glitches into an averaged number
  — exactly the wrong optimisation in FPV.
- **`fec_work` / `burst_rate` / `holdoff_rate` / `late_rate`**
  feed the FEC knob selector within an escalation; clumped-loss
  events are infrequent per-window (often zero), so a slower
  EWMA reduces noise without losing much responsiveness.

**Why this shape for `residual_loss`.** The intuitive-looking
`1 - (lost + fec_recovered) / data` penalises successful FEC
recovery (e.g. 10 % fragment loss fully absorbed by FEC reads
0.89, not 1.0), which makes any state-machine threshold above
0.9 effectively unreachable whenever FEC is doing work.
`residual_loss` is the fraction of primaries the consumer never
saw — unaffected by how much the codec worked behind the scenes.
`fec_work_rate` is tracked separately as an orthogonal signal:
rising `fec_work_rate` means the parity headroom is being
consumed, a cue to raise `n` *before* FEC starts missing.

Both use `count_p_outgoing + count_p_lost` as the denominator —
the estimate of how many primaries the TX actually emitted in
this window. `count_p_data` (used for the `packet_rate` sanity
check) counts every decrypted fragment including parity, so it
is `~n/k` times larger than `count_p_outgoing` and not a useful
loss-fraction denominator.

**Leading feed-forward loop (RSSI-driven):**

- `rssi` / `snr` → drives **MCS**, **TX power**, and **encoder
  bitrate**. RSSI maps through a per-airframe table (§6) to a
  target operating point; the controller steers MCS + bitrate
  together (outer loop) while TX power tracks an RSSI target
  (inner loop) so the link margin stays ≥ `rssi_margin_db`
  above the MCS sensitivity floor. Guard interval is pinned to
  long (`short_gi = false`) for robustness.

**Trailing protective loop (loss-driven):**

- `residual_loss > 0` in any window → **immediate escalation**:
  raise FEC `n` one step, fire IDR. No hysteresis, no wait — the
  pilot already saw the glitch. This is the safety net for when
  the feed-forward loop was wrong or late.
- `residual_loss > 0` sustained across multiple windows → in
  addition to the above, step the feed-forward loop down one
  gear (lower MCS / lower bitrate) as well. The leading loop is
  clearly mis-calibrated and the RSSI thresholds need to be
  tighter.
- `fec_work` rising while `residual_loss == 0` → parity headroom
  is being consumed but not yet exhausted. Raise `n`
  preemptively; this is the *only* time `(k, n)` moves without
  observed loss.

**FEC-knob selectors (within an escalation):**

- `burst_rate` → drives interleaver depth.
  `count_bursts_recovered` is RX's count of blocks where FEC
  recovered ≥ ⌈(n-k)/2⌉ primaries in one go — a direct "the
  channel just dumped a clump on us and FEC saved it" signal.
  Rising → link is getting bursty → raise depth to disperse
  further.
- `holdoff_rate` → deadline fires when the RX gave up waiting
  for fragments. Non-zero means the current `(hold_off_ms)`
  window is too tight for observed inter-arrival jitter, OR the
  link is losing so many fragments the block never completes.
  Rising under sustained depth means the controller should
  either lower depth (reduce hold-off) or raise `n` (more parity
  so fewer recoveries hit the wall).
- `late_rate` → fragments arriving after their deadline.
  Non-zero means the TX's hold-off model isn't matching RX's
  expectation (e.g. radio-driver injection delays).
  Informational; persistent non-zero means the hold-off window
  should grow.

**Sanity:**

- `packet_rate_w` → reject feed-forward decisions when
  `count_p_data < 20` in the window (quiet streams or bitrate
  drops where 10 Hz sampling is too sparse). `residual_loss`
  still fires regardless — a glitch is a glitch even on a sparse
  window.

### Field reference

All counters reset at the end of each `log_interval` window. Code
references point at
[src/rx.cpp](../../src/rx.cpp) and
[src/rx.hpp](../../src/rx.hpp) (the source for every definition
below).

#### `RX_ANT` — one line per (freq, mcs, bw, antenna) key per window

Emitted from
[src/rx.cpp:544-547](../../src/rx.cpp#L544-L547), fed by
`rxAntennaItem::log_rssi` at
[src/rx.hpp:131-148](../../src/rx.hpp#L131-L148).

| Wire field | Type | Meaning |
|---|---|---|
| `freq`       | uint16 dec | Channel frequency in MHz (`IEEE80211_RADIOTAP_CHANNEL`). |
| `mcs`        | uint8 dec  | Radiotap MCS index on the received frame. |
| `bw`         | uint8 dec  | Radiotap bandwidth code (same encoding as radiotap MCS bw field). |
| `ant_id`     | uint64 hex | Composite antenna key: `(src_ipv4 << 32) \| (wlan_idx << 8) \| ant_idx`. `src_ipv4` is 0 unless stats are being forwarded from a remote `wfb_rx` over UDP; `wlan_idx` is the local wlan interface index; `ant_idx` is the radiotap antenna index. Uniqueness is what matters — treat the value as opaque. |
| `count`      | int32 dec  | Number of data-fragment RSSI samples logged to this key in the window. |
| `rssi_min`   | int8 dBm   | Minimum `RADIOTAP_DBM_ANTSIGNAL` seen this window. |
| `rssi_avg`   | int32 dBm  | Integer average (`rssi_sum / count`). |
| `rssi_max`   | int8 dBm   | Maximum RSSI. |
| `snr_min`    | int8 dB    | Minimum of per-fragment `rssi − noise`; `0` when noise is unavailable (`SCHAR_MAX` sentinel). |
| `snr_avg`    | int32 dB   | Integer average (`snr_sum / count`). |
| `snr_max`    | int8 dB    | Maximum SNR. |

Multiple `RX_ANT` lines per window (one per distinct antenna key)
are normal on diversity setups.

#### `PKT` — exactly one line per window

Emitted from
[src/rx.cpp:554-564](../../src/rx.cpp#L554-L564).

| # | Wire field | Counter | Meaning |
|---|---|---|---|
| 1  | `all`                 | `count_p_all`             | Every packet delivered to the aggregator this window (data + session + malformed). Increments at [rx.cpp:649](../../src/rx.cpp#L649). |
| 2  | `all_bytes`           | `count_b_all`             | Total bytes of those packets. Bytes on the wire as seen by the aggregator. |
| 3  | `dec_err`             | `count_p_dec_err`         | Packets that failed decryption or passed decryption but failed a session-data sanity check (channel_id mismatch, bad epoch, unknown fec_type, invalid `(k, n)`, unable to decrypt a data fragment). |
| 4  | `session`             | `count_p_session`         | Valid session (key-announce) packets accepted this window. Includes duplicates of the already-current session (normal; TX re-broadcasts SESSION every `SESSION_KEY_ANNOUNCE_MSEC`). |
| 5  | `data`                | `count_p_data`            | Successfully-decrypted **data fragments** — includes both primaries and FEC parity. Not a primary count. At `(k, n)` with zero loss, `data ≈ n/k × outgoing`. |
| 6  | `uniq`                | `count_p_uniq.size()`     | Number of *unique* data-fragment nonces (`(block_idx, fragment_idx)`) seen this window. Same fragment retransmitted by two radios counts once. |
| 7  | `fec_recovered`       | `count_p_fec_recovered`   | Primaries (indices `0..k-1`) reconstructed via FEC this window. Incremented at [rx.cpp:1019](../../src/rx.cpp#L1019) and [rx.cpp:1059](../../src/rx.cpp#L1059). |
| 8  | `lost`                | `count_p_lost`            | Primaries that were never delivered to the consumer — detected as gaps in the `packet_seq = block_idx × k + fragment_idx` sequence at [rx.cpp:1142-1146](../../src/rx.cpp#L1142-L1146). These are primaries FEC could not recover. |
| 9  | `bad`                 | `count_p_bad`             | Internal errors: short packets, oversize packets, unknown packet types, invalid `fragment_idx`, corrupted payload. |
| 10 | `outgoing`            | `count_p_outgoing`        | Primaries actually emitted to the downstream consumer (non-FEC-only, passed size check). Incremented at [rx.cpp:1165](../../src/rx.cpp#L1165). This is the "primaries delivered" count. |
| 11 | `outgoing_bytes`      | `count_b_outgoing`        | Total payload bytes of outgoing primaries (excludes wpacket header). |
| 12 | `bursts_recovered`    | `count_bursts_recovered`  | Blocks where FEC recovered ≥ `⌈(n−k)/2⌉` primaries in one go — a clumped-loss signal. Only incremented under `interleave_depth > 1`, at [rx.cpp:1067](../../src/rx.cpp#L1067). Zero at depth 1. |
| 13 | `holdoff_fired`       | `count_holdoff_fired`     | Ring-front blocks whose deadline expired before they completed, forcing the ring to drain partial data. Only under `depth > 1`, at [rx.cpp:1120](../../src/rx.cpp#L1120). Zero at depth 1. |
| 14 | `late_after_deadline` | `count_late_after_deadline` | Fragments arriving for a block already retired from the ring (i.e. the TX's inter-packet spread pushed them past RX's deadline). Only under `depth > 1`, at [rx.cpp:910](../../src/rx.cpp#L910). Zero at depth 1. |

**Identities the daemon can rely on:**

```
count_p_all  ≈  count_p_data + count_p_session + count_p_bad + count_p_dec_err
                (≈ rather than = because a SESSION duplicate of the
                 already-current session bumps count_p_session from
                 the pre-decrypt path, and some bad/dec_err paths
                 short-circuit before the classification counter
                 would have incremented.)

count_p_outgoing  =  primaries_native + count_p_fec_recovered
                     where primaries_native is not exposed directly.
count_p_data      =  primaries_native + parity_received
                     so  count_p_data + count_p_fec_recovered >= count_p_outgoing
                     (parity_received >= 0).

count_p_outgoing + count_p_lost  ≈  primaries the TX emitted this window
                 (the TX-emitted primary count is what `residual_loss`
                  in §3 uses as its denominator.)
```

#### `SESSION` — emitted on-change and once per window after `session_established`

Emitted from
[src/rx.cpp:574-576](../../src/rx.cpp#L574-L576) (periodic) and
[src/rx.cpp:816-818](../../src/rx.cpp#L816-L818) /
[src/rx.cpp:838-840](../../src/rx.cpp#L838-L840) (on-change).

| # | Wire field | Type | Meaning |
|---|---|---|---|
| 1 | `epoch`            | uint64 dec | TX-chosen session epoch. Monotonic; RX rejects SESSION packets with epoch < current. |
| 2 | `fec_type`         | uint8 dec  | `1` = `WFB_FEC_VDM_RS` (stock Reed-Solomon, no interleaving). `2` = `WFB_FEC_VDM_RS_INTERLEAVED` (same codec, interleaved on-air). Any other value is rejected by RX with `count_p_dec_err += 1`. |
| 3 | `k`                | int dec    | FEC `k`, current session. |
| 4 | `n`                | int dec    | FEC `n`, current session. |
| 5 | `interleave_depth` | uint dec   | `1..255`. TX with depth = 1 omits the TLV; RX then defaults to 1. At depth > 1, the TX emits `TLV_INTERLEAVE_DEPTH` inside the session data; RX parses at [rx.cpp:778-788](../../src/rx.cpp#L778-L788). |
| 6 | `contract_version` | uint dec   | `WFB_IPC_CONTRACT_VERSION` — currently `2`. Bumped only on breaking schema changes (field reorder / reinterpretation). Trailing fields may be appended without bumping. |

### Secondary — radio driver cross-check

The radio backend (`iw` / nl80211) can report RSSI / SNR / noise
floor and bitrate estimate directly. These cross-check what
`IPC_MSG RX_ANT` reports — useful for detecting wfb-ng stat
anomalies or a flaky radio. The controller does not use them as
inputs to the policy engine; `RX_ANT` is the authoritative source.

### Tertiary — encoder / flight telemetry

Bitrate actually achieved by the encoder, frame-drop counters,
encoder queue depth, external signals like battery voltage,
altitude, GS distance. Not required for the core loop; useful for
sophisticated policies (e.g. knowing the drone is far away biases
toward defensive FEC; a low battery biases toward lower bitrate to
save wifi TX power).

---

## 4. Policy engine

Two coupled loops run against the single video stream that
fec-enhancements Phase 1 produces:

1. **Leading loop — RSSI-driven feed-forward** (§4.1). Keeps the
   link margin healthy. Sets MCS, TX power, and encoder bitrate
   from the observed `rssi` via a per-airframe table. Purpose:
   prevent loss from ever starting. (`short_gi` stays pinned to
   `false` — long guard interval is more robust at FPV distances;
   not controlled.)
2. **Trailing loop — loss-driven protective** (§4.2). Fires the
   instant `residual_loss > 0`. Raises FEC `n`, fires IDR, and —
   if loss is sustained — drops the leading loop down a gear.
   Purpose: safety net for when the leading loop was slow or
   mis-calibrated.

The two loops are intentionally asymmetric. The leading loop
operates on a half-second time scale (SNR changes that fast);
the trailing loop operates on a per-window time scale (a single
100 ms window with any loss is already a glitch the pilot saw).

### §4.1 — Leading loop: RSSI → (TX power, MCS, bitrate)

The leading loop is two nested controllers, keyed by time
constant:

- **Inner, fast: TX-power closed loop.** Targets a fixed
  `rssi_target_dBm` (default −60 dBm). Every ~1 s, nudge TX
  power up/down so observed `rssi` approaches target. Heavy
  anti-oscillation guards — see below.
- **Outer, slower: MCS / bitrate selector.** Maps the observed
  `rssi` to a `(mcs, bitrate)` row. Runs on the §3 EWMA-smoothed
  `rssi`, with hysteresis.

The inner loop normalises the link so the outer loop sees a
stable RSSI under most conditions. Only when TX power saturates
at the regulatory cap (and observed `rssi` still drops) does the
outer loop move down a row — that's the channel actually fading
faster than we can compensate.

#### Inner loop — TX-power control

Closed-loop rule, evaluated every
`tx_power_cooldown_ms` (default 1000 ms):

```
delta_db = rssi_target_dBm - rssi        # negative when we're above target
if abs(delta_db) < rssi_deadband_db:
    continue                             # inside the dead-band; do nothing
tx_power_new = clamp(tx_power_current + delta_db,
                     tx_power_min_dBm, tx_power_max_dBm)
if tx_power_new == tx_power_current:
    continue                             # already saturated or rounded away
emit CMD_SET_RADIO(tx_power=tx_power_new)
```

**Anti-oscillation (load-bearing — the naive "rssi low → raise
power → rssi high → drop power" loop otherwise rings forever):**

- **Dead-band (`rssi_deadband_db`, default 3 dB).** Ignore
  observed RSSI within ±3 dB of target. RF noise makes ±1–2 dB
  window-to-window jitter normal; reacting to it would chase
  noise. The dead-band must exceed the RSSI measurement noise.
- **Cooldown (`tx_power_cooldown_ms`, default 1 s).** At most
  one power step per second, even if RSSI is far from target.
  The link takes a few windows to settle after a power change;
  reacting faster overshoots.
- **MCS-change freeze (`tx_power_freeze_after_mcs_ms`, default
  2 s).** When the outer loop changes MCS, hold TX power steady
  for 2 s. MCS negotiation and radio re-initialisation can
  produce transient RSSI artefacts; power-adjusting on those
  would put the two loops into a fight.
- **Bounded per-step correction (clamp delta to ±3 dB).** Even
  if `delta_db` reads 15 dB (sudden obstacle), the single step
  is ≤ 3 dB. If the fade is real, the next tick (1 s later) will
  pick up the remaining delta. This keeps the loop well-damped
  even when observations are noisy.
- **Gain asymmetry (optional, per-airframe).** Some operators
  prefer `gain_up > gain_down` — raise power eagerly, drop it
  conservatively — to minimise the risk of running under-powered
  during a fade. Exposed as `tx_power_gain_up_db`,
  `tx_power_gain_down_db` in §6; default both to 1.0 (symmetric).

TX power changes are **not** advertised to the encoder or the
trailing loop. They're a pure link-margin adjustment.

#### Outer loop — MCS / bitrate table

The operating-point table maps `rssi` (EWMA-smoothed min across
antennas, §3) to a target `(mcs, bitrate_Mbps)`. Per-card radio
profile loaded at startup from `wfb_ng/conf/radios/<name>.yaml` —
see §6.1 for the file format and the `m8812eu2` default.

**Design rules common to all profiles:**

- MCS is capped at 7 (1T1R SISO). MCS 8–15 (2T2R MIMO) are
  deliberately out of scope for this controller — the mechanism
  to drive them would need per-antenna path-loss tracking, which
  the current RX_ANT pipeline doesn't surface cleanly. Single
  stream is enough for FPV video bandwidth.
- Bitrate number at each row is ~40–50 % of the nominal LGI
  throughput for that (bandwidth, MCS), leaving headroom for FEC
  parity (`(k, n) = (8, 12)` baseline = 50 % overhead) plus
  telemetry + re-tx margin.
- Sensitivity + `rssi_margin_db` determines the row's lower
  bound: `row_rssi_min_dBm = sensitivity_dBm + rssi_margin_db`.

**Default (M8812EU2, HT20, long GI), at `rssi_margin_db = 8`:**

| Band (dBm)          | MCS | bitrate  | `k` (§4.2 band) |
|---------------------|-----|----------|------------------|
| `rssi >= -69`       | 7   | 26 Mbps  | 8                |
| `-72 <= rssi < -69` | 6   | 23 Mbps  | 8                |
| `-74 <= rssi < -72` | 5   | 21 Mbps  | 6                |
| `-77 <= rssi < -74` | 4   | 16 Mbps  | 6                |
| `-80 <= rssi < -77` | 3   | 10 Mbps  | 4                |
| `-83 <= rssi < -80` | 2   |  8 Mbps  | 4                |
| `-85 <= rssi < -83` | 1   |  5 Mbps  | 2                |
| `-88 <= rssi < -85` | 0   |  3 Mbps  | 2                |
| `rssi < -88`        | —   | —        | — (`budget_exhausted`, RTH) |

Boundaries are `sensitivity_dBm + rssi_margin_db` for each MCS.
Bitrates are `data_rate_Mbps_LGI * 0.40` (see profile).
Profile provenance (which rows came from the vendor datasheet
vs. interpolation) lives in the profile file's header comment,
not in this runtime table — operators are expected to
field-validate the whole map per airframe regardless.

`k` per row keeps block-fill time proportional to bitrate, so
FEC latency stays ≲ 5–10 ms at every MCS row instead of running
up to 32 ms at k=8 / 3 Mbps. See §4.2 "(k, n) ladder" for the
per-k `n`-escalation ladders the trailing loop uses within each
band.

**fps adjustment.** The values above are tuned for the 60 fps
latency cap (50 ms). At 90 fps (33 ms cap) the latency-budget
predictor (§4 "Latency budget enforcement") may auto-drop `k`
one band when the preferred value combined with depth > 1 would
exceed the tighter cap. This is the same refusal/auto-adjust
mechanism that governs depth — no new subsystem. Operators who
want a hard fps-specific override can ship an `m8812eu2_90fps`
profile with the adjusted `k` column baked in.

These are illustrative — actual MCS/sensitivity numbers are
chipset-specific. The per-airframe `rssi_mcs_map` in
`[link_adapt]` (§6) overrides the defaults after field
calibration.

**Row hysteresis.** 3 dB upper guard: to move *up* a row,
smoothed `rssi` must exceed the new row's lower bound by 3 dB
for at least 2 s. To move *down* a row: `rssi` below current
row's lower bound for 500 ms. Asymmetric — fast down, slow up.

**Why this composition is stable.** Inner loop's dead-band
(±3 dB around target) is larger than the outer loop's hysteresis
guard (3 dB), so inner-loop corrections never move the outer
loop on their own. The outer loop only trips when either (a) TX
power saturates at the regulatory max and the fade continues, or
(b) the fade exceeds `rssi_target ± 3 dB` for long enough that
the inner loop's 1 s cooldown hasn't caught up — in both cases
we want the MCS drop.

**Encoder bitrate derives from MCS row.** Conservative: ~50–60 %
of the nominal MCS throughput at `(k=8, n=12)` overhead, leaving
airtime for FEC parity + re-tx + telemetry.

**Commands emitted:**

- MCS → `CMD_SET_RADIO` to the drone's `wfb_tx` (with
  `short_gi = false` always — the applier pins it regardless of
  what the GS sends).
- TX power → radio backend (`iw` helper) on the drone.
- Encoder bitrate → encoder-backend helper on the drone
  (Phase 1 wiring; §7).

MCS and encoder bitrate travel in the same decision packet so
the applier either applies both or neither (atomicity matters —
an MCS drop without a matching bitrate drop queues airtime debt
that becomes loss). TX-power changes are independent and can fly
in their own decision packet.

### §4.2 — Trailing loop: loss-driven protective escalation

**Reaction is immediate, not hysteresis-delayed.** One 100 ms
window with `residual_loss > 0` means the pilot already saw a
glitch. The controller treats that as a ground-truth signal that
the leading loop was too optimistic, and responds on the same
tick:

| Trigger (this 100 ms window) | Actions (all on the same decision packet)                                                    |
|---|---|
| `residual_loss_w > 0`        | (a) raise FEC `n` one step **within the current `k`-band** (§4.2 ladder; e.g. at `k=8` the steps are `(8,12) → (8,14) → (8,16)`). If already at the top `n` of the band, drop into the next lower band at its floor (`(6, 12)` for `k=8`) — the "Step 3 drops k" transition.<br>(b) **request an IDR from the encoder** (GS → drone applier → encoder helper, §2): the current GOP is already corrupted by the lost primary, so the decoder needs a fresh keyframe to resync cleanly; waiting for the next scheduled IDR would extend the blocky patch.<br>Issued via `CMD_SET_FEC` with the new `(k, n)`. |
| `residual_loss_w > 0` *and* last two windows also had loss | All of the above, *plus* step the leading loop down one MCS row (force-drop via `CMD_SET_RADIO`, inner TX-power loop stays frozen for `tx_power_freeze_after_mcs_ms`). If the new row sits in a lower `k`-band, the trailing loop rebases at the new band's floor rather than stacking escalations. Repeat-loss means the leading loop's calibration is wrong, not just a one-off. |
| `fec_work` rising, `residual_loss_w == 0` | raise `n` one step within the current `k`-band, preemptively (waits for next `min_change_interval_ms_fec` boundary). No IDR — nothing has glitched yet. |

**IDR-request mechanics.** The request flows:

1. GS service detects `residual_loss_w > 0` → appends an
   `idr_request` flag to the outgoing decision packet on the
   same tick.
2. Drone applier receives the decision, applies FEC change via
   `CMD_SET_FEC`, and dispatches `idr_request` to the encoder
   helper over the local Unix socket (Phase 1 wiring;
   `/var/run/wfb-enc.sock`).
3. Encoder helper forces an IDR on the *next* encoded frame.

End-to-end latency from loss event to next IDR hitting the wire
is ~1 frame period (16.7 ms at 60 fps) plus the return-link RTT
(typically < 10 ms). Well inside the "pilot just saw one blocky
block" window — the next frame recovers.

**Cooldown bypass.** The trailing loop's `residual_loss_w > 0`
path **bypasses** `min_change_interval_ms_fec` (see §4 cooldown
rules). A glitch is a glitch; we pay the 12 ms 1C refresh cost
+ one frame of IDR bandwidth immediately rather than waiting
out the cooldown. IDR flood is prevented separately by the
drone applier's `min_idr_interval_ms` throttle (default 500 ms,
§6 drone config, §10).

**`(k, n)` ladder — per-MCS-row `k`, per-k `n` escalation.**
`k` is set by the radio profile row (§6.1) for the current MCS;
`n` escalates within that row in response to loss. Why split
this way:

- **`k` is driven by bitrate, not by loss.** Block-fill time is
  `k × MTU × 8 / bitrate`. At low bitrate, `k=8` fills so slowly
  that even depth 1 blows the FPV latency cap. A per-row `k`
  keeps block-fill proportional to frame period at every
  operating point.
- **`n` is driven by loss.** Within a given `k`, additional
  parity is the cheap-on-latency, expensive-on-airtime knob that
  responds to observed channel quality at that MCS row.

Four steps per `k`-band, same shape across all bands (floor →
+25% → +50% → drop `k`):

| k  | Floor       | Step 1      | Step 2      | Step 3 (drop k) |
|----|-------------|-------------|-------------|-----------------|
| 8  | `(8, 12)`   | `(8, 14)`   | `(8, 16)`   | `(6, 12)`       |
| 6  | `(6, 10)`   | `(6, 12)`   | `(6, 14)`   | `(4, 8)`        |
| 4  | `(4, 8)`    | `(4, 10)`   | `(4, 12)`   | `(2, 6)`        |
| 2  | `(2, 4)`    | `(2, 6)`    | `(2, 8)`    | `(1, 4)`        |

The `k=8` band matches master.cfg `[video]`'s existing floor of
`(k=8, n=12)` and is the steady-state at MCS 6–7.

**Why Step 3 drops `k` (not just raises `n` further).** Once
loss has escalated to the `n_max` row of a band and is still
non-zero, the channel is too lossy for parity expansion alone;
reducing `k` (i.e. the data-per-block ratio) buys finer-grained
recovery. Step 3 is the transition into the next-lower band —
typically the next MCS-row change follows it within seconds.

**Band boundary crossings.** When the leading loop changes MCS
row and the new row's preferred `k` differs from the current
`k`, the trailing loop issues a `CMD_SET_FEC` to rebase at the
new band's floor (or nearest equivalent protection level). Cost:
one 1C refresh (~12 ms stall + (D−1) blocks discarded). With
hysteresis on the leading loop, MCS-row changes are seconds
apart at worst, so band crossings are not a busy path.

**Interleaver depth ladder.** Ceilings per the FPV latency
budget in
[fec-enhancements-v2.md §4.2](fec-enhancements-v2.md#42-latency-budget):

| Floor | 60 fps ceiling | 90 fps ceiling |
|---|---|---|
| 1 | 3 | 2 |

Per fec-enhancements-v2.md §4.2 worked example, one depth step
at `(k=8, n=12)` adds ~12 ms; depth 3 total latency ~37 ms at
the reference operating point — matches the `(k=8, n=14) d=3 =
37 ms` row in §4.2's table, under the 50 ms cap.

**Within a protective escalation, which FEC knob moves?**

- `burst_rate` low (< 1 burst-recovery / s on the EWMA) → raise
  `n`. Losses are uniform; FEC parity budget is the right answer.
- `burst_rate` rising AND `holdoff_rate > 0` → raise depth.
  Losses clumping + RX missing deadlines = interleaver is sized
  too small.
- Both signals present → raise both one step.

**On step-down** (multiple consecutive windows with
`residual_loss_w == 0` *and* rising `rssi`), lower depth first
(reclaims the most latency), then lower `n`. Never lower depth
and `n` in the same tick. The leading loop drives its own
step-up (MCS/bitrate) independently via §4.1's hysteresis.

### Why the controller cadence can be fast (1C design)

Phase 1 Step C wired `refresh_session` under plan v2.1 R1 (option
1C): `session_key` is process-lifetime-constant;
`CMD_SET_FEC` / `CMD_SET_INTERLEAVE_DEPTH` reconfigure the codec in
place and re-broadcast SESSION on the same key. Each command:

1. Close the currently-open FEC block with FEC-only closers.
2. Flush the interleaver (partial D-frame discarded).
3. Reconfigure FEC + interleaver in place.
4. Broadcast a session-refresh TLV on the **same** `session_key`.

Refresh cost — **two components** (budgeted from
fec-enhancements-v2.md §4.2, not measured; Phase 1 bench only
covers encode/decode paths):

- **Stall** (no-data window on the TX): ≤ 1 block-duration (~12 ms
  at `(k=8, n=12)`). Independent of depth — just the time to close
  the currently-open FEC block.
- **Data loss**: up to `(D − 1)` blocks of in-flight payload
  discarded when the interleaver flushes, aged out by RX's Step D
  deadline sweep. Scales with depth — at D=3 that's up to ~24 ms
  of payload per refresh (~one frame at 60 fps).

On the RX: `session_key` is preserved, but the rx_ring is wiped
via `deinit_fec` when `(k, n)` changes. No decryption gap; the
in-flight blocks at refresh time are discarded consistent with the
TX-side loss budget above.

**Cooldowns — policy, not code-enforced.** The TX accepts
back-to-back refreshes at any interval the control socket can
serve; these floors are chosen by the daemon. 200 ms matches the
operator-observed minimum interval between real-flight
`(k, n, depth)` changes (obstacle transitions, range-driven bitrate
adjustments — see fec-enhancements-v2.md UNDECIDED-1 v2.1 decision).
Going below 200 ms gets expensive on the data-loss side: at D=3,
~24 ms of payload per refresh against a 200 ms interval is ~12 %
of the video stream potentially dropped at the cooldown floor.
Going above 1 s leaves the controller unable to react to
burst-behind-trees transitions. 200 ms is the pragmatic midpoint.

Rules (all daemon-side policy):

- Minimum **200 ms** cooldown between any two `CMD_SET_FEC` calls.
- Minimum **200 ms** cooldown between any two
  `CMD_SET_INTERLEAVE_DEPTH` calls.
- Minimum **50 ms** cooldown between a `CMD_SET_FEC` and a
  `CMD_SET_INTERLEAVE_DEPTH` targeting the same stream. Chosen to
  avoid stacking two refreshes into overlapping block-closer
  windows; the TX handles back-to-back refreshes correctly, so
  this is latency-of-a-single-refresh padding, not a correctness
  constraint.
- State-machine steps fire at most one knob change per tick
  (daemon policy; "never lower depth and `n` in the same tick" in
  the knob-selection rules below is enforced here, not by the TX).

### Latency budget enforcement

Every proposed decision goes through a predictor (see
[fec-enhancements-v2.md §4.2](fec-enhancements-v2.md#42-latency-budget)):

```
latency_total = block_fill_time + block_airtime + fec_decode_time
              + (depth − 1) × block_duration
```

The predictor runs before every proposed knob change. Two
outcomes:

1. **Proposed `(k, n, depth)` fits the budget** → decision goes
   through.
2. **Proposed combination exceeds the budget** → the predictor
   auto-adjusts *downward* in this priority order, re-predicting
   after each step:
   - Drop `depth` by 1 (reclaims `block_duration` of latency per
     step; cheap to unwind if the channel improves).
   - If depth is already 1 and the budget still doesn't fit,
     drop `k` to the next-lower band (per §4.2 ladder); `n` is
     rebased to the new band's floor or the nearest equivalent
     protection.
   - If no combination fits (even `(2, 4), d=1`), **refuse**.
     The controller holds the current state, logs
     `budget_exhausted`, and surfaces the condition to the GS
     operator (and optionally the flight controller).

This is where fps-dependence hits the decision flow: at 90 fps
`max_latency_ms` shrinks to ~33 ms, so the auto-adjust will step
through a lower-k band earlier in the escalation than it would
at 60 fps / 50 ms. Rationale: beyond the FPV latency budget the
link is unflyable regardless of how reliably the bytes arrive —
better to return home at the current level than add latency
that breaks control-feel.

### Full knob ordering — who moves when

The two loops partition the nine knobs from §1:

| Knob group        | Owner (loop)                    | Trigger                           |
|-------------------|---------------------------------|-----------------------------------|
| MCS               | Leading (§4.1, outer loop)      | observed `rssi` crosses a row boundary (inner TX-power loop saturated or fade faster than cooldown) |
| Encoder bitrate   | Leading (§4.1, outer loop)      | Row change (coupled to MCS)       |
| Encoder fps       | Leading (§4.1), last-resort row | `rssi` < MCS-0 floor              |
| `(k, n)`          | Trailing (§4.2)                 | `residual_loss > 0` or `fec_work` rising |
| Interleaver depth | Trailing (§4.2)                 | `burst_rate` + `holdoff_rate`     |
| TX power          | Leading (§4.1, inner loop)      | closed-loop to `rssi_target_dBm` (dead-band + cooldown; see §4.1) |
| Encoder ROI       | Leading (§4.1), optional        | Only when bitrate pinned to floor |
| Emit IDR          | Trailing (§4.2)                 | Any `residual_loss_w > 0` window (rate-limited by `min_idr_interval_ms`) |

**FPV doctrine on degradation order.** When the leading loop
exhausts its table (even at MCS 0, RSSI still below floor),
degrade the encoder in this order before resorting to dropping
out:

1. Drop encoder **bitrate** further (already coupled to MCS, but
   a fixed floor per MCS row lets us squeeze more).
2. Drop encoder **fps** (90 → 60 → 30). Noticeable but flyable.
3. Apply **ROI / foveated encoding** (centre gets budget, edges
   starve). Only on hardware that supports it.
4. Drop **resolution**. Pilot-feels-very-wrong; last resort.

**Resolution never for normal degradation** — only on the
last-row failure path. The FPV preference is blocky video over
glitchy video, so the encoder becomes the knob that absorbs the
bandwidth crunch; FEC stays generous.

**IDR-on-command** fires on every `residual_loss_w > 0` window
(§4.2) so the decoder gets a fresh keyframe the moment protection
ramps up — the previous GOP is already corrupted by the lost
primary and continuing to diff off it only extends the visible
artefact. Rate-limited by `min_idr_interval_ms` (default 500 ms)
to keep a sustained loss event from flooding keyframes onto the
link. The leading loop does *not* request IDR on MCS / bitrate
changes by itself; MCS changes at matched bitrate drops don't
corrupt the GOP, so no keyframe is needed.

### §4B — Drone-local OSD output

The applier writes its current state to `/tmp/MSPOSD.msg`
(default; overridable in drone config) every
`osd_update_interval_ms` milliseconds (default 1000 ms).
[OpenIPC/msposd](https://github.com/OpenIPC/msposd) reads the
file and overlays the text on the outgoing video before it
reaches the encoder, so the pilot sees the current profile
through the same video feed they're flying.

**Line format (one line, fits in ~40 columns for typical OSD
fonts):**

```
LA MCS7 26M (8,12)d1 TX23 R-60
```

Fields, in order:

| Token              | Meaning                                  |
|--------------------|------------------------------------------|
| `LA`               | Fixed prefix — "link-adapt"              |
| `MCS7`             | Current MCS index                        |
| `26M`              | Current encoder bitrate (Mbps, int)      |
| `(8,12)d1`         | Current `(k, n)` and interleaver depth   |
| `TX23`             | Current TX power (dBm, int)              |
| `R-60`             | Most recent smoothed `rssi` (dBm, int)   |

Events append a second line for one update cycle:

```
LA IDR  (n↑) loss@t=19.1s
LA MCS6→MCS5 k-rebase (6,10)
LA WATCHDOG safe_defaults
```

msposd renders both lines if present. Color codes (msposd's
custom-message convention) are applied to draw protective
escalations in red / amber. Colour mapping lives in the drone
config — operators who find the colours distracting can disable
per field.

The OSD sink is a file write at 1 Hz; overhead is negligible,
and `/tmp` being tmpfs on typical OpenIPC images means no disk
I/O. If the applier crashes, `/tmp/MSPOSD.msg` stops being
refreshed; msposd keeps showing the last message — note it's
stale, not live.

---

## 5. Safety model

Four specific failsafes. Failsafes 1 and 4 live inside the drone
C applier (non-negotiable, in-process, independent of the GS).
Failsafes 2 and 3 live inside the GS Python service (the decision
source). The split is deliberate: anything that protects the drone
from a sick GS must not depend on the GS.

1. **Watchdog on the GS link.** *(Drone applier, C.)* If no
   decision packet arrives for `health_timeout_ms` (default 10 s),
   the applier pushes `safe_defaults` once to the local `wfb_tx`
   control socket and stops touching the TX until a fresh decision
   arrives. The drone never gets stuck at an aggressive setting
   because the GS fell off the air.
2. **Oscillation detector.** *(GS service, Python.)* If any knob
   emits the same command > 4 times in 30 s, the controller locks
   it at its highest recent value for 60 s. Applies to
   `CMD_SET_FEC`, `CMD_SET_INTERLEAVE_DEPTH`, `CMD_SET_RADIO`,
   and TX-power updates separately. TX-power's anti-oscillation
   design (§4.1 inner loop) normally keeps it out of this
   trigger, but the detector is the backstop when calibration is
   bad and the dead-band is being chased.
3. **Never exceed the latency cap.** *(GS service, Python.)*
   Predicted-latency check per §4 above. Refuse, don't degrade
   latency.
4. **Safety ceiling enforced locally.** *(Drone applier, C.)*
   The applier independently rejects any command above the
   per-airframe ceiling from the drone's local config file, even
   if the GS signed off on it. Ceilings cover:
   - `(k, n, depth)` for FEC / interleaver.
   - `tx_power_max_dBm` — regulatory / hardware cap on TX power.
     Critical: a mis-calibrated GS asking for 33 dBm on a
     chipset rated for 20 dBm can damage the PA. The applier
     clamps every TX-power decision to the local ceiling.
   - `mcs_index` / `bandwidth` pairs the chipset is validated
     for.

   If the GS is compromised, the drone still flies inside its
   envelope. The interleaver-depth ceiling must also stay ≤
   `MAX_INTERLEAVE_DEPTH` (8, at
   [src/rx.hpp:103](../../src/rx.hpp#L103)) — the compile-time
   RX ring sizing. `wfb_tx_cmd` accepts `depth 1..255` and
   `wfb_tx` only rejects depth conflicts against `n > 32` /
   `fec_timeout > 0`; nothing in the TX rejects depth > 8, so
   the applier is the only line of defense for that bound.

### What a watchdog-triggered fallback looks like

```
safe_defaults = {
    video: (k=8, n=12),   # 50% overhead; matches master.cfg [video] floor
    depth: 1,             # depth 1 = no interleaving, lowest latency
}
```

Chosen so that the drone survives until a human (or the flight stack)
reacts.

---

## 6. Config surface

Two config files — one per component. The GS controller owns the
policy tuning; the drone applier owns the hardware ceiling. Where
they overlap (hard bounds), the drone-side values are authoritative.

### GS side — `[link_adapt]` profile in `master.cfg`

Lives in `master.cfg` in the same style as other wfb-ng profiles.
Consumed by the adaptive-link Twisted service at startup.

**Prerequisite:** set `log_interval = 100` in the `[common]`
section of master.cfg (default is 1000). The controller needs the
10 Hz stats cadence described in §3; wfb-ng-wide metric cadence
is controlled by this single knob.

```
[link_adapt]
adaptive_link = false             # master off-switch; default OFF

# Airframe calibration (used by the latency predictor)
video_framerate = 60              # 60 or 90; drives depth ceilings
per_packet_airtime_us = 80        # platform-measured; used in predictor

# Latency budget (§4.2 of fec-enhancements-v2.md)
max_latency_ms = 50               # hard cap; refuse changes that exceed

# Policy bounds for the trailing (FEC) loop.
# Controller won't emit decisions outside these.
# (Drone applier enforces its own ceiling independently; see §5.)
# Per-k bands live in the radio profile (§6.1 preferred_k);
# these are the absolute floor/ceiling across all bands.
video_n_min     = 4               # k=2 band floor; smallest n we'll use
video_n_max     = 16              # k=8 band step-2 ceiling
video_k_min     = 2               # k=2 band floor (MCS 0-1 rows)
video_k_max     = 8               # k=8 band ceiling (MCS 6-7 rows)
depth_video_max = 3               # at 60 fps; 2 at 90 fps

# Leading loop (RSSI-driven) — see §4.1.
# Two nested controllers: outer MCS selector + inner TX-power
# closed loop. Both driven by smoothed `rssi` from §3.

# Outer loop — MCS / bitrate selector.
# The rssi_mcs_map is built at startup from the selected radio
# profile (see §6.1). Different WiFi chipsets have different
# sensitivity/TX-power numbers, so the map is not defined here.
# Pick a profile shipped under wfb_ng/conf/radios/.
radio_profile         = 'm8812eu2'     # default; BL-M8812EU2, RTL8812EU chipset
radio_profiles_dir    = '/etc/wfb-ng/radios'  # alternate search path for local overrides
bandwidth             = 20             # HT20 (robust) or HT40 (higher throughput)
rssi_margin_db    = 8                  # headroom above vendor sensitivity
rssi_up_guard_db  = 3                  # extra margin to move up a row
rssi_up_hold_ms   = 2000               # smoothed rssi must clear new row for this long
rssi_down_hold_ms = 500                # smoothed rssi must stay below row for this long
mcs_max           = 7                  # hard cap on MCS index; design policy (§4.1)

# Inner loop — TX-power closed loop around rssi_target_dBm.
# Anti-oscillation guards: see §4.1 for rationale of each.
rssi_target_dBm             = -60    # aim observed rssi here
rssi_deadband_db            = 3      # ignore |rssi - target| within this band
tx_power_min_dBm            = 5      # per-airframe lower floor
tx_power_max_dBm            = 23     # regulatory / hardware cap
tx_power_cooldown_ms        = 1000   # at most one step this often
tx_power_freeze_after_mcs_ms= 2000   # hold steady for this long after MCS change
tx_power_step_max_db        = 3      # clamp single-step delta
tx_power_gain_up_db         = 1.0    # multiplier on positive delta
tx_power_gain_down_db       = 1.0    # multiplier on negative delta

# Encoder degradation ladder below the rssi_mcs_map floor.
# Applied left-to-right once MCS is at row floor, TX power is
# saturated at tx_power_max_dBm, and rssi still below the floor's
# rssi_min_dBm.
encoder_degrade_order = ['bitrate_half', 'fps_60', 'fps_30', 'roi', 'resolution']

# Metric smoothing (EWMA time constants; see §3).
# At 10 Hz sampling: alpha = 1 - exp(-tick_ms / tau_ms).
# residual_loss is intentionally *not* smoothed (see §3).
ewma_alpha_rssi  = 0.2            # ~500 ms time constant
ewma_alpha_fec   = 0.2            # ~500 ms for fec_work
ewma_alpha_burst = 0.1            # ~1 s for burst/holdoff/late

# Controller timing (1C refresh semantics; see §4 cooldown rules).
# At 10 Hz sampling, 200 ms = 2 ticks -- commands fire at most every
# other tick per knob. The trailing loop can BYPASS min_change_interval
# when residual_loss > 0 fires an immediate escalation.
min_change_interval_ms_fec = 200      # cooldown on CMD_SET_FEC
min_change_interval_ms_depth = 200    # cooldown on depth
min_change_interval_ms_radio = 500    # cooldown on CMD_SET_RADIO (MCS)
min_change_interval_ms_cross = 50     # between a SET_FEC and SET_DEPTH
# IDR throttle: enforced by the drone applier (see §10 /
# drone config min_idr_interval_ms). The GS emits IDR requests
# freely on every residual_loss_w > 0 window; the applier
# drops duplicates that arrive inside the throttle window.
health_timeout_ms = 10000             # GS-link watchdog (also sent to
                                      # applier in the decision stream
                                      # so drone's watchdog matches)

# Fallback — sent to drone so it stores its copy for watchdog use
safe_defaults = {
    video: (8, 12),
    depth: 1,
    mcs: 1,                       # low-MCS survives most fades
    bitrate_kbps: 2000,
    # short_gi always False (pinned on applier)
}

# Return-link transport
return_link = 'tunnel'                  # stream name in [drone]/[gs] config
```

`adaptive_link = false` is the default; no behavior change for
operators who don't opt in.

### §6.1 Radio card profiles — `wfb_ng/conf/radios/*.yaml`

Different WiFi chipsets have different sensitivities, TX-power
budgets, and supported bandwidth modes. Rather than bake one
chipset's numbers into the design, the GS controller loads a
**radio profile** at startup — one YAML file per card. YAML is
the right fit: pure data, no code execution, hand-editable,
comment-friendly for source attribution.

**Resolution order at startup:**

1. `<radio_profiles_dir>/<radio_profile>.yaml`
2. `wfb_ng/conf/radios/<radio_profile>.yaml` (packaged default)

The local override path (`radio_profiles_dir`) lets operators
ship field-calibrated profiles without editing the wfb-ng
source tree.

**Profile schema (default `m8812eu2.yaml`):**

```yaml
# wfb_ng/conf/radios/m8812eu2.yaml
#
# Source for published values: BL-M8812EU2 datasheet V1.0.1.0
# (2023-11-13), §4 WLAN RF Specification. Chipset: Realtek
# RTL8812EU.
#
# The datasheet publishes sensitivity at MCS 0 and MCS 7 only.
# MCS 1-6 values in this file are linear-in-dBm interpolation
# between those endpoints (2.71 dB per step, rounded to int).
# Field-validate every row per airframe before operational use
# — antenna gains, front-end losses, and operator country of
# operation all shift the numbers from the chip-level sheet.
#
# Calibrated TX power from datasheet: HT20 MCS7 = 23 dBm;
# HT40 MCS7 = 22.5 dBm. Going above the calibrated TX power
# voids EVM specs.

name: BL-M8812EU2
chipset: RTL8812EU

# MCS range. Hard cap 7 per §4.1 design policy (1T1R SISO).
# The chipset supports MCS 8-15 (2T2R MIMO) but we don't drive
# those.
mcs_min: 0
mcs_max: 7

# Supported bandwidth modes (wfb-ng uses 802.11n HT only).
bandwidth_supported: [20, 40]
bandwidth_default:   20       # HT20 — robust, longer range

# TX power bounds (dBm).
tx_power_min_dBm: 0
tx_power_max_dBm: 23          # HT20 calibrated ceiling

# Receiver sensitivity @ PER < 10%, in dBm.
# Outer key is bandwidth (MHz), inner key is MCS index.
sensitivity_dBm:
  20:       # HT20
    0: -96
    1: -93
    2: -91
    3: -88
    4: -85
    5: -83
    6: -80
    7: -77
  40:       # HT40
    0: -93
    1: -90
    2: -88
    3: -85
    4: -82
    5: -80
    6: -77
    7: -74

# Nominal data rate @ long guard interval, 1T1R SISO (Mbps).
# Defined by the 802.11n standard (not per-chip), so these
# values are reported verbatim in every profile.
data_rate_Mbps_LGI:
  20:
    0:   6.5
    1:  13.0
    2:  19.5
    3:  26.0
    4:  39.0
    5:  52.0
    6:  58.5
    7:  65.0
  40:
    0:  13.5
    1:  27.0
    2:  40.5
    3:  54.0
    4:  81.0
    5: 108.0
    6: 121.5
    7: 135.0

# Preferred FEC k per MCS row (§4.2). Tuned for the 60 fps
# latency cap (50 ms) at depth 1-2. At 90 fps the
# latency-budget predictor (§4) may auto-drop k one band.
# Bandwidth-agnostic — same table for HT20 and HT40 because
# block-fill time is k * MTU / bitrate and bitrate already
# scales with bandwidth at the same MCS row.
preferred_k:
  7: 8     # MCS7 cruise; k=8 matches master.cfg [video] floor
  6: 8
  5: 6
  4: 6
  3: 4
  2: 4
  1: 2
  0: 2     # MCS0 survival; smallest k keeps block-fill bounded

# Conservative encoder-bitrate fraction of nominal (0..1).
# Controller emits bitrate = data_rate * encoder_bitrate_frac,
# leaving headroom for FEC parity + re-tx + telemetry.
encoder_bitrate_frac: 0.40
```

**Startup validation.** The GS service, on load:

- Parses the YAML with a safe loader (no Python-tag support).
- Confirms `mcs_max <= 7` (design policy).
- Confirms every `(bandwidth, mcs)` pair in the row range has
  both a `sensitivity_dBm` entry and a `data_rate_Mbps_LGI`
  entry.
- Confirms every MCS in `preferred_k` is in the `{2, 4, 6, 8}`
  set (the bands §4.2 defines) and that `preferred_k` values
  decrease monotonically from MCS 7 to MCS 0.
- Builds the runtime `rssi_mcs_map` from `sensitivity_dBm` +
  `rssi_margin_db` + `data_rate_Mbps_LGI * encoder_bitrate_frac`
  + `preferred_k`. The row table shown in §4.1 is the output of
  this build for the `m8812eu2` HT20 default.
- Runs the latency-budget predictor at the chosen `video_fps`
  against each row's preferred `k` at depth 1 and depth 2. If
  any row would exceed `max_latency_ms`, the service logs a
  warning and notes the auto-drop-k rows for runtime.

**Adding a new card.** Drop a new file under
`wfb_ng/conf/radios/<name>.yaml`, fill in the schema above,
set `radio_profile = '<name>'` in `master.cfg`. No code
changes. Source attribution in the file header is required
(the loader doesn't enforce it but code review should).

### Drone side — `/etc/wfb-link-adapt.conf`

Read by the `wfb-la-applier` C binary at startup. Syntax is a
minimal `key = value` format (no sections; keep the parser in the
applier tiny). Hardware ceilings and applier behaviour only;
policy values live on the GS.

```
# Listen endpoint for decision packets (local end of the tunnel).
listen_addr = 127.0.0.1
listen_port = 5800

# wfb_tx control socket (where CMD_SET_FEC etc. are sent).
wfb_tx_ctrl_addr = 127.0.0.1
wfb_tx_ctrl_port = 8000

# Per-airframe hardware ceiling. Applier rejects any decision
# above any of these values regardless of what the GS says.
#
# depth_max must stay <= MAX_INTERLEAVE_DEPTH (8) at
# src/rx.hpp:103 -- the compile-time RX ring sizing.
# n_max must stay <= 32 when depth_max > 1 (src/tx.cpp:1183).
# k_min default of 2 matches the GS-side per-MCS-row bands
# (§4.2); raise it if your airframe should never drop into
# a low-k / low-bitrate survival mode.
video_k_min = 2
video_k_max = 8
video_n_max = 16
depth_max = 3

# TX power hardware / regulatory ceiling. The GS's inner loop may
# ask for anything in [tx_power_min_dBm, tx_power_max_dBm]; the
# applier clamps to this local pair. Set to the lower of:
# (a) chipset's safe operating power, (b) regulatory limit for
# this airframe's country of operation.
tx_power_min_dBm = 0
tx_power_max_dBm = 20

# IDR throttle — authoritative cap on encoder IDR-request rate.
# GS emits IDR requests on every residual_loss_w > 0 window
# (§4.2); the applier drops any IDR that arrives within
# min_idr_interval_ms of the last one it forwarded. Lower
# bound: ~1 frame period (16.7 ms @ 60 fps, 11.1 ms @ 90 fps).
# Higher values trade fewer keyframes for a longer corruption
# window after a missed IDR.
min_idr_interval_ms = 500

# OSD sink — msposd custom-message file drop (§4B).
# Set osd_enable = 0 to skip the write entirely.
osd_enable              = 1
osd_msg_path            = /tmp/MSPOSD.msg
osd_update_interval_ms  = 1000    # periodic status line
osd_event_color         = red     # for protective escalations
osd_normal_color        = white   # for steady-state line

# GS-link watchdog. Must be >= the GS's
# min_change_interval_ms_fec (no decisions for this long -> GS
# considered down). Drone falls back to safe_defaults and stops
# reapplying until decisions resume.
health_timeout_ms = 10000
safe_k = 8
safe_n = 12
safe_depth = 1
safe_mcs = 1
safe_tx_power_dBm = 20            # survival: hit max legal power
safe_bitrate_kbps = 2000
# short_gi is always False — applier pins it regardless of GS input.

# Backends — active from Phase 1 (drone-only) onward.
# Uncomment and set to match the airframe. The radio_backend
# default is 'iw' (shelled out); encoder_backend_sock points
# at the per-encoder helper's local Unix socket.
radio_backend         = iw
encoder_backend_sock  = /var/run/wfb-enc.sock
# encoder_kind — one of: waybeam_venc | majestic | none
# (informs the applier which helper protocol dialect to speak).
encoder_kind          = majestic
```

---

## 7. Phased plan

Each phase independently shippable, behind the master off-switch.

### Phase 0 — Observer mode (GS Python only, log-only)

Goal: validate the controller's decisions against a pilot's
subjective link-quality judgement before any command is applied.

- **GS side (Python).** New Twisted service inside wfb-ng,
  subscribing to `ant_stat_cb.update_rx_stats` at
  [wfb_ng/protocols.py:438](../../wfb_ng/protocols.py#L438) — no
  new `wfb_rx` spawn, no stdout parser needed.
- Computes the §3 signal set — `rssi` (smoothed), `residual_loss`
  (raw per window), `fec_work`, `burst_rate`, `holdoff_rate`,
  `late_rate` — and runs both control loops (§4.1 leading,
  §4.2 trailing).
- **Emits no commands.** Prints decisions to stdout / file (and
  optionally to the GS OSD, read-only) so operators can validate
  them.
- **Drone side: no change.** The C applier is not shipped yet.
- **Files added (net-new), GS side only:**
  - Under `wfb_ng/link_adapt/`:
    - `service.py` — Twisted service entry point; binds to
      `ant_stat_cb`, drives the policy tick, emits decisions to
      a log/stdout sink (return-link transport wired in Phase 2).
    - `policy.py` — leading + trailing loops, knob selector.
    - `predictor.py` — latency predictor mirroring
      fec-enhancements-v2.md §4.2.
    - `profile.py` — radio-profile loader (§6.1); builds the
      runtime `rssi_mcs_map` from the selected profile.
  - Under `wfb_ng/conf/radios/`:
    - `m8812eu2.yaml` — default radio profile (§6.1), populated
      from the BL-M8812EU2 datasheet with linearly-interpolated
      MCS 1–6 sensitivities. File header comment records the
      source and the field-validation requirement.
  - `wfb_ng/conf/master.cfg` — new `[link_adapt]` profile with
    `adaptive_link = false`, `radio_profile = 'm8812eu2'`.
- **Risk:** zero to the live link.
- **Verification:** run during a real flight; log output matches
  pilot's subjective "link quality" judgement.

### Phase 1 — Drone applier with all backends (drone-only)

Goal: ship a complete drone-side applier — all three backends,
both drone-side failsafes, OSD wiring — and verify it end-to-end
on the drone *without* any GS-side decision emission. Operators
drive the applier by hand from a local UDP tool so each backend
can be validated in isolation before the GS takes over.

No GS changes in this phase. Phase 0's GS observer keeps running
in log-only mode; wiring the observer's output to the return
link is deferred to Phase 2.

- **Drone side (C), net-new:**
  - `src/wfb_la_applier.c` — single-file applier binary. Links
    against libc and (optionally) libnl for the radio backend.
    Reuses `src/tx_cmd.h` directly for the wire format to
    `wfb_tx`. No Python, no Twisted.
  - `src/wfb_la_applier.h` — internal helpers + decision-packet
    struct definition.
  - `src/wfb_la_inject.c` — companion CLI that crafts a single
    decision packet and sends it to the applier's UDP listen
    port. Modelled on `wfb_tx_cmd`. Used for operator bringup
    and CI; **this is the decision source in Phase 1**, because
    the GS isn't sending anything yet.
  - `Makefile` targets `wfb-la-applier` and `wfb-la-inject`
    added alongside the existing `wfb_tx` / `wfb_rx` /
    `wfb_tx_cmd`.
  - `/etc/wfb-link-adapt.conf` sample shipped under
    `wfb_ng/conf/wfb-link-adapt.conf.sample` (drone-side
    config; see §6).
- **Backends active in Phase 1 (all three):**
  - **FEC/depth** via `src/tx_cmd.h` UDP to local `wfb_tx` —
    `CMD_SET_FEC`, `CMD_SET_INTERLEAVE_DEPTH`.
  - **Radio** via `iw` helper (shelled out via `posix_spawn`)
    or libnl directly: TX power (critical for the §4.1 inner
    loop), MCS, bandwidth via `CMD_SET_RADIO`. `short_gi`
    pinned to `false` (§1).
  - **Encoder** via local Unix socket
    (`/var/run/wfb-enc.sock` by convention) to a per-encoder
    helper: bitrate, fps, GOP, IDR-request, ROI. Target
    encoders: **waybeam_venc** and **majestic** on OpenIPC —
    one helper binary per encoder, shared control API shape
    (§7 Phase 3 → now collapsed into Phase 1).
- **Failsafes 1 and 4 (drone-side) live.** Watchdog on the GS
  link (fires `safe_defaults` after `health_timeout_ms`) and
  per-airframe safety ceiling (rejects anything over the
  configured bounds — FEC, depth, MCS, TX power, bandwidth).
- **OSD status line** written to `/tmp/MSPOSD.msg` on every
  applied decision and every tick (§4B); msposd picks it up if
  installed.
- **IDR-request throttle** enforced (`min_idr_interval_ms`,
  §10); injections exceeding the cap are dropped.
- **Init-system integration.** A single `systemd` unit (or
  OpenRC, where used) spawns the applier alongside the
  existing `wfb_tx` service on the drone.
- **Verification in Phase 1:**
  - Use `wfb-la-inject` to drive each backend manually through
    its operating range; confirm the applier applies, the
    ceiling rejects appropriately, the watchdog fires after a
    10 s silence, and msposd shows the correct profile line.
  - Run the OpenIPC encoder helpers against a real camera and
    confirm `set_bitrate` / `set_fps` / `set_roi` /
    `request_idr` take effect on the video stream.
  - No flight; bench test covers everything because nothing
    on the GS sends commands yet.
- **Rollback:** stop `wfb-la-applier`. With no process running,
  the drone reverts to wfb-ng's static master.cfg defaults.

### Phase 2 — GS decision emission end-to-end

Goal: wire the Phase 0 GS controller up to the Phase 1 drone
applier. This is the "adaptive-link turns on" phase.

- **GS side (Python), net-new:**
  - Decision-packet serialiser (matching `src/wfb_la_applier.h`
    struct — single source of truth for wire format).
  - Return-link writer: raw UDP into the local `tunnel` stream
    endpoint that wfb-ng already binds.
  - GS-side failsafes 2 (oscillation detector) and 3
    (latency-cap predictor refusal) gate outgoing decisions.
  - MAVLink status-channel reader: parse
    `STATUSTEXT` / custom rejection messages from the drone
    applier on the upstream `mavlink` stream (§10).
  - `adaptive_link = true` in master.cfg takes effect for real.
- **Drone side (C):** no net-new code. The Phase 1 applier is
  already the receiver.
- **Rollback:** on the GS, `adaptive_link = false` in
  master.cfg — the GS reverts to Phase 0 log-only behaviour
  and the drone applier sees silence, triggers the watchdog,
  and lands on `safe_defaults`.
- **Verification:** controlled-degradation bench test first
  (attenuator on GS → drone path), then flight validation.

### Phase 3 — Airframe tuning and flight validation

- Per-airframe calibration of the GS `[link_adapt]` profile and
  the drone `wfb-link-adapt.conf` ceiling.
- Controlled-degradation flight test (attenuator sweep, distance
  sweep, urban interference).
- Oscillation detector tuning (GS-side parameter).
- Sign-off on safe_defaults per airframe (both sides: GS
  `safe_defaults`, drone `safe_k` / `safe_n` / `safe_depth`).

---

## 8. Example timeline — range fade and recovery

60 fps, `max_latency_ms = 50`, default M8812EU2 HT20 profile,
`rssi_target = -60 dBm`, `tx_power_max = 23 dBm`. Drone flies
out to range over ~30 s, path loss rises from 68 dB cruise to
96 dB at the edge, then returns. The leading loop (RSSI-driven)
runs continuously; the trailing loop (loss-driven) stays quiet
because the leading loop keeps loss at zero. The controller
samples at 10 Hz internally; only the ticks where a knob
actually changes are shown.

`rssi ≈ tx_power − path_loss` below (antenna-gain constants
absorbed into `path_loss`). MCS rows per the default
`rssi_mcs_map` in §4.1.

```
t       path_loss  tx_pwr  rssi   residual   MCS knobs          FEC knobs    notes
t=0s    68 dB       8 dBm  -60    0          MCS7 26Mbps        (8,12) d=1   cruise; at rssi_target
t=15s   78 dB      18 dBm  -60    0          MCS7 26Mbps        (8,12) d=1   inner loop raising power to track
t=22s   85 dB      23 dBm  -62    0          MCS7 26Mbps        (8,12) d=1   SATURATED; rssi starting to drop
                                                                              but still in deadband of target
t=28s   91 dB      23 dBm  -68    0          MCS7 26Mbps        (8,12) d=1   rssi still above -69 MCS7 floor
t=30s   92 dB      23 dBm  -69    0          MCS7 26Mbps        (8,12) d=1   at the boundary
t=31s   93 dB      23 dBm  -70    0          MCS6 23Mbps        (8,12) d=1   crossed -69; drop one row. k stays
                                                                              at 8 (MCS6 is still k=8 band).
                                                                              tx_power freeze 2s.
t=33s   94 dB      23 dBm  -71    0          MCS6 23Mbps        (8,12) d=1   freeze over; power already at max
t=35s   95 dB      23 dBm  -72    0          MCS5 21Mbps        (6,10) d=1   crossed -72 down; MCS5. k BAND
                                                                              CHANGE: k=8 → k=6. Trailing loop
                                                                              issues CMD_SET_FEC to rebase at
                                                                              (6,10) floor. ~12ms stall.
t=38s   96 dB      23 dBm  -73    0          MCS5 21Mbps        (6,10) d=1   holding at edge of range
...
t=50s   95 dB      23 dBm  -72    0          MCS5 21Mbps        (6,10) d=1   recovery starts
t=52s   92 dB      23 dBm  -69    0          MCS5 21Mbps        (6,10) d=1   rssi back above -72 (MCS5 floor),
                                                                              but up-hold 2s required
t=54s   90 dB      23 dBm  -67    0          MCS6 23Mbps        (8,12) d=1   rssi > (-72 + 3) up-guard for 2s;
                                                                              step up to MCS6. k BAND CHANGE:
                                                                              k=6 → k=8. Rebase at (8,12).
t=57s   87 dB      23 dBm  -64    0          MCS7 26Mbps        (8,12) d=1   rssi > -69 + 3 for 2s; MCS7 row.
                                                                              Same k=8 band — no FEC rebase.
                                                                              tx_power freeze 2s.
t=60s   80 dB      23 dBm  -57    0          MCS7 26Mbps        (8,12) d=1   freeze over; inner loop: rssi
                                                                              3dB above target, drop power.
t=61s   80 dB      20 dBm  -60    0          MCS7 26Mbps        (8,12) d=1   back at target
t=63s   75 dB      15 dBm  -60    0          MCS7 26Mbps        (8,12) d=1   inner loop still tracking; path
                                                                              loss keeps dropping with range
t=65s   68 dB       8 dBm  -60    0          MCS7 26Mbps        (8,12) d=1   cruise; battery saved.
```

(Guard interval is long throughout — `short_gi` is pinned to
`false` per §1; not shown in the table.)

What this illustrates:

- **0–22 s**: inner loop absorbs rising path loss by raising TX
  power 3 dB at a time; observed `rssi` stays near `-60 dBm`
  target. MCS row never changes. This is the design path —
  outer loop never touches MCS when the inner loop has margin.
- **t=22 s**: `tx_power` saturates at 23 dBm. Any further path
  loss shows up as real RSSI drop.
- **t=31 s**: observed RSSI crosses the MCS 7 row boundary
  (-69). Outer loop drops to MCS 6; `k` stays at 8 because MCS 6
  is in the same `k`-band.
- **t=35 s**: RSSI crosses the MCS 5 boundary (-72). Outer loop
  drops to MCS 5 **and** the trailing loop crosses a `k`-band
  (8 → 6). One `CMD_SET_FEC` rebases to `(6, 10)`; ~12 ms stall.
- **t=54 s**: recovery crosses the same `k`-band boundary in
  reverse (k=6 → k=8), another `CMD_SET_FEC` rebase.
- **t=57–65 s**: inner loop drops TX power in 3 dB steps down to
  a low cruise level. Dead-band + 1 s cooldown keeps it from
  oscillating around the target.
- **No IDR was fired** at any point — the trailing loop stayed
  quiet because the leading loop kept `residual_loss` at zero.
  The two `k`-band rebases happened during no-loss windows, so
  no IDR request accompanied them (band crossings on the leading
  loop's step-down path do not corrupt the GOP — they're
  coordinated rate drops).

### Contrast: unexpected multipath at a tree line (trailing loop fires)

Same flight, but at t=19s the drone dips behind a line of trees
and the leading loop hasn't yet dropped to MCS4 — residual_loss
fires because the fade was faster than RSSI told us:

```
t        rssi   residual_loss_w   leading knobs        trailing knobs   notes
t=19.0s  -67    0                  MCS7 26Mbps          (8,12) d=1       cruise with margin
t=19.1s  -69    0.014              MCS7 26Mbps          (8,14) d=1 IDR   TRAILING fires: 1 window with loss
                                                                         → raise n immediately + IDR.
                                                                         Pilot saw a blocky patch, not a
                                                                         glitch — n=14 absorbed it on the
                                                                         next block.
t=19.2s  -72    0.021              MCS6 23Mbps          (8,16) d=2       still lossy: leading loop forced
                                                                         down one MCS row; trailing
                                                                         raises n + depth.
t=19.3s  -72    0                  MCS6 23Mbps          (8,16) d=2       recovered.
t=20.5s  -71    0 (1s)              MCS6 23Mbps          (8,16) d=1       step-down: depth first
t=22.0s  -70    0 (2s)              MCS6 23Mbps          (8,14) d=1       then n
t=23.0s  -68    0 (3s)              MCS6 23Mbps          (8,12) d=1       floor; rssi still waiting 2s at
                                                                         >-66 before MCS7 up-step
```

Two things to notice:

1. The trailing loop's reaction at t=19.1s is **single-window**,
   not hysteresis-delayed. One 100 ms window with loss → raise
   `n` + IDR immediately. That's the FPV doctrine: a glitch is
   a glitch, don't wait to confirm a second one.
2. The step-down in the trailing loop takes multiple seconds
   even though `residual_loss` cleared at t=19.3s. This is
   asymmetric on purpose — we bought the protection cheaply, we
   pay it back slowly to avoid oscillation.

### `budget_exhausted`

If the leading loop hits MCS 0 with `rssi` still below the floor
(~-80 dBm), it raises `budget_exhausted` instead of dropping
further. The GS emits the signal to the flight controller (e.g.
MAVLink STATUSTEXT) and lets the flight stack decide (RTH /
hold altitude / pilot takes manual action). Under the FPV
doctrine, flying at MCS 0 with loss is not an option — blocky
video at MCS 1 is the floor for "still flyable."

---

## 9. Risks

1. **Oscillation** *(GS)*. Asymmetric hysteresis + cooldown +
   detector are the three-layer defense for the trailing loop
   and the outer MCS selector. Still requires tuning per
   airframe.
1a. **Band-boundary flapping** *(GS, coupled loops)*. A borderline
   RSSI right at a `k`-band boundary (e.g. between MCS 5 and MCS 6
   in the default profile) can cause repeated `k` rebases as the
   leading loop flips rows. Defence: the leading loop's existing
   row hysteresis (3 dB / 2 s up, 500 ms down) applies; the
   oscillation detector (failsafe §5 #2) will lock the row if
   it does thrash. Worth calibrating
   `rssi_mcs_map` row boundaries so they don't sit exactly at a
   `k`-band transition for the expected operating points.
1b. **TX-power oscillation** *(GS, inner loop)*. The naive
   "rssi low → raise power → rssi high → drop power → rssi low
   …" loop oscillates forever. Defence stack in §4.1: dead-band
   (3 dB), cooldown (1 s), MCS-change freeze (2 s), bounded
   single-step correction (3 dB). If the `rssi_deadband_db` is
   set below the observed RSSI measurement noise, the loop will
   ring — calibrate dead-band > measurement noise for the target
   chipset.
2. **Rekey storm** *(GS → drone)*. A sick stream at the cooldown
   edge could emit a command every 200 ms indefinitely.
   GS-side oscillation detector catches before the drone applier
   does.
3. **Stale decision telemetry** *(return link)*. Decision packets
   travel over the `tunnel` stream, which may itself be failing.
   Budget one-way decision-packet age at ≤ 2 s normally; >
   `health_timeout_ms` (10 s) → the drone applier falls back to
   safe_defaults (failsafe 1).
4. **Misclassification of burstiness** *(GS)*.
   `count_bursts_recovered` is a proxy: RX's count of blocks where
   FEC recovered ≥ ⌈(n-k)/2⌉ primaries. It tags a clumped-loss
   event but cannot distinguish "one bursty instant inside an
   otherwise calm window" from "sustained bursty channel." Reject
   windows with < 100 packets; consider a secondary EWMA over
   several windows before escalating depth.
5. **Backend failure modes** *(drone applier)*. Each backend
   (radio, encoder) can fail independently. The applier must
   tolerate "backend reports error" without crashing; it degrades
   to `wfb_tx`-only control and reports the degradation to the
   GS via MAVLink (§10 status channel).
6. **Drone applier / GS controller disagreement** *(both)*. The
   applier rejects commands outside its local ceiling. The GS
   controller sees the reject via MAVLink and must not re-issue
   immediately — rate-limit retries.
7. **GS starvation** *(GS)*. If the Python service gets starved
   (CPU overload, disk I/O on stdout parse), decisions lag. Run
   with soft real-time priority; avoid disk I/O on the hot path;
   keep log writes off the decision thread.
8. **Drone applier starvation** *(drone)*. Unlikely given the
   applier's small footprint, but worth noting: the applier is
   the only line of defence between the GS and the `wfb_tx`
   control socket. Run it at a priority at least matching
   `wfb_tx`.

---

## 10. Settled decisions

Design choices made after review; captured here so the rationale
for each stays with the doc.

- **Code location.**
  - GS Python service: `wfb_ng.link_adapt` sub-package (reuses
    Twisted service model; avoids a second `wfb_rx` spawn).
  - Drone C applier: `src/wfb_la_applier.c` alongside the
    existing `wfb_tx` / `wfb_rx` / `wfb_tx_cmd` sources; ships
    as a separate binary `wfb-la-applier`.

- **Return-link (GS → drone) protocol: raw UDP over `tunnel`.**
  Fixed-size decision-packet struct with explicit endianness.
  Rationale: keeps the drone-side C parser trivially small
  (single `struct`, `ntohl`/`ntohs`, no library dependency).
  Using MAVLink here would drag a MAVLink parser into the drone
  image for no win — decision packets don't need to coexist
  with flight-controller telemetry in the same parser.

- **Status channel (drone → GS): MAVLink.** The drone applier
  reports rejections (ceiling hits), watchdog fallbacks, and
  backend failures (risks §9 #5, #6) as MAVLink messages on the
  existing `mavlink` stream (`[drone]`/`[gs]` config at
  [wfb_ng/conf/master.cfg:132-154](../../wfb_ng/conf/master.cfg#L132-L154)).
  `STATUSTEXT` for human-readable events; a lightweight custom
  message type for structured rejections. The asymmetry (raw
  UDP down, MAVLink up) is deliberate: decisions need a tiny
  parser on a resource-tight drone; status upstream naturally
  co-locates with the flight-controller telemetry the GS
  operator already reads.

- **ROI encoding support.** Supported. The OpenIPC drone
  ecosystem has two video encoders in common use —
  **waybeam_venc** and **majestic** — and both expose roughly
  the same API shape (a JSON/ctl socket for bitrate / GOP / IDR
  and a ROI rectangle + QP-delta endpoint). The Phase 1 encoder
  backend (§7) targets this shared surface with a single helper
  per encoder; ROI is wired from day one rather than gated on
  a survey.

- **IDR-on-command throttle.** Minimum interval default **500 ms**,
  enforced by the drone applier (authoritative cap). The GS
  emits IDR requests freely whenever the trailing loop fires
  (§4.2); the applier drops any request that arrives within
  `min_idr_interval_ms` of the last one it forwarded to the
  encoder. Configurable per-airframe via
  `/etc/wfb-link-adapt.conf` — see §6 drone config. Rationale:
  the applier is the right enforcement point because it's the
  last stage before the encoder helper and it's the layer
  that's independent of GS correctness.

- **Drone-local OSD: msposd custom-message file drop.** The
  applier writes the current profile state to
  `/tmp/MSPOSD.msg` at 1 Hz;
  [OpenIPC/msposd](https://github.com/OpenIPC/msposd) reads
  the file and overlays the text on the video before encoding.
  See §4B for the line format. Chosen over a MAVLink-based
  OSD integration because msposd's file interface needs no
  protocol parser on either side and co-exists cleanly with
  the MAVLink upstream status channel — the two paths don't
  share machinery and can't interfere with each other.

---

## 11. Dependencies

All pre-reqs for Phase 0 (GS observer), Phase 1 (drone applier)
and Phase 2 (GS decision emission) ship on branch
`feat/interleaving_uep`.

- **Fec-enhancements Phase 1** (interleaver + `CMD_SET_INTERLEAVE_DEPTH`
  + 1C refresh semantics + 14-field `PKT` + 6-field `SESSION`).
  **Status: shipped.** Commits `e71b317` through `d08a94e` on
  `feat/interleaving_uep`. Enables depth as a runtime knob, tight
  rekey cooldowns (§4), and the counter-derived metrics (§3).
- **Stable `IPC_MSG` contract.** **Status: shipped** as part of
  Phase 1 Step A (plan §2.1 `WFB_IPC_CONTRACT_VERSION = 2`).
  **Gap:** the stability commitment lives at the plan-doc level
  only; no code test pins the field order. A contract test
  (e.g. `tests/ipc_contract_test.py`) that freezes the 14-field
  PKT / 6-field SESSION layouts would be a cheap follow-up and
  protect the GS controller from a future silent reorder in
  `wfb_rx`.

All dependencies needed for Phase 0 (GS observer), Phase 1
(drone applier) and Phase 2 (GS decision emission) are in
place today.
