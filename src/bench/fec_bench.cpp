// fec_bench -- standalone FEC benchmark harness.
//
// Phase 0 of doc/design/fec-enhancements-v2.md. Links against the same
// libzfex object (src/zfex.o) that wfb_tx / wfb_rx use -- no fork of
// the FEC code. Simulates a lossy channel, feeds encoded fragments
// through a channel model, runs fec_decode_simd on the survivors,
// measures recovery rate + CPU cost. CSV out.
//
// This PR (Step B): channel models, CSV emit, --selftest, --single
// mode. --sweep lands in Step C.
//
// Notes for reviewers who are not fluent in C -- places to look hard:
//
//   (1) Alignment. fec_encode_simd / fec_decode_simd require every
//       buffer to start at a ZFEX_SIMD_ALIGNMENT boundary. We allocate
//       via posix_memalign (same idiom as src/fec_test.cpp:25). A
//       plain `new uint8_t[N]` would SIGBUS on strict-alignment ARM.
//
//   (2) Pointer-array order. fec_encode_simd takes inpkts[0..k) =
//       primaries in fragment-index order, and fecs[0..n-k) = parity
//       buffers. fec_decode_simd takes inpkts[0..k) = any k surviving
//       fragments, with index[i] recording the *original fragment
//       number* of inpkts[i]. A primary that survived must live at
//       slot index[i]=i; a parity that substitutes for a missing
//       primary lives at some slot with index[i] >= k. Outpkts lists
//       the buffers to reconstruct missing primaries into.
//
//   (3) Ownership. All buffers are owned by this main() stack frame
//       and live across the entire config. We allocate once per
//       config, free at end. No async handoff across a thread or a
//       socket, so no lifetime puzzles.
//
//   (4) Timing. clock_gettime(CLOCK_MONOTONIC) -- same clock as
//       src/wifibroadcast.cpp:50-64. Called immediately before and
//       after each fec_*_simd call; no other code sits in between.

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <random>
#include <string>
#include <vector>

extern "C" {
#include "zfex.h"
}

#include "bench/channel_model.hpp"
#include "bench/interleaver.hpp"
#include "../interleaver.hpp"  // Phase 1 Step E: production at src/interleaver.hpp (../ disambiguates from src/bench/interleaver.hpp)

namespace {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

uint64_t now_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return uint64_t(ts.tv_sec) * 1000000000ull + uint64_t(ts.tv_nsec);
}

// Splitmix64 -- used to derive per-(config, rng-slot) child seeds
// deterministically from the user-supplied master seed. One function,
// no hidden state.
uint64_t splitmix64(uint64_t x) {
    x += 0x9E3779B97F4A7C15ull;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
    return x ^ (x >> 31);
}

// Deterministic fill: byte j of fragment i of block b = low byte of
// (b * 1315423911 + i * 2654435761 + j). Cheap, non-constant, and a
// single-byte corruption stands out at decode-verify time.
uint8_t expected_byte(uint64_t block_idx, unsigned frag_idx, size_t j) {
    const uint64_t v =
        block_idx * 1315423911ull + uint64_t(frag_idx) * 2654435761ull + uint64_t(j);
    return uint8_t(v & 0xff);
}

void fill_primary(uint8_t* buf, size_t block_size, uint64_t block_idx, unsigned frag_idx) {
    for (size_t j = 0; j < block_size; ++j) {
        buf[j] = expected_byte(block_idx, frag_idx, j);
    }
}

void* xaligned_alloc(size_t alignment, size_t size) {
    void* p = nullptr;
    const int rc = posix_memalign(&p, alignment, size);
    if (rc != 0) {
        std::fprintf(stderr, "posix_memalign(%zu, %zu) failed: %d\n", alignment, size, rc);
        std::exit(1);
    }
    return p;
}

uint64_t percentile_ns(std::vector<uint64_t>& samples, double q) {
    // Destructive: partial-sorts in place. Caller has no further use.
    if (samples.empty()) return 0;
    size_t idx = size_t(q * (samples.size() - 1));
    if (idx >= samples.size()) idx = samples.size() - 1;
    std::nth_element(samples.begin(), samples.begin() + idx, samples.end());
    return samples[idx];
}

double mean_ns(const std::vector<uint64_t>& samples) {
    if (samples.empty()) return 0.0;
    long double acc = 0.0;
    for (uint64_t v : samples) acc += static_cast<long double>(v);
    return double(acc / samples.size());
}

// ---------------------------------------------------------------------------
// Config + result structs
// ---------------------------------------------------------------------------

enum class Model { Uniform, GE, Periodic };

const char* model_name(Model m) {
    switch (m) {
        case Model::Uniform:  return "uniform";
        case Model::GE:       return "ge";
        case Model::Periodic: return "periodic";
    }
    return "?";
}

struct Config {
    Model model;
    // Model-dependent parameters. param1/param2 are also what we emit
    // in the CSV row so the summary script can key on them generically.
    double param1 = 0.0; // uniform: loss p; ge: burst_mean; periodic: period
    double param2 = 0.0; // ge: gap_mean; periodic: burst_len
    unsigned k = 8;
    unsigned n = 12;
    unsigned depth = 1; // block interleaver depth. 1 = no interleaving.
    size_t block_size = 1466; // MAX_FEC_PAYLOAD-ish per plan §4.2
    uint64_t blocks = 10000;
    uint64_t seed = 0xC0FFEEull;

    // Wire-timing assumptions used to compute the CSV `latency_ms`
    // column. Defaults are the plan §4.2 reference operating point:
    // 8812au, MCS7 40 MHz HT, ~8 Mb/s H.264. Override via
    // --ipi-ms / --airtime-us / --slack-ms for other operating
    // points. The harness itself does not *measure* latency --
    // these values parametrize a theoretical model derived from
    // §4.2's formula.
    double ipi_ms = 1.4;       // inter-packet interval
    double airtime_us = 80.0;  // per-packet wire airtime
    double slack_ms = 5.0;     // plan §4.7 RX deadline slack

    // Phase 1 Step E: when true and depth > 1, fragments go through
    // the production src/interleaver.cpp (wfb::BlockInterleaver)
    // instead of the reference's pure-math emit_slot(). Measures the
    // real push+drain memcpy cost. Recovery rates are unchanged --
    // the schedule test pins bit-identical emission order.
    bool use_prod_interleaver = false;
};

struct Result {
    // Recovery counters
    uint64_t blocks_recovered = 0;   // >= k fragments survived
    uint64_t blocks_lost = 0;        // < k fragments survived
    uint64_t primary_packets_total = 0;  // always blocks * k
    uint64_t primary_packets_lost = 0;   // those we could not reconstruct

    // Per-block CPU samples (nanoseconds). encode has `blocks` samples.
    // decode has one sample per block where we actually invoked
    // fec_decode_simd (>=1 loss AND at least k survived).
    std::vector<uint64_t> encode_ns;
    std::vector<uint64_t> decode_ns;
    // Phase 1 Step E: production interleaver push+drain time, per
    // block (one sample per block). Empty when use_prod_interleaver
    // is false or depth == 1.
    std::vector<uint64_t> interleaver_ns;

    // Peak heap bytes we explicitly allocated in this config. Includes:
    //   - n fragment buffers (aligned-up to SIMD)
    //   - encode_ns + decode_ns vector capacities
    // Excludes small bookkeeping (fec_t, survivor lists).
    uint64_t peak_mem_bytes = 0;
};

// ---------------------------------------------------------------------------
// run_config -- the heart of the harness
//
// Iterates D-frames. Within each D-frame:
//   (1) encode all D blocks
//   (2) walk the D*n emit slots in block-interleaver order, call
//       channel.drop() at each (GE state sees emit-order events)
//   (3) run per-block recovery + verification
//
// D = 1 is a pure degenerate of this loop: num_frames = num_blocks,
// each frame has exactly one block, slot order is (b*n, b*n+1, ...,
// b*n+n-1) -- identical to the old per-block loop. The D = 1 code
// path is therefore bit-identical to the pre-interleaver harness.
//
// Memory ownership: every `frag[d][i]` buffer is posix_memalign'd to
// ZFEX_SIMD_ALIGNMENT, owned by this function, freed at the bottom.
// No pointers cross the function boundary. ASan under `--selftest`
// must exit clean.
// ---------------------------------------------------------------------------
template <typename ChannelT>
Result run_config(const Config& cfg, ChannelT& channel) {
    // zfex requires all encode/decode buffers to be aligned; we
    // allocate the aligned-up-to-SIMD size so the SIMD kernel can
    // over-read the tail without going out of bounds.
    const size_t buf_size = ZFEX_ROUND_UP_SIMD(cfg.block_size);
    const unsigned D = cfg.depth;
    assert(D >= 1);

    // Round the requested block count up to a multiple of D so every
    // D-frame is complete. Callers that care about the exact value
    // should read the `blocks` field of the Result back. The sweep
    // driver always uses 10000 and 10000 is divisible by 1/2/4/8/16.
    const uint64_t requested_blocks = cfg.blocks;
    const uint64_t num_frames  = (requested_blocks + D - 1) / D;
    const uint64_t total_blocks = num_frames * D;

    fec_bench::BlockInterleaver interleaver(cfg.n, D);

    // Phase 1 Step E: optional production interleaver, same schedule
    // (pinned by interleaver_schedule_test). Allocated once per
    // config; reused across frames via its push/drain/reset cycle.
    // Only engaged when depth > 1 (the class itself supports D==1
    // as a degenerate but the harness skips it since there's no
    // schedule difference to time).
    std::unique_ptr<wfb::BlockInterleaver> prod_interleaver;
    if (cfg.use_prod_interleaver && D > 1) {
        prod_interleaver.reset(new wfb::BlockInterleaver(cfg.n, D, buf_size));
    }

    fec_t* fec_p = nullptr;
    if (fec_new(uint16_t(cfg.k), uint16_t(cfg.n), &fec_p) != ZFEX_SC_OK) {
        std::fprintf(stderr, "fec_new(%u, %u) failed\n", cfg.k, cfg.n);
        std::exit(1);
    }

    // D * n owned buffers. Outer index = block slot within a frame
    // (0 .. D-1); inner = fragment index within the block (0 .. n-1).
    // [d][0..k)  = primaries, [d][k..n) = parity.
    std::vector<std::vector<uint8_t*>> frag(D, std::vector<uint8_t*>(cfg.n, nullptr));
    for (unsigned d = 0; d < D; ++d) {
        for (unsigned i = 0; i < cfg.n; ++i) {
            frag[d][i] = static_cast<uint8_t*>(xaligned_alloc(ZFEX_SIMD_ALIGNMENT, buf_size));
        }
    }

    // Scratch for pre-decode byte snapshotting (see step C(4) below).
    uint8_t* original_copy = static_cast<uint8_t*>(xaligned_alloc(ZFEX_SIMD_ALIGNMENT, buf_size));

    Result result;
    result.encode_ns.reserve(total_blocks);
    result.decode_ns.reserve(total_blocks);
    result.interleaver_ns.reserve(total_blocks);

    // Per-block working storage for fec_decode_simd argument marshalling.
    // Reused across blocks; capacity never shrinks.
    std::vector<const uint8_t*> in_ptrs(cfg.k, nullptr);
    std::vector<uint8_t*>       out_ptrs;           out_ptrs.reserve(cfg.k);
    std::vector<unsigned>       idx_arr(cfg.k, 0);
    std::vector<unsigned>       reconstruct_targets; reconstruct_targets.reserve(cfg.k);
    std::vector<unsigned>       empty_primary_slots; empty_primary_slots.reserve(cfg.k);

    // survived[d][i] = did fragment i of block frame*D+d survive this frame.
    // Reused across frames; reset to all-true at the top of each frame.
    std::vector<std::vector<bool>> survived(D, std::vector<bool>(cfg.n, true));

    for (uint64_t frame = 0; frame < num_frames; ++frame) {
        // =============================================================
        // A. Encode all D blocks in this frame.
        // =============================================================
        for (unsigned d = 0; d < D; ++d) {
            const uint64_t b = frame * uint64_t(D) + d;

            for (unsigned i = 0; i < cfg.k; ++i) {
                fill_primary(frag[d][i], cfg.block_size, b, i);
            }
            // Zero tail bytes in the aligned-up region so the SIMD
            // encode doesn't hash uninitialised memory into the
            // parity.
            if (buf_size > cfg.block_size) {
                for (unsigned i = 0; i < cfg.k; ++i) {
                    std::memset(frag[d][i] + cfg.block_size, 0,
                                buf_size - cfg.block_size);
                }
            }

            const uint64_t t0 = now_ns();
            const zfex_status_code_t enc_rc = fec_encode_simd(
                fec_p,
                reinterpret_cast<const gf* const*>(frag[d].data()),
                reinterpret_cast<gf* const*>(frag[d].data() + cfg.k),
                cfg.block_size);
            const uint64_t t1 = now_ns();
            if (enc_rc != ZFEX_SC_OK) {
                std::fprintf(stderr,
                    "fec_encode_simd failed at block %llu\n",
                    (unsigned long long)b);
                std::exit(1);
            }
            result.encode_ns.push_back(t1 - t0);
        }

        // =============================================================
        // B. Walk the D*n emit slots of this frame in INTERLEAVER
        //    order; invoke the channel at each slot. This is what
        //    makes GE / periodic see emit-time ordering rather than
        //    block-at-a-time ordering -- the whole reason we buffered
        //    D blocks before emitting.
        //
        //    Two modes:
        //      - reference (default): slot->(b,f) mapping via the
        //        pure-math fec_bench::BlockInterleaver. Fast, no
        //        allocations beyond config setup.
        //      - production (--use-prod-interleaver): push D*n
        //        encoded fragments into wfb::BlockInterleaver and
        //        drain them, timing the push+drain cycle. This
        //        captures the real per-fragment memcpy cost the
        //        Phase 1 wfb_tx will pay at run-time. The schedule
        //        test pins production = reference, so recovery
        //        numbers in both modes are identical.
        // =============================================================
        for (unsigned d = 0; d < D; ++d) {
            std::fill(survived[d].begin(), survived[d].end(), true);
        }
        const uint64_t slots_per_frame = uint64_t(D) * uint64_t(cfg.n);
        const uint64_t frame_base_slot = frame * slots_per_frame;

        if (prod_interleaver) {
            // Production: push every fragment into the interleaver
            // then drain. Time the full cycle. Inside drain, we use
            // the reference for slot->(b,f) lookup (schedule-
            // equivalent per interleaver_schedule_test).
            const uint64_t t_int_start = now_ns();
            for (unsigned d = 0; d < D; ++d) {
                const uint64_t b = frame * uint64_t(D) + d;
                for (unsigned f = 0; f < cfg.n; ++f) {
                    prod_interleaver->push(b, f, frag[d][f], buf_size);
                }
            }
            assert(prod_interleaver->is_frame_full());
            uint64_t slot_counter = frame_base_slot;
            prod_interleaver->drain(
                [&](const uint8_t* /*buf*/, std::size_t /*sz*/) {
                    const auto bf = interleaver.fragment_at(slot_counter);
                    const unsigned d = unsigned(bf.first - frame * uint64_t(D));
                    const unsigned f = bf.second;
                    const bool dropped = channel.drop(slot_counter);
                    survived[d][f] = !dropped;
                    ++slot_counter;
                });
            const uint64_t t_int_end = now_ns();
            // Normalize to per-block: one frame of D blocks shares
            // one push+drain cycle, so divide by D for an
            // apples-to-apples comparison with encode_us and
            // decode_us (which are also per-block).
            const uint64_t dt_per_block = (t_int_end - t_int_start) / uint64_t(D);
            for (unsigned d = 0; d < D; ++d) {
                result.interleaver_ns.push_back(dt_per_block);
            }
        } else {
            // Reference path (default): mapping only, no memcpy.
            for (uint64_t s = 0; s < slots_per_frame; ++s) {
                const uint64_t absolute_slot = frame_base_slot + s;
                const auto bf = interleaver.fragment_at(absolute_slot);
                const uint64_t b = bf.first;
                const unsigned f = bf.second;
                assert(b / D == frame);
                const unsigned d = unsigned(b - frame * uint64_t(D));

                const bool dropped = channel.drop(absolute_slot);
                survived[d][f] = !dropped;
            }
        }

        // =============================================================
        // C. Per-block recovery + verification. Independent across
        //    the D blocks of this frame.
        // =============================================================
        for (unsigned d = 0; d < D; ++d) {
            const uint64_t b = frame * uint64_t(D) + d;
            uint8_t** block_frag = frag[d].data();
            const std::vector<bool>& surv = survived[d];

            result.primary_packets_total += cfg.k;

            unsigned n_survived = 0;
            for (unsigned i = 0; i < cfg.n; ++i) if (surv[i]) ++n_survived;

            if (n_survived < cfg.k) {
                // Unrecoverable. Count any surviving primaries as
                // delivered; count the rest as lost. (RX could in
                // principle still forward surviving primaries even
                // without FEC, matching current wfb_rx behavior.)
                unsigned primaries_got = 0;
                for (unsigned i = 0; i < cfg.k; ++i) if (surv[i]) ++primaries_got;
                result.primary_packets_lost += (cfg.k - primaries_got);
                result.blocks_lost += 1;
                continue;
            }

            result.blocks_recovered += 1;

            // Fast path: all primaries survived, no decode needed.
            bool all_primaries_survived = true;
            for (unsigned i = 0; i < cfg.k; ++i) {
                if (!surv[i]) { all_primaries_survived = false; break; }
            }
            if (all_primaries_survived) continue;

            // ---- Build fec_decode_simd inputs. ----------------------
            // Shape, per zfex.h:
            //   in_ptrs[i]: a surviving fragment buffer.
            //   idx_arr[i]: the fragment number of in_ptrs[i].
            //   If primary i survived, in_ptrs[i] must be that primary
            //   and idx_arr[i] == i. Empty primary slots get filled
            //   with surviving parities (idx >= k). out_ptrs lists
            //   buffers to reconstruct missing primaries into.
            out_ptrs.clear();
            reconstruct_targets.clear();
            empty_primary_slots.clear();

            for (unsigned i = 0; i < cfg.k; ++i) {
                if (surv[i]) {
                    in_ptrs[i] = block_frag[i];
                    idx_arr[i] = i;
                } else {
                    empty_primary_slots.push_back(i);
                }
            }

            unsigned parity_cursor = cfg.k;
            for (unsigned slot : empty_primary_slots) {
                while (parity_cursor < cfg.n && !surv[parity_cursor]) ++parity_cursor;
                assert(parity_cursor < cfg.n);

                in_ptrs[slot] = block_frag[parity_cursor];
                idx_arr[slot] = parity_cursor;
                ++parity_cursor;

                // Snapshot original bytes for post-decode byte
                // verification, then zero the buffer so any
                // unreconstructed byte stands out.
                std::memcpy(original_copy, block_frag[slot], buf_size);
                std::memset(block_frag[slot], 0, buf_size);
                out_ptrs.push_back(block_frag[slot]);
                reconstruct_targets.push_back(slot);
            }

            const uint64_t d0 = now_ns();
            const zfex_status_code_t dec_rc = fec_decode_simd(
                fec_p,
                reinterpret_cast<const gf**>(in_ptrs.data()),
                reinterpret_cast<gf* const*>(out_ptrs.data()),
                idx_arr.data(),
                cfg.block_size);
            const uint64_t d1 = now_ns();
            if (dec_rc != ZFEX_SC_OK) {
                std::fprintf(stderr,
                    "fec_decode_simd failed at block %llu\n",
                    (unsigned long long)b);
                std::exit(1);
            }
            result.decode_ns.push_back(d1 - d0);

            // Byte-exact verification of reconstructed primaries.
            for (size_t r = 0; r < reconstruct_targets.size(); ++r) {
                const unsigned slot = reconstruct_targets[r];
                for (size_t j = 0; j < cfg.block_size; ++j) {
                    const uint8_t want = expected_byte(b, slot, j);
                    if (block_frag[slot][j] != want) {
                        std::fprintf(stderr,
                            "decode verify mismatch: block=%llu slot=%u "
                            "byte=%zu got=0x%02x want=0x%02x\n",
                            (unsigned long long)b, slot, j,
                            block_frag[slot][j], want);
                        std::exit(1);
                    }
                }
            }
        }
    }

    // Free per-config storage.
    for (unsigned d = 0; d < D; ++d) {
        for (unsigned i = 0; i < cfg.n; ++i) free(frag[d][i]);
    }
    free(original_copy);
    fec_free(fec_p);

    result.peak_mem_bytes =
        uint64_t(D) * uint64_t(cfg.n) * uint64_t(buf_size) // frag buffers
      + uint64_t(buf_size)                                  // original_copy
      + uint64_t(total_blocks) * sizeof(uint64_t) * 2;      // timing vectors
    return result;
}

// Thin dispatch wrapper -- picks the channel model from the config,
// constructs it with a deterministic child seed.
Result run_config_dispatch(const Config& cfg) {
    const uint64_t child_seed = splitmix64(cfg.seed ^ uint64_t(cfg.model));
    switch (cfg.model) {
        case Model::Uniform: {
            fec_bench::UniformLoss ch(cfg.param1, child_seed);
            return run_config(cfg, ch);
        }
        case Model::GE: {
            fec_bench::GilbertElliottLoss ch(cfg.param1, cfg.param2, child_seed);
            return run_config(cfg, ch);
        }
        case Model::Periodic: {
            fec_bench::PeriodicLoss ch(size_t(cfg.param1), size_t(cfg.param2), child_seed);
            return run_config(cfg, ch);
        }
    }
    // Unreachable.
    std::fprintf(stderr, "run_config_dispatch: unknown model\n");
    std::exit(1);
}

// ---------------------------------------------------------------------------
// CSV output
// ---------------------------------------------------------------------------

// CSV schema. `depth` sits between `n` and `blocks` per plan §3.4
// (rebased into v2.1). `latency_ms` (v2.1 addition) is computed from
// a theoretical model at the plan §4.2 reference operating point;
// see `Config` for the assumed IPI/airtime/slack.
// `interleaver_us_*` (Phase 1 Step E) are the production interleaver
// push+drain per-block cost. Empty when --use-prod-interleaver is
// off or depth == 1.
// The old Phase 0 baseline.csv (without depth/latency/interleaver
// columns) is still readable by bench_summary.py.
const char* CSV_HEADER =
    "channel_model,param1,param2,k,n,depth,blocks,seed,"
    "block_recovery_rate,residual_packet_loss,"
    "encode_us_mean,encode_us_p99,"
    "decode_us_mean,decode_us_p99,"
    "interleaver_us_mean,interleaver_us_p99,"
    "peak_mem_bytes,latency_ms";

void write_csv_header(FILE* out) {
    std::fprintf(out, "%s\n", CSV_HEADER);
}

void write_csv_row(FILE* out, const Config& cfg, Result& res) {
    // Effective blocks run -- run_config rounds up to a multiple of D.
    const uint64_t total_blocks = res.blocks_recovered + res.blocks_lost;
    const double recovery_rate = total_blocks > 0
        ? double(res.blocks_recovered) / double(total_blocks) : 0.0;
    const double residual_loss = res.primary_packets_total > 0
        ? double(res.primary_packets_lost) / double(res.primary_packets_total) : 0.0;

    const double enc_mean_us = mean_ns(res.encode_ns) / 1000.0;
    const uint64_t enc_p99_ns = percentile_ns(res.encode_ns, 0.99);
    const double enc_p99_us = double(enc_p99_ns) / 1000.0;

    const bool have_decode = !res.decode_ns.empty();
    const double dec_mean_us = have_decode ? mean_ns(res.decode_ns) / 1000.0 : 0.0;
    const uint64_t dec_p99_ns = have_decode ? percentile_ns(res.decode_ns, 0.99) : 0;
    const double dec_p99_us = have_decode ? double(dec_p99_ns) / 1000.0 : 0.0;

    // param2 is empty for uniform; numeric for ge and periodic. We
    // still always emit a field (possibly empty) so column count is
    // stable across models.
    char p2buf[32];
    if (cfg.model == Model::Uniform) {
        p2buf[0] = '\0';
    } else {
        std::snprintf(p2buf, sizeof(p2buf), "%.6g", cfg.param2);
    }

    // Empty cells for decode stats when we never decoded.
    char dec_mean_buf[32], dec_p99_buf[32];
    if (have_decode) {
        std::snprintf(dec_mean_buf, sizeof(dec_mean_buf), "%.3f", dec_mean_us);
        std::snprintf(dec_p99_buf,  sizeof(dec_p99_buf),  "%.3f", dec_p99_us);
    } else {
        dec_mean_buf[0] = '\0';
        dec_p99_buf[0]  = '\0';
    }

    // Phase 1 Step E: production interleaver timing. Empty when
    // --use-prod-interleaver was not set, or when depth == 1.
    char int_mean_buf[32], int_p99_buf[32];
    const bool have_int = !res.interleaver_ns.empty();
    if (have_int) {
        const double int_mean_us = mean_ns(res.interleaver_ns) / 1000.0;
        const uint64_t int_p99_ns = percentile_ns(res.interleaver_ns, 0.99);
        const double int_p99_us = double(int_p99_ns) / 1000.0;
        std::snprintf(int_mean_buf, sizeof(int_mean_buf), "%.3f", int_mean_us);
        std::snprintf(int_p99_buf,  sizeof(int_p99_buf),  "%.3f", int_p99_us);
    } else {
        int_mean_buf[0] = '\0';
        int_p99_buf[0]  = '\0';
    }

    // Plan §4.2 latency model:
    //   block_duration_ms = k * ipi_ms + n * airtime_ms
    //   latency_ms        = D * block_duration_ms + slack_ms
    // Decode time is not folded in -- it is sub-millisecond per §3.6
    // measurements and adds noise across seeds. The CSV's
    // decode_us_mean column shows that cost separately.
    const double airtime_ms        = cfg.airtime_us / 1000.0;
    const double block_duration_ms = double(cfg.k) * cfg.ipi_ms
                                   + double(cfg.n) * airtime_ms;
    const double latency_ms        = double(cfg.depth) * block_duration_ms
                                   + cfg.slack_ms;

    std::fprintf(out,
        "%s,%.6g,%s,%u,%u,%u,%llu,%llu,"
        "%.6f,%.6f,"
        "%.3f,%.3f,"
        "%s,%s,"
        "%s,%s,"
        "%llu,%.3f\n",
        model_name(cfg.model),
        cfg.param1, p2buf,
        cfg.k, cfg.n, cfg.depth,
        (unsigned long long)total_blocks,
        (unsigned long long)cfg.seed,
        recovery_rate, residual_loss,
        enc_mean_us, enc_p99_us,
        dec_mean_buf, dec_p99_buf,
        int_mean_buf, int_p99_buf,
        (unsigned long long)res.peak_mem_bytes,
        latency_ms);
    std::fflush(out);
}

// ---------------------------------------------------------------------------
// Sweep driver
//
// Two presets, matching the plan:
//   small  -- fast smoke sweep, single (k,n), one seed, 1000 blocks.
//             Intended for CI and local sanity checks. Seconds to run.
//   full   -- full Cartesian product per plan §3.5: four (k,n) pairs,
//             three channel models at their full parameter sweeps,
//             three seeds per config, 10000 blocks each, depths
//             {1,2,4,8}. (v2.1: depth 16 dropped from the baseline
//             sweep -- it sits well above plan §4.2's depth ceiling
//             for every stream type and is of regression-test
//             interest only. Add with --single to spot-check.)
//
// Progress is printed to stderr so --output /dev/stdout remains clean.
// ---------------------------------------------------------------------------

struct SweepGrid {
    std::vector<std::pair<unsigned, unsigned>> kn_pairs;   // (k, n)
    std::vector<unsigned> depths;                          // interleaver depth axis
    std::vector<double> uniform_losses;                    // per uniform
    std::vector<std::pair<double, double>> ge_params;      // (burst, gap)
    std::vector<std::pair<size_t, size_t>> periodic_params;// (period, burst_len)
    unsigned seeds_per_config;
    uint64_t blocks;
};

SweepGrid make_grid_small() {
    SweepGrid g;
    g.kn_pairs       = { {8, 12} };
    g.depths         = { 1, 2, 4 };
    g.uniform_losses = { 0.0, 0.05, 0.20 };
    g.ge_params      = { {5.0, 100.0} };
    g.periodic_params= { {10, 1} };
    g.seeds_per_config = 1;
    g.blocks           = 1000;
    return g;
}

SweepGrid make_grid_full() {
    SweepGrid g;
    g.kn_pairs       = { {8, 12}, {4, 8}, {4, 12}, {16, 20} };
    g.depths         = { 1, 2, 4, 8 };
    g.uniform_losses = { 0.01, 0.05, 0.10, 0.20, 0.30 };
    g.ge_params      = {
        {2.0, 100.0}, {5.0, 100.0}, {10.0, 100.0}, {20.0, 100.0},
        {2.0, 1000.0}, {5.0, 1000.0}, {10.0, 1000.0}, {20.0, 1000.0},
    };
    g.periodic_params= { {5, 1}, {10, 1}, {20, 1} };
    g.seeds_per_config = 3;
    g.blocks           = 10000;
    return g;
}

size_t count_configs(const SweepGrid& g) {
    const size_t per_kn =
        g.uniform_losses.size()
      + g.ge_params.size()
      + g.periodic_params.size();
    return g.kn_pairs.size() * g.depths.size() * per_kn * g.seeds_per_config;
}

void run_and_emit(FILE* out, const Config& cfg) {
    Result res = run_config_dispatch(cfg);
    write_csv_row(out, cfg, res);
}

void run_sweep(FILE* out, const SweepGrid& g, const Config& tmpl) {
    const size_t total = count_configs(g);
    size_t done = 0;
    uint64_t ctr = 0; // monotonic counter across all configs; mixed into seed

    std::fprintf(stderr, "[sweep] %zu configs to run, %llu blocks each\n",
                 total, (unsigned long long)g.blocks);

    auto emit = [&](Model m, double p1, double p2,
                    unsigned k, unsigned n, unsigned D) {
        for (unsigned s = 0; s < g.seeds_per_config; ++s) {
            // Start from the top-level template so timing overrides
            // (--ipi-ms / --airtime-us / --slack-ms, --block-size)
            // propagate into every row.
            Config cfg = tmpl;
            cfg.model = m;
            cfg.param1 = p1;
            cfg.param2 = p2;
            cfg.k = k; cfg.n = n; cfg.depth = D;
            cfg.blocks = g.blocks;
            cfg.seed = splitmix64(tmpl.seed + ctr++);

            run_and_emit(out, cfg);
            ++done;
            std::fprintf(stderr,
                "[sweep] %zu/%zu (%s k=%u n=%u D=%u p1=%.4g p2=%.4g)\n",
                done, total, model_name(m), k, n, D, p1, p2);
        }
    };

    for (const auto& kn : g.kn_pairs) {
        const unsigned k = kn.first;
        const unsigned n = kn.second;
        for (unsigned D : g.depths) {
            for (double p : g.uniform_losses)     emit(Model::Uniform,  p,   0.0, k, n, D);
            for (const auto& gp : g.ge_params)    emit(Model::GE, gp.first, gp.second, k, n, D);
            for (const auto& pp : g.periodic_params) emit(Model::Periodic,
                                                         double(pp.first),
                                                         double(pp.second), k, n, D);
        }
    }
}

// ---------------------------------------------------------------------------
// CLI parsing
// ---------------------------------------------------------------------------

[[noreturn]] void usage(int code) {
    std::fprintf(stderr,
        "Usage: fec_bench [--sweep <preset> | --single ...] [--output PATH]\n"
        "                 [--seed N] [--append] [--selftest]\n"
        "\n"
        "Modes (mutually exclusive):\n"
        "  --sweep <preset>        Run a preset sweep. Presets:\n"
        "                            small -- fast smoke sweep (1k blocks, (8,12))\n"
        "                            full  -- full baseline per plan §3.5\n"
        "                                     (10k blocks, 4 (k,n), 3 seeds)\n"
        "  --single                Run one configuration. Flags:\n"
        "      --channel {uniform|ge|periodic}\n"
        "      --loss P            (uniform)\n"
        "      --burst-mean M --gap-mean G    (ge)\n"
        "      --period P --burst-len L       (periodic)\n"
        "      --k K --n N\n"
        "      --interleave-depth D  (default 1 = no interleaving)\n"
        "      --blocks N          (default 10000; rounded up to a multiple of D)\n"
        "      --block-size BYTES  (default 1466)\n"
        "      --ipi-ms F          inter-packet interval, ms  (default 1.4)\n"
        "      --airtime-us F      per-packet airtime, µs     (default 80)\n"
        "      --slack-ms F        RX deadline slack, ms       (default 5)\n"
        "                          (timing flags parametrize the CSV's\n"
        "                           latency_ms column; they do not affect\n"
        "                           the recovery measurement itself.)\n"
        "      --use-prod-interleaver\n"
        "                          Route fragments through the Phase 1\n"
        "                          production src/interleaver.cpp and\n"
        "                          time push+drain per block. Recovery\n"
        "                          numbers are unchanged (schedule is\n"
        "                          pinned equal to the reference).\n"
        "  --selftest              Run built-in correctness gates and exit.\n"
        "\n"
        "Common:\n"
        "  --output PATH           CSV output path (default stdout).\n"
        "  --append                Append to --output without writing header.\n"
        "  --seed N                Master seed (default 0xC0FFEE).\n"
        "  --help\n");
    std::exit(code);
}

const char* eat(int& i, int argc, char** argv, const char* flag) {
    if (i + 1 >= argc) {
        std::fprintf(stderr, "%s requires an argument\n", flag);
        usage(2);
    }
    return argv[++i];
}

Model parse_model(const char* s) {
    if (!std::strcmp(s, "uniform"))  return Model::Uniform;
    if (!std::strcmp(s, "ge"))       return Model::GE;
    if (!std::strcmp(s, "periodic")) return Model::Periodic;
    std::fprintf(stderr, "unknown channel model: %s\n", s);
    usage(2);
}

// ---------------------------------------------------------------------------
// Selftest: the correctness gates Step B promised.
// ---------------------------------------------------------------------------
bool selftest() {
    std::fprintf(stderr, "[selftest] 1. uniform p=0.0 -> expect 100%% recovery\n");
    {
        Config cfg; cfg.model = Model::Uniform; cfg.param1 = 0.0;
        cfg.k = 8; cfg.n = 12; cfg.blocks = 500; cfg.block_size = 1466;
        cfg.seed = 1;
        Result r = run_config_dispatch(cfg);
        if (r.blocks_recovered != cfg.blocks || r.primary_packets_lost != 0) {
            std::fprintf(stderr,
                "  FAIL: recovered=%llu/%llu lost=%llu\n",
                (unsigned long long)r.blocks_recovered,
                (unsigned long long)cfg.blocks,
                (unsigned long long)r.primary_packets_lost);
            return false;
        }
        std::fprintf(stderr, "  ok\n");
    }

    std::fprintf(stderr, "[selftest] 2. uniform p=1.0 -> expect 0%% recovery\n");
    {
        Config cfg; cfg.model = Model::Uniform; cfg.param1 = 1.0;
        cfg.k = 8; cfg.n = 12; cfg.blocks = 500; cfg.block_size = 1466;
        cfg.seed = 2;
        Result r = run_config_dispatch(cfg);
        if (r.blocks_recovered != 0 ||
            r.primary_packets_lost != cfg.blocks * cfg.k) {
            std::fprintf(stderr,
                "  FAIL: recovered=%llu/%llu lost=%llu\n",
                (unsigned long long)r.blocks_recovered,
                (unsigned long long)cfg.blocks,
                (unsigned long long)r.primary_packets_lost);
            return false;
        }
        std::fprintf(stderr, "  ok\n");
    }

    std::fprintf(stderr, "[selftest] 3. (k=8,n=12) at p=0.10 -> expect >0 decodes "
                         "and 100%% verified reconstruction\n");
    {
        // n-k = 4 parity. At p=0.10, most blocks have <=4 losses and
        // are recoverable; occasional blocks have >4 and are lost.
        // Either way, every decode that runs must verify bit-exact.
        // We don't assert a specific recovery rate here (that's a
        // measurement, not a gate); just that some decodes happened
        // AND the verify loop in run_config didn't abort.
        Config cfg; cfg.model = Model::Uniform; cfg.param1 = 0.10;
        cfg.k = 8; cfg.n = 12; cfg.blocks = 500; cfg.block_size = 1466;
        cfg.seed = 3;
        Result r = run_config_dispatch(cfg);
        if (r.decode_ns.empty()) {
            std::fprintf(stderr, "  FAIL: no decode invocations at p=0.10\n");
            return false;
        }
        std::fprintf(stderr, "  ok: recovered=%llu/%llu, decodes=%zu\n",
                     (unsigned long long)r.blocks_recovered,
                     (unsigned long long)cfg.blocks,
                     r.decode_ns.size());
    }

    std::fprintf(stderr, "[selftest] 4. determinism: same seed -> same counts\n");
    {
        Config cfg; cfg.model = Model::Uniform; cfg.param1 = 0.20;
        cfg.k = 8; cfg.n = 12; cfg.blocks = 500; cfg.block_size = 1466;
        cfg.seed = 42;
        Result a = run_config_dispatch(cfg);
        Result b = run_config_dispatch(cfg);
        if (a.blocks_recovered != b.blocks_recovered ||
            a.primary_packets_lost != b.primary_packets_lost) {
            std::fprintf(stderr,
                "  FAIL: a=(rec=%llu lost=%llu) b=(rec=%llu lost=%llu)\n",
                (unsigned long long)a.blocks_recovered, (unsigned long long)a.primary_packets_lost,
                (unsigned long long)b.blocks_recovered, (unsigned long long)b.primary_packets_lost);
            return false;
        }
        std::fprintf(stderr, "  ok\n");
    }

    std::fprintf(stderr, "[selftest] 5. interleaver actually disperses bursts:\n"
                         "            periodic burst_len=5 (> parity 4) at D=1 should fail;\n"
                         "            same burst at D=4 should recover.\n");
    {
        // Construct a periodic 5-in-17 loss pattern. At (k,n)=(8,12),
        // parity budget is 4, so a 5-fragment burst falling inside a
        // single block is unrecoverable. Picking period=17 (coprime
        // with n=12) avoids fluke alignment with the D=4 interleaver
        // schedule -- at D=4, each block sees ≤ 4 losses per frame,
        // recoverable at the edge.
        Config a; a.model = Model::Periodic;
        a.param1 = 17; a.param2 = 5;
        a.k = 8; a.n = 12; a.depth = 1;
        a.blocks = 1024; a.block_size = 1466; a.seed = 5;
        Result ra = run_config_dispatch(a);

        Config b = a; b.depth = 4;
        Result rb = run_config_dispatch(b);

        if (ra.blocks_lost == 0) {
            std::fprintf(stderr,
                "  FAIL: D=1 lost 0 blocks -- the test premise is wrong\n");
            return false;
        }
        if (rb.blocks_lost != 0) {
            std::fprintf(stderr,
                "  FAIL: D=4 lost %llu blocks, expected 0\n",
                (unsigned long long)rb.blocks_lost);
            return false;
        }
        std::fprintf(stderr, "  ok: D=1 lost %llu/%llu; D=4 lost 0\n",
                     (unsigned long long)ra.blocks_lost,
                     (unsigned long long)a.blocks);
    }

    std::fprintf(stderr, "[selftest] 6. D=1 reduces to pre-interleaver behavior:\n"
                         "            block counts identical to pre-refactor harness at D=1.\n");
    {
        // This one is a regression canary for the run_config rewrite:
        // at D=1, uniform p=0.10, seed=3, k=8, n=12, 500 blocks --
        // the same numbers Step B's selftest #3 recorded.
        Config c; c.model = Model::Uniform; c.param1 = 0.10;
        c.k = 8; c.n = 12; c.depth = 1;
        c.blocks = 500; c.block_size = 1466; c.seed = 3;
        Result r = run_config_dispatch(c);
        // Step B's run of this config produced blocks_recovered=498.
        // Anything different means the D=1 path changed semantics.
        if (r.blocks_recovered != 498) {
            std::fprintf(stderr,
                "  FAIL: recovered=%llu, expected 498 (the pre-refactor Step B number)\n",
                (unsigned long long)r.blocks_recovered);
            return false;
        }
        std::fprintf(stderr, "  ok: D=1 recovered=498/500 matches Step B exactly\n");
    }

    std::fprintf(stderr, "[selftest] all passed\n");
    return true;
}

} // namespace

int main(int argc, char** argv) {
    enum class Mode { None, Sweep, Single, Selftest } mode = Mode::None;
    const char* sweep_preset = nullptr;
    const char* output_path  = nullptr;
    bool append = false;

    Config cfg;
    bool channel_set = false;

    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (!std::strcmp(a, "--help") || !std::strcmp(a, "-h")) {
            usage(0);
        } else if (!std::strcmp(a, "--selftest")) {
            if (mode != Mode::None) usage(2);
            mode = Mode::Selftest;
        } else if (!std::strcmp(a, "--sweep")) {
            if (mode != Mode::None) usage(2);
            mode = Mode::Sweep;
            sweep_preset = eat(i, argc, argv, a);
        } else if (!std::strcmp(a, "--single")) {
            if (mode != Mode::None) usage(2);
            mode = Mode::Single;
        } else if (!std::strcmp(a, "--output") || !std::strcmp(a, "-o")) {
            output_path = eat(i, argc, argv, a);
        } else if (!std::strcmp(a, "--append")) {
            append = true;
        } else if (!std::strcmp(a, "--seed")) {
            cfg.seed = std::strtoull(eat(i, argc, argv, a), nullptr, 0);
        } else if (!std::strcmp(a, "--channel")) {
            cfg.model = parse_model(eat(i, argc, argv, a));
            channel_set = true;
        } else if (!std::strcmp(a, "--loss")) {
            cfg.param1 = std::atof(eat(i, argc, argv, a));
        } else if (!std::strcmp(a, "--burst-mean")) {
            cfg.param1 = std::atof(eat(i, argc, argv, a));
        } else if (!std::strcmp(a, "--gap-mean")) {
            cfg.param2 = std::atof(eat(i, argc, argv, a));
        } else if (!std::strcmp(a, "--period")) {
            cfg.param1 = std::atof(eat(i, argc, argv, a));
        } else if (!std::strcmp(a, "--burst-len")) {
            cfg.param2 = std::atof(eat(i, argc, argv, a));
        } else if (!std::strcmp(a, "--interleave-depth")) {
            cfg.depth = unsigned(std::atoi(eat(i, argc, argv, a)));
            if (cfg.depth < 1) {
                std::fprintf(stderr, "--interleave-depth must be >= 1\n");
                usage(2);
            }
        } else if (!std::strcmp(a, "--ipi-ms")) {
            cfg.ipi_ms = std::atof(eat(i, argc, argv, a));
        } else if (!std::strcmp(a, "--airtime-us")) {
            cfg.airtime_us = std::atof(eat(i, argc, argv, a));
        } else if (!std::strcmp(a, "--slack-ms")) {
            cfg.slack_ms = std::atof(eat(i, argc, argv, a));
        } else if (!std::strcmp(a, "--use-prod-interleaver")) {
            cfg.use_prod_interleaver = true;
        } else if (!std::strcmp(a, "--k")) {
            cfg.k = unsigned(std::atoi(eat(i, argc, argv, a)));
        } else if (!std::strcmp(a, "--n")) {
            cfg.n = unsigned(std::atoi(eat(i, argc, argv, a)));
        } else if (!std::strcmp(a, "--blocks")) {
            cfg.blocks = std::strtoull(eat(i, argc, argv, a), nullptr, 0);
        } else if (!std::strcmp(a, "--block-size")) {
            cfg.block_size = size_t(std::strtoull(eat(i, argc, argv, a), nullptr, 0));
        } else {
            std::fprintf(stderr, "unknown argument: %s\n", a);
            usage(2);
        }
    }

    if (mode == Mode::None) {
        std::fprintf(stderr, "no mode specified (try --selftest or --single)\n");
        usage(2);
    }

    if (mode == Mode::Selftest) {
        return selftest() ? 0 : 1;
    }

    if (mode == Mode::Sweep) {
        SweepGrid g;
        if (!std::strcmp(sweep_preset, "small")) {
            g = make_grid_small();
        } else if (!std::strcmp(sweep_preset, "full")) {
            g = make_grid_full();
        } else {
            std::fprintf(stderr, "unknown sweep preset: %s (expected small|full)\n",
                         sweep_preset);
            return 2;
        }

        FILE* out = stdout;
        if (output_path != nullptr) {
            out = std::fopen(output_path, append ? "ae" : "we");
            if (!out) {
                std::fprintf(stderr, "fopen(%s): %s\n",
                             output_path, std::strerror(errno));
                return 1;
            }
        }
        if (!append) write_csv_header(out);
        run_sweep(out, g, cfg);
        if (out != stdout) std::fclose(out);
        return 0;
    }

    // --single mode.
    if (!channel_set) {
        std::fprintf(stderr, "--single requires --channel\n");
        usage(2);
    }
    if (cfg.k == 0 || cfg.n < cfg.k) {
        std::fprintf(stderr, "invalid (k=%u, n=%u): require n >= k >= 1\n",
                     cfg.k, cfg.n);
        usage(2);
    }
    if (cfg.block_size == 0) {
        std::fprintf(stderr, "block_size must be > 0\n");
        usage(2);
    }

    FILE* out = stdout;
    if (output_path != nullptr) {
        out = std::fopen(output_path, append ? "ae" : "we");
        if (!out) {
            std::fprintf(stderr, "fopen(%s): %s\n", output_path, std::strerror(errno));
            return 1;
        }
    }
    if (!append) write_csv_header(out);

    Result res = run_config_dispatch(cfg);
    write_csv_row(out, cfg, res);

    if (out != stdout) std::fclose(out);
    return 0;
}
