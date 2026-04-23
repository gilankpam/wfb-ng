// src/fec_swin.hpp
// Sliding-window FEC (WFB_FEC_SWIN_RS) implementation of IFecEncoder
// and (Phase 2b B3, not yet landed) IFecDecoder. Matches the design
// doc §5-§7.
//
// Phase 2b B2: SwinFecEncoder only. SwinFecDecoder arrives in B3;
// until then, make_fec_decoder's SWIN branch throws.
//
// Wire format under WFB_FEC_SWIN_RS (§5.2, §5.4):
//   data_nonce:       bit 63 = is_repair, bits 62..56 = repair_idx,
//                     bits 55..0 = seq_num.
//   source packet:    is_repair=0, repair_idx=0; seq_num is a
//                     monotonic source-side counter.
//   repair packet:    is_repair=1; repair_idx per §5.3 (0 per window
//                     for R ≤ 1, 0..⌈R⌉-1 for R > 1); seq_num is a
//                     monotonic repair-side counter (independent of
//                     the source-side one).
//   repair payload:   wpacket_hdr_repair_t (11 bytes) + parity bytes,
//                     AEAD-encrypted by Transmitter.
//
// Sizes at design defaults (§7.2):
//   video:   W=64  R=0.5   (⌈R·W⌉=32)
//   mavlink: W=16  R=1.0   (⌈R·W⌉=16)
//   tunnel:  W=32  R=1.0   (⌈R·W⌉=32)
//
// Constraints:
//   W ≥ 1, R_num ≥ 1, R_den ≥ 1.
//   ⌈R·W⌉ ≤ 128  (7-bit repair_idx, §5.3).
//   W + ⌈R·W⌉ ≤ 255  (zfex fec_new's n < 256 limit — this is
//                     additional to the §5.3 cap because zfex still
//                     runs an RS code of size W+⌈R·W⌉ internally).

#ifndef FEC_SWIN_HPP
#define FEC_SWIN_HPP

#include "fec_iface.hpp"
#include "zfex.h"

#include <cstdint>
#include <cstddef>
#include <map>
#include <vector>

// wpacket_hdr_repair_t moved to fec_iface.hpp in B4 so tx.cpp and
// rx.cpp can write/parse the repair inner header without pulling
// SwinFecEncoder / SwinFecDecoder declarations.


// SwinFecEncoder — encoder half of the sliding-window codec.
//
// State machine (§7.3):
//   For R ≤ 1: repair_due_in counter init to ⌈1/R⌉. On each source,
//   decrement; on hit-0, mark 1 pending repair (with repair_idx=0),
//   reset counter.
//   For R > 1: on each source, mark ⌈R⌉ pending repairs with
//   repair_idx=0..⌈R⌉-1.
//
// Transmitter contract: call on_source_packet, then drain
// next_repair in a loop until it returns false. Repairs carry the
// current window (seq_tail = latest source seq) and a parity row
// computed via fec_encode_row_simd (Phase 2b B1).
//
// Ownership: one per Transmitter via unique_ptr. No thread safety.
class SwinFecEncoder : public IFecEncoder {
public:
    SwinFecEncoder(uint16_t W, uint8_t R_num, uint8_t R_den);
    ~SwinFecEncoder() override;

    void on_source_packet(uint64_t seq,
                          const uint8_t* payload,
                          size_t sz) override;

    bool next_repair(uint8_t* out,
                     size_t* sz_out,
                     uint64_t* nonce_out) override;

    void tick(uint64_t now_ms) override;

private:
    SwinFecEncoder(const SwinFecEncoder&) = delete;
    SwinFecEncoder& operator=(const SwinFecEncoder&) = delete;

    // Configuration (immutable post-construction).
    const uint16_t W_;            // window width; zfex k
    const uint8_t  R_num_;
    const uint8_t  R_den_;
    const uint16_t repairs_per_window_;   // ⌈R·W⌉, zfex (n - k)
    const bool     R_gt_1_;               // R_num > R_den ⇒ R > 1
    const uint16_t repair_period_;        // ⌈1/R⌉, for R ≤ 1 only
    const uint16_t repairs_per_source_;   // ⌈R⌉,    for R > 1 only

    // zfex handle: fec_new(W, W + repairs_per_window_).
    fec_t* fec_p_;

    // Window ring: W_ SIMD-aligned ZFEX_ROUND_UP_SIMD(MAX_FEC_PAYLOAD)
    // slots. Indexed by (seq_num % W_). Initialized to zeros so that
    // partial-window repairs at stream startup treat unseen slots as
    // all-zero sources (decoder treats them the same way on its end,
    // so parity is self-consistent). Pointers held in a raw array
    // sized to W_ — same pattern as BlockFecEncoder.
    uint8_t** ring_;

    // Internal aligned scratch used by fec_encode_row_simd so that
    // the caller's `out` can start with the 11-byte
    // wpacket_hdr_repair_t header (unaligned offset for parity). We
    // compute parity into parity_scratch_, then memcpy it to
    // out + sizeof(wpacket_hdr_repair_t).
    uint8_t* parity_scratch_;

    // Pointer scratch: W_ entries handed to fec_encode_row_simd.
    // Filled fresh on each next_repair with the current window's
    // ring pointers in seq order.
    const uint8_t** input_ptrs_;

    // Per-window bookkeeping.
    uint64_t window_tail_seq_;   // seq_num of latest source seen;
                                 // 0 before first source (but
                                 // has_any_source_ is the valid flag).
    bool     has_any_source_;
    size_t   max_packet_size_;   // largest `sz` seen across the
                                 // current window's sources (resets
                                 // whenever the window's repair burst
                                 // completes).

    // Scheduling state (§7.3).
    uint16_t repair_due_in_;     // R ≤ 1: countdown to next emit.
    uint16_t pending_repairs_;   // # next_repair calls remaining for
                                 // the current burst.
    uint8_t  next_repair_idx_;   // repair_idx to emit on the next
                                 // next_repair call (0 for R ≤ 1;
                                 // 0..⌈R⌉-1 cycling for R > 1).
    uint64_t window_tail_for_burst_;  // snapshot of window_tail_seq_
                                      // at the moment the current
                                      // repair burst was scheduled —
                                      // all repairs in the burst
                                      // share this value.
    size_t   max_pkt_for_burst_;      // snapshot of max_packet_size_
                                      // at burst-scheduling time.

    // Repair-side monotonic seq_num for nonce emission (§5.2).
    // Independent of the source-side seq_num tracked via
    // window_tail_seq_.
    uint64_t repair_seq_next_;
};


// SwinFecDecoder — decoder half of the sliding-window codec.
//
// RX model (§7.4):
// - Source ring with W_rx = 2·W slots; slot = seq_num % W_rx.
// - Repair store keyed by (window_tail_seq, repair_idx), up to
//   W_rx · R entries in practice; implemented as std::map (dynamic).
// - On each source arrival: place in ring, track arrival time, try
//   to drain pop_ready in order.
// - On each repair arrival: store by key, attempt to decode the
//   window [window_tail - W + 1, window_tail] if total known inputs
//   (source + repair) ≥ W.
// - Emit order: pop_ready returns source packets in increasing
//   seq_num order (B0: seq_out IS the flat packet_seq). Gaps in
//   the front are waited for (recovery or T_flush).
// - tick(now_ms): if any RECEIVED/RECOVERED slot ahead of
//   next_emit_seq has been sitting for ≥ T_flush ms, force-advance
//   past the gaps between; count_w_flush++ per flush event.
//
// Ownership / thread model same as SwinFecEncoder.
class SwinFecDecoder : public IFecDecoder {
public:
    SwinFecDecoder(uint16_t W, uint8_t R_num, uint8_t R_den,
                   PacketLossListener* loss_listener,
                   uint64_t T_flush_ms);
    ~SwinFecDecoder() override;

    void on_source_packet(uint64_t seq,
                          const uint8_t* payload,
                          size_t sz) override;

    void on_repair_packet(uint64_t repair_nonce,
                          uint64_t window_tail_seq,
                          uint8_t  repair_idx,
                          const uint8_t* payload,
                          size_t sz) override;

    bool pop_ready(uint64_t* seq_out,
                   uint8_t* out,
                   size_t* sz_out) override;

    void tick(uint64_t now_ms) override;

    // IFecDecoder B0 accessors.
    bool is_repair_fragment(uint64_t data_nonce) const override {
        return (data_nonce >> 63) & 1;
    }
    uint32_t count_p_fec_recovered() const override { return count_p_fec_recovered_; }
    uint32_t count_p_override() const override { return 0; }  // block-specific
    uint32_t count_w_flush() const override { return count_w_flush_; }

private:
    SwinFecDecoder(const SwinFecDecoder&) = delete;
    SwinFecDecoder& operator=(const SwinFecDecoder&) = delete;

    struct SourceSlot {
        uint64_t seq;               // which seq this slot currently
                                    // holds; UINT64_MAX = never used
        uint8_t* data;              // aligned MAX_FEC_PAYLOAD buffer
        size_t   data_size;         // logical payload size (incl.
                                    // wpacket_hdr_t)
        enum State : uint8_t {
            EMPTY = 0,              // slot known to exist (seq set)
                                    // but no data yet (gap)
            RECEIVED,               // source arrived on the wire
            RECOVERED,              // filled via fec_decode_simd
            EMITTED,                // already popped by caller
        } state;
        uint64_t arrival_time_ms;   // when this slot was marked
                                    // RECEIVED or RECOVERED
                                    // (for T_flush deadline)
    };

    struct RepairKey {
        uint64_t window_tail_seq;
        uint8_t  repair_idx;
        bool operator<(const RepairKey& o) const {
            if (window_tail_seq != o.window_tail_seq) {
                return window_tail_seq < o.window_tail_seq;
            }
            return repair_idx < o.repair_idx;
        }
    };

    struct RepairEntry {
        uint8_t* data;              // aligned parity buffer
        size_t   data_size;         // parity_len from wpacket_hdr_repair_t
        uint64_t arrival_time_ms;
    };

    // Internal helpers.
    void advance_max_seq(uint64_t new_max);

    // One decode attempt for window ending at `tail`, parity
    // payload size `parity_len`. Returns newly-recovered seqs
    // (empty if no progress). Idempotent: calling twice with the
    // same (tail, parity_len) does no additional work.
    std::vector<uint64_t> do_decode_once(uint64_t tail, size_t parity_len);

    // Cascade: seed a decode at (tail, parity_len), then for each
    // newly-recovered source seq S, retry decode for any
    // repair-bearing window covering S (tail ∈ [S, S+W-1]).
    // Iterative (worklist) to avoid stack blow-up on long bursts.
    void cascade_decode(uint64_t initial_tail, size_t initial_parity_len);

    bool drain_one(uint64_t* seq_out, uint8_t* out, size_t* sz_out);

    // Configuration.
    const uint16_t W_;
    const uint16_t W_rx_;           // 2 * W
    const uint16_t repairs_per_window_;
    const uint64_t T_flush_ms_;

    fec_t* fec_p_;
    PacketLossListener* loss_listener_;

    std::vector<SourceSlot> ring_;  // sized to W_rx_ at ctor
    std::map<RepairKey, RepairEntry> repair_store_;

    // Stream state.
    uint64_t max_seq_received_;
    uint64_t next_emit_seq_;
    bool     has_any_source_;
    uint64_t last_tick_ms_;

    // Stats (IFecDecoder accessors return these).
    uint32_t count_p_fec_recovered_;
    uint32_t count_w_flush_;

    // Decode scratch (reused across try_decode_window calls to avoid
    // per-call heap alloc). Resized to W_ at ctor.
    std::vector<const gf*>     decode_inpkts_;
    std::vector<gf*>           decode_outpkts_;
    std::vector<unsigned int>  decode_index_;
};

#endif // FEC_SWIN_HPP
