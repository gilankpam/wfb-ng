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

// Inner-header layout for SWIN repair packets (§5.4). Lives inside
// the AEAD-encrypted payload. Fields are big-endian on the wire;
// callers / readers must byteswap explicitly.
typedef struct __attribute__((packed)) {
    uint8_t  flags;             // WFB_PACKET_REPAIR_SWIN
    uint16_t payload_size;      // big-endian, parity-payload size in bytes
                                // (= max_packet_size across the covered window)
    uint64_t window_tail_seq;   // big-endian, seq_num of last source
                                // covered by this repair
} wpacket_hdr_repair_t;


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

#endif // FEC_SWIN_HPP
