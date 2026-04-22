// src/fec_swin.cpp
// See fec_swin.hpp for the interface contract, state machine, and
// wire-format references. Design §5 (wire), §6 (zfex one-row
// extension, used as fec_encode_row_simd below), §7 (window sizing
// and repair scheduling).

#include "fec_swin.hpp"
#include "wifibroadcast.hpp"

#include <cassert>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <endian.h>
#include <stdexcept>

namespace {

// ceil(num / den) for unsigned integers, den > 0.
inline uint16_t ceil_div_u16(uint32_t num, uint32_t den) {
    return (uint16_t)((num + den - 1) / den);
}

}  // namespace

SwinFecEncoder::SwinFecEncoder(uint16_t W, uint8_t R_num, uint8_t R_den)
    : W_(W),
      R_num_(R_num),
      R_den_(R_den),
      repairs_per_window_(ceil_div_u16((uint32_t)R_num * (uint32_t)W,
                                       (uint32_t)R_den)),
      R_gt_1_(R_num > R_den),
      repair_period_(R_gt_1_ ? 0 : ceil_div_u16(R_den, R_num)),
      repairs_per_source_(R_gt_1_ ? ceil_div_u16(R_num, R_den) : 0),
      fec_p_(nullptr),
      ring_(nullptr),
      parity_scratch_(nullptr),
      input_ptrs_(nullptr),
      window_tail_seq_(0),
      has_any_source_(false),
      max_packet_size_(0),
      repair_due_in_(R_gt_1_ ? 0 : repair_period_),
      pending_repairs_(0),
      next_repair_idx_(0),
      window_tail_for_burst_(0),
      max_pkt_for_burst_(0),
      repair_seq_next_(0)
{
    assert(W >= 1);
    assert(R_num >= 1);
    assert(R_den >= 1);
    // §5.3: 7-bit repair_idx caps repairs-per-window at 128.
    assert(repairs_per_window_ <= 128);
    // zfex internal limit (fec_new asserts n < 256). The §5.3 128
    // cap plus W can still exceed this at W=128 R=1.0; reject at
    // construction with a clear message rather than letting zfex
    // assert opaquely.
    if ((int)W_ + (int)repairs_per_window_ >= 256) {
        throw std::runtime_error(
            "SwinFecEncoder: W + ⌈R·W⌉ exceeds zfex's n < 256 limit "
            "(try a smaller W or R)");
    }

    zfex_status_code_t rc = fec_new(W_, W_ + repairs_per_window_, &fec_p_);
    assert(rc == ZFEX_SC_OK);

    // Ring: W_ aligned slots, zero-initialized so partial-window
    // repairs at stream startup compute against an all-zero phantom
    // tail. Decoder side will do the same and the math is
    // self-consistent.
    ring_ = new uint8_t*[W_];
    for (uint16_t i = 0; i < W_; i++) {
        int rc2 = posix_memalign((void**)&ring_[i],
                                 ZFEX_SIMD_ALIGNMENT,
                                 ZFEX_ROUND_UP_SIMD(MAX_FEC_PAYLOAD));
        assert(rc2 == 0);
        std::memset(ring_[i], 0, ZFEX_ROUND_UP_SIMD(MAX_FEC_PAYLOAD));
    }

    // Parity scratch for the aligned output of fec_encode_row_simd.
    int rc2 = posix_memalign((void**)&parity_scratch_,
                             ZFEX_SIMD_ALIGNMENT,
                             ZFEX_ROUND_UP_SIMD(MAX_FEC_PAYLOAD));
    assert(rc2 == 0);

    // Pointer scratch for fec_encode_row_simd's inpkts argument.
    input_ptrs_ = new const uint8_t*[W_];
}

SwinFecEncoder::~SwinFecEncoder() {
    for (uint16_t i = 0; i < W_; i++) {
        free(ring_[i]);
    }
    delete[] ring_;
    free(parity_scratch_);
    delete[] input_ptrs_;
    zfex_status_code_t rc = fec_free(fec_p_);
    assert(rc == ZFEX_SC_OK);
}

void SwinFecEncoder::on_source_packet(uint64_t seq,
                                      const uint8_t* payload,
                                      size_t sz)
{
    // Per §5.2, source's seq is 56-bit seq_num in the low bits; the
    // is_repair bit is 0 and repair_idx bits are 0.
    const uint64_t seq_num = seq & BLOCK_IDX_MASK;
    assert((seq >> 56) == 0);  // is_repair=0, repair_idx=0 invariant
    assert(sz <= MAX_FEC_PAYLOAD);

    // Copy the framed source into its ring slot. Callers pass
    // pre-framed bytes (wpacket_hdr_t + user data + zero pad); we
    // hold it verbatim so that if the decoder recovers this source
    // later via FEC, the recovered bytes include the caller's
    // wpacket_hdr_t unchanged.
    uint8_t* slot = ring_[seq_num % W_];
    std::memcpy(slot, payload, sz);
    std::memset(slot + sz, 0, MAX_FEC_PAYLOAD - sz);

    window_tail_seq_ = seq_num;
    has_any_source_ = true;
    max_packet_size_ = std::max(max_packet_size_, sz);

    // Scheduling (§7.3).
    if (R_gt_1_) {
        // R > 1: every source triggers ⌈R⌉ repairs with repair_idx
        // 0..⌈R⌉-1. Each source's window is distinct; previous
        // source's burst must already be drained before we schedule
        // a new one — that's the Transmitter's "drain until false"
        // contract. Assert it.
        assert(pending_repairs_ == 0);
        pending_repairs_ = repairs_per_source_;
        next_repair_idx_ = 0;
        window_tail_for_burst_ = seq_num;
        max_pkt_for_burst_ = max_packet_size_;
        max_packet_size_ = 0;  // next source starts a fresh window
                               // (§7.3 R>1: "the next source's
                               // repairs cover a new window")
    } else {
        // R ≤ 1: countdown. On hit-0, schedule one repair with
        // repair_idx=0 covering the current window (§5.3: for R≤1,
        // only repair_idx=0 is emitted per window).
        assert(pending_repairs_ == 0);  // drain contract
        assert(repair_due_in_ > 0);
        repair_due_in_ -= 1;
        if (repair_due_in_ == 0) {
            pending_repairs_ = 1;
            next_repair_idx_ = 0;
            window_tail_for_burst_ = seq_num;
            max_pkt_for_burst_ = max_packet_size_;
            repair_due_in_ = repair_period_;
            // max_packet_size_ carries over to the next window
            // because R ≤ 1 windows overlap (each window still
            // covers W sources ending at its own tail, so the "max"
            // is a property of the source stream, not reset between
            // repairs). We reset it only when a source reaches
            // max capacity in isolation; simpler to keep
            // monotone-over-stream. If this becomes a padding
            // amplification issue (see §12.1), the fix is a rolling
            // max over the W-source window, tracked here.
            // Phase 2b-lite: carry over.
        }
    }
}

bool SwinFecEncoder::next_repair(uint8_t* out,
                                 size_t* sz_out,
                                 uint64_t* nonce_out)
{
    if (pending_repairs_ == 0) return false;

    assert(out != nullptr);
    assert(sz_out != nullptr);
    assert(nonce_out != nullptr);
    assert(has_any_source_);  // ought to be impossible to schedule a
                              // repair without having seen a source

    const uint8_t repair_idx = next_repair_idx_;
    const uint64_t tail = window_tail_for_burst_;
    const size_t max_pkt = max_pkt_for_burst_;

    // Build the W input pointers in seq order. For window
    // [tail - W + 1, tail], input[i] corresponds to seq
    // (tail - W + 1 + i), which lives in ring[(tail - W + 1 + i) % W].
    // With modular arithmetic, (tail - W + 1 + i) % W == (tail + 1 + i) % W.
    for (uint16_t i = 0; i < W_; i++) {
        input_ptrs_[i] = ring_[((size_t)tail + 1 + i) % W_];
    }

    // Compute one parity row via the B1 zfex extension.
    // fecnum = W_ (zfex's k) + repair_idx.
    const unsigned int fecnum = (unsigned int)W_ + (unsigned int)repair_idx;
    const size_t parity_len = (max_pkt > 0) ? max_pkt : 1;
    zfex_status_code_t rc = fec_encode_row_simd(
        fec_p_,
        (const gf* const*)input_ptrs_,
        (gf*)parity_scratch_,
        parity_len,
        fecnum);
    if (rc != ZFEX_SC_OK) {
        throw std::runtime_error("SwinFecEncoder: fec_encode_row_simd failed");
    }

    // Compose the repair wire payload: wpacket_hdr_repair_t
    // (11 bytes) + parity bytes.
    wpacket_hdr_repair_t* hdr = (wpacket_hdr_repair_t*)out;
    hdr->flags = WFB_PACKET_REPAIR_SWIN;
    hdr->payload_size = htobe16((uint16_t)parity_len);
    hdr->window_tail_seq = htobe64(tail);
    std::memcpy(out + sizeof(wpacket_hdr_repair_t),
                parity_scratch_,
                parity_len);

    *sz_out = sizeof(wpacket_hdr_repair_t) + parity_len;

    // §5.2 repair nonce: is_repair=1 | repair_idx(7 bits) | seq_num(56).
    const uint64_t r_seq = repair_seq_next_ & BLOCK_IDX_MASK;
    *nonce_out = (1ULL << 63)
               | ((uint64_t)(repair_idx & 0x7f) << 56)
               | r_seq;

    // Advance state.
    repair_seq_next_ = (repair_seq_next_ + 1) & BLOCK_IDX_MASK;
    next_repair_idx_ += 1;
    pending_repairs_ -= 1;

    return true;
}

void SwinFecEncoder::tick(uint64_t /*now_ms*/) {
    // Encoder has no wall-clock state in Phase 2b. T_flush is a
    // decoder concept (§7.4); per-source pacing on the TX side is
    // handled by Transmitter itself (same as block FEC's fec_delay
    // loop). A future optional phase could take over pacing here.
}
