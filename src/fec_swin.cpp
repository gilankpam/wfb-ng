// src/fec_swin.cpp
// See fec_swin.hpp for the interface contract, state machine, and
// wire-format references. Design §5 (wire), §6 (zfex one-row
// extension, used as fec_encode_row_simd below), §7 (window sizing
// and repair scheduling).

#include "fec_swin.hpp"
#include "wifibroadcast.hpp"
// SwinFecDecoder calls loss_listener_->on_packet_loss(...) on
// T_flush force-advance; needs the full PacketLossListener definition
// (fec_iface.hpp only forward-declares it).
#include "rx.hpp"

#include <cassert>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <iterator>
#include <queue>
#include <utility>
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


// ========================================================================
// SwinFecDecoder
// ========================================================================

SwinFecDecoder::SwinFecDecoder(uint16_t W, uint8_t R_num, uint8_t R_den,
                               PacketLossListener* loss_listener,
                               uint64_t T_flush_ms)
    : W_(W),
      W_rx_((uint16_t)(2 * W)),
      repairs_per_window_(ceil_div_u16((uint32_t)R_num * (uint32_t)W,
                                       (uint32_t)R_den)),
      T_flush_ms_(T_flush_ms),
      fec_p_(nullptr),
      loss_listener_(loss_listener),
      ring_(),
      repair_store_(),
      max_seq_received_(0),
      next_emit_seq_(0),
      has_any_source_(false),
      last_tick_ms_(0),
      count_p_fec_recovered_(0),
      count_w_flush_(0),
      decode_inpkts_(W),
      decode_outpkts_(W),
      decode_index_(W)
{
    assert(W >= 1);
    assert(R_num >= 1);
    assert(R_den >= 1);
    assert(repairs_per_window_ <= 128);
    if ((int)W_ + (int)repairs_per_window_ >= 256) {
        throw std::runtime_error(
            "SwinFecDecoder: W + ⌈R·W⌉ exceeds zfex's n < 256 limit");
    }
    assert(T_flush_ms > 0);

    zfex_status_code_t rc = fec_new(W_, W_ + repairs_per_window_, &fec_p_);
    assert(rc == ZFEX_SC_OK);

    // Source ring: W_rx_ slots. Each holds MAX_FEC_PAYLOAD aligned
    // so fec_decode_simd can read/write directly into the slot's
    // data buffer.
    ring_.resize(W_rx_);
    for (uint16_t i = 0; i < W_rx_; i++) {
        int rc2 = posix_memalign((void**)&ring_[i].data,
                                 ZFEX_SIMD_ALIGNMENT,
                                 ZFEX_ROUND_UP_SIMD(MAX_FEC_PAYLOAD));
        assert(rc2 == 0);
        std::memset(ring_[i].data, 0, ZFEX_ROUND_UP_SIMD(MAX_FEC_PAYLOAD));
        ring_[i].seq = UINT64_MAX;
        ring_[i].data_size = 0;
        ring_[i].state = SourceSlot::EMPTY;
        ring_[i].arrival_time_ms = 0;
    }
}

SwinFecDecoder::~SwinFecDecoder() {
    for (auto& slot : ring_) {
        free(slot.data);
        slot.data = nullptr;
    }
    for (auto& kv : repair_store_) {
        free(kv.second.data);
    }
    repair_store_.clear();
    zfex_status_code_t rc = fec_free(fec_p_);
    assert(rc == ZFEX_SC_OK);
}

// When a source arrives at seq new_max > max_seq_received_, fill in
// all intermediate slots with EMPTY placeholders so pop_ready can
// distinguish gaps from never-seen positions. Any slot being
// overwritten that held an unemitted source counts as a flush.
//
// On the first source ever, also initializes the stream: stamps
// from 0 (or max - W_rx + 1 if the jump exceeds ring capacity)
// up through new_max, so a late-arriving seq < new_max still has
// a valid placeholder slot.
void SwinFecDecoder::advance_max_seq(uint64_t new_max) {
    uint64_t start;
    if (has_any_source_) {
        if (new_max <= max_seq_received_) return;
        start = max_seq_received_ + 1;
    } else {
        // First source: stamp from 0 (or capped to W_rx window).
        start = 0;
        has_any_source_ = true;
    }
    if (new_max + 1 >= (uint64_t)W_rx_ &&
        start < new_max - (uint64_t)W_rx_ + 1)
    {
        start = new_max - (uint64_t)W_rx_ + 1;
    }

    for (uint64_t s = start; s <= new_max; s++) {
        SourceSlot& slot = ring_[s % W_rx_];
        // Preserve slots that already hold valid data for this seq
        // (e.g. an early cascade-recovery that beat the source to
        // the ring). A slot with matching seq and a non-EMPTY state
        // carries real source bytes — stamping it would clobber them
        // and cause a double-count when the cascade later re-recovers.
        if (slot.seq == s && slot.state != SourceSlot::EMPTY) {
            continue;
        }
        // Evicting a DIFFERENT seq's unemitted data counts as a flush.
        if (slot.seq != UINT64_MAX
            && slot.seq != s
            && slot.state != SourceSlot::EMITTED
            && slot.state != SourceSlot::EMPTY
            && slot.seq >= next_emit_seq_)
        {
            count_w_flush_ += 1;
        }
        slot.seq = s;
        slot.data_size = 0;
        slot.state = SourceSlot::EMPTY;
        slot.arrival_time_ms = 0;
    }
    max_seq_received_ = new_max;
}

void SwinFecDecoder::on_source_packet(uint64_t seq,
                                      const uint8_t* payload,
                                      size_t sz)
{
    assert(sz <= MAX_FEC_PAYLOAD);
    const uint64_t seq_num = seq & BLOCK_IDX_MASK;
    assert((seq >> 56) == 0);  // is_repair=0, repair_idx=0 invariant

    // First source: anchor the stream. advance_max_seq handles the
    // !has_any_source_ special case.
    if (!has_any_source_) {
        advance_max_seq(seq_num);
    } else if (seq_num > max_seq_received_) {
        advance_max_seq(seq_num);
    } else if (seq_num + W_rx_ <= max_seq_received_) {
        // Too old to fit in the reorder window.
        return;
    }

    SourceSlot& slot = ring_[seq_num % W_rx_];
    // Duplicate source (we already have data for this exact seq) — drop.
    if (slot.seq == seq_num && slot.state != SourceSlot::EMPTY) {
        return;
    }

    const bool filled_gap = (slot.seq == seq_num &&
                             slot.state == SourceSlot::EMPTY);

    slot.seq = seq_num;
    std::memcpy(slot.data, payload, sz);
    std::memset(slot.data + sz, 0, MAX_FEC_PAYLOAD - sz);
    slot.data_size = sz;
    slot.state = SourceSlot::RECEIVED;
    slot.arrival_time_ms = last_tick_ms_;

    // If an out-of-order source filled a prior gap, some previously
    // under-determined decodes may now be solvable. Cascade-retry
    // any repair-bearing windows covering this seq. For the common
    // in-order case (seq_num == max_seq_received_ and slot was newly
    // initialized EMPTY, not a back-fill), skip — nothing to retry.
    if (filled_gap) {
        for (uint64_t ct = seq_num; ct < seq_num + (uint64_t)W_; ct++) {
            auto it = repair_store_.lower_bound({ct, 0});
            if (it != repair_store_.end()
                && it->first.window_tail_seq == ct)
            {
                cascade_decode(ct, it->second.data_size);
            }
        }
    }
}

void SwinFecDecoder::on_repair_packet(uint64_t repair_nonce,
                                      uint64_t window_tail_seq,
                                      uint8_t  repair_idx,
                                      const uint8_t* payload,
                                      size_t sz)
{
    (void)repair_nonce;  // nonce bits are consistency-checkable but
                         // not load-bearing here; B4 will assert
                         // consistency as a sanity check.
    assert(repair_idx < 128);  // 7-bit field
    assert(sz <= MAX_FEC_PAYLOAD);

    const uint64_t tail = window_tail_seq & BLOCK_IDX_MASK;

    // Reject late repairs: if the window already slid out of the
    // reorder window (all its sources are past the retired boundary),
    // can't help. Same bound as source late-drop.
    if (has_any_source_) {
        // Window covers [tail - W + 1, tail]. The window's newest
        // seq is `tail`. If tail is older than our ring's oldest
        // reachable seq, this repair can't help.
        if (tail + W_rx_ <= max_seq_received_) {
            return;
        }
        // If the window's tail is below next_emit_seq we've already
        // passed it by (force-flushed). Drop.
        if (tail < next_emit_seq_) {
            return;
        }
    }

    // Store (or replace) the repair. Dup arrival for same
    // (window_tail, repair_idx) key is rare but can happen with
    // retransmission; last-write-wins.
    RepairKey key{tail, repair_idx};
    auto it = repair_store_.find(key);
    if (it == repair_store_.end()) {
        RepairEntry re;
        int rc = posix_memalign((void**)&re.data,
                                ZFEX_SIMD_ALIGNMENT,
                                ZFEX_ROUND_UP_SIMD(MAX_FEC_PAYLOAD));
        assert(rc == 0);
        re.data_size = sz;
        re.arrival_time_ms = last_tick_ms_;
        std::memcpy(re.data, payload, sz);
        repair_store_[key] = re;
    } else {
        it->second.data_size = sz;
        it->second.arrival_time_ms = last_tick_ms_;
        std::memcpy(it->second.data, payload, sz);
    }

    // Attempt to decode this window and cascade to adjacent windows
    // if this decode recovers any sources (see §7.2 + B3 cascade
    // discussion). The repair payload size (sz) is the parity-bytes
    // length, i.e. max source size across this window at encode
    // time — passed to fec_decode_simd.
    cascade_decode(tail, sz);
}

// One decode attempt for window ending at `tail`. Returns the list
// of seqs newly recovered (empty if not enough inputs, or if every
// position in the window was already known, or if the decode ran
// but no slot flipped EMPTY → RECOVERED).
std::vector<uint64_t>
SwinFecDecoder::do_decode_once(uint64_t tail, size_t parity_len)
{
    std::vector<uint64_t> recovered;

    // Phantom-source guard: can't decode if the window extends into
    // pre-stream territory.
    if (tail + 1 < W_) return recovered;
    const uint64_t first_seq = tail + 1 - W_;

    // Stale-cascade guard: if we've already emitted (or flushed)
    // past this window's tail, any recovery here is useless — the
    // sources would never reach pop_ready anyway — and actively
    // harmful because ring wraparound may have reused some of the
    // slots we'd try to write into. Skip.
    if (has_any_source_ && tail < next_emit_seq_) return recovered;

    // Count known sources in [first_seq, tail].
    int known_sources = 0;
    for (uint16_t i = 0; i < W_; i++) {
        uint64_t s = first_seq + i;
        if (s > max_seq_received_) break;  // future source
        SourceSlot& slot = ring_[s % W_rx_];
        if (slot.seq == s &&
            (slot.state == SourceSlot::RECEIVED ||
             slot.state == SourceSlot::RECOVERED ||
             slot.state == SourceSlot::EMITTED)) {
            known_sources += 1;
        }
    }

    // Count repairs for this window.
    auto begin_it = repair_store_.lower_bound({tail, 0});
    auto end_it = repair_store_.upper_bound({tail, 127});
    int known_repairs = (int)std::distance(begin_it, end_it);

    if (known_sources + known_repairs < W_) return recovered;
    if (known_sources == W_) return recovered;  // nothing missing

    // Ring-rollover guard: ensure every slot in the window either
    // holds seq s or is UNINITIALIZED (seq == UINT64_MAX). If the
    // ring has rolled through this seq and reused the slot for a
    // newer one, aborting the decode is the only safe option —
    // writing a recovered payload into that slot would corrupt the
    // newer seq's data.
    for (uint16_t i = 0; i < W_; i++) {
        uint64_t s = first_seq + i;
        SourceSlot& slot = ring_[s % W_rx_];
        if (slot.seq != s && slot.seq != UINT64_MAX) {
            return recovered;
        }
    }

    // Build the W_-entry inpkts / index / outpkts arrays.
    auto rep_it = begin_it;
    int num_outs = 0;
    for (uint16_t i = 0; i < W_; i++) {
        uint64_t s = first_seq + i;
        SourceSlot& slot = ring_[s % W_rx_];
        bool have_source = (s <= max_seq_received_ &&
                            slot.seq == s &&
                            (slot.state == SourceSlot::RECEIVED ||
                             slot.state == SourceSlot::RECOVERED ||
                             slot.state == SourceSlot::EMITTED));
        if (have_source) {
            decode_inpkts_[i] = (const gf*)slot.data;
            decode_index_[i] = i;
        } else {
            assert(rep_it != end_it);
            decode_inpkts_[i] = (const gf*)rep_it->second.data;
            decode_index_[i] = (unsigned int)W_ + rep_it->first.repair_idx;
            // Slot must be either s-stamped (EMPTY) or uninitialized
            // per the rollover guard above.
            if (slot.seq == UINT64_MAX) {
                slot.seq = s;
                slot.state = SourceSlot::EMPTY;
                slot.data_size = 0;
            }
            decode_outpkts_[num_outs++] = (gf*)slot.data;
            ++rep_it;
        }
    }
    if (num_outs == 0) return recovered;

    zfex_status_code_t rc = fec_decode_simd(
        fec_p_,
        decode_inpkts_.data(),
        decode_outpkts_.data(),
        decode_index_.data(),
        parity_len);
    if (rc != ZFEX_SC_OK) {
        throw std::runtime_error("SwinFecDecoder: fec_decode_simd failed");
    }

    // Mark newly-recovered slots and collect their seqs.
    for (uint16_t i = 0; i < W_; i++) {
        uint64_t s = first_seq + i;
        SourceSlot& slot = ring_[s % W_rx_];
        if (slot.seq == s && slot.state == SourceSlot::EMPTY) {
            slot.state = SourceSlot::RECOVERED;
            slot.data_size = parity_len;
            slot.arrival_time_ms = last_tick_ms_;
            count_p_fec_recovered_ += 1;
            recovered.push_back(s);
        }
    }
    return recovered;
}

// Cascade: seed decode at (tail, parity_len). Every source
// recovered in that decode may unblock adjacent windows —
// specifically, any repair-bearing window whose range contains the
// recovered source. Enqueue those windows and repeat until the
// worklist drains.
//
// Bounded work: worklist entries are (window_tail, parity_len)
// pairs; each window can contribute at most W_ recovered seqs over
// its entire life, and the decoder will only ever visit each
// (tail, parity_len) pair a small number of times before the window
// either fully decodes or is retired. No visited-set needed — a
// second visit of a fully-decoded window is a no-op early-return
// inside do_decode_once.
void SwinFecDecoder::cascade_decode(uint64_t initial_tail,
                                    size_t initial_parity_len)
{
    std::queue<std::pair<uint64_t, size_t>> worklist;
    worklist.push({initial_tail, initial_parity_len});

    while (!worklist.empty()) {
        auto item = worklist.front();
        worklist.pop();
        const uint64_t tail = item.first;
        const size_t parity_len = item.second;

        std::vector<uint64_t> recovered = do_decode_once(tail, parity_len);
        if (recovered.empty()) continue;

        // For each newly-recovered source S, add all repair-bearing
        // windows that include S to the worklist. Window [ct-W+1, ct]
        // contains S iff S ≤ ct ≤ S + W - 1.
        for (uint64_t s : recovered) {
            const uint64_t ct_min = s;
            const uint64_t ct_max = s + (uint64_t)W_ - 1;
            auto lo = repair_store_.lower_bound({ct_min, 0});
            auto hi = repair_store_.upper_bound({ct_max, 127});
            for (auto it = lo; it != hi; ++it) {
                worklist.push({it->first.window_tail_seq,
                               it->second.data_size});
            }
        }
    }
}

// Drain one emittable source. Returns false if next_emit_seq has a
// gap (waiting for recovery or T_flush).
bool SwinFecDecoder::drain_one(uint64_t* seq_out,
                               uint8_t* out,
                               size_t* sz_out)
{
    if (!has_any_source_) return false;
    if (next_emit_seq_ > max_seq_received_) return false;

    SourceSlot& slot = ring_[next_emit_seq_ % W_rx_];
    if (slot.seq != next_emit_seq_) {
        // Slot was overwritten by a newer seq — this position is
        // out of the reorder window entirely. Declare it lost and
        // advance. tick() is the usual trigger for this; here we
        // cover the edge case where the caller calls pop_ready
        // without a preceding tick that would've flushed it.
        count_w_flush_ += 1;
        next_emit_seq_ += 1;
        return drain_one(seq_out, out, sz_out);
    }
    if (slot.state == SourceSlot::EMPTY) {
        return false;  // gap; wait
    }
    if (slot.state == SourceSlot::EMITTED) {
        next_emit_seq_ += 1;
        return drain_one(seq_out, out, sz_out);
    }

    // RECEIVED or RECOVERED → emit.
    *seq_out = next_emit_seq_;  // flat packet_seq per B0 = seq_num
    std::memcpy(out, slot.data, MAX_FEC_PAYLOAD);
    *sz_out = MAX_FEC_PAYLOAD;
    slot.state = SourceSlot::EMITTED;
    next_emit_seq_ += 1;
    return true;
}

bool SwinFecDecoder::pop_ready(uint64_t* seq_out,
                               uint8_t* out,
                               size_t* sz_out)
{
    assert(seq_out != nullptr);
    assert(out != nullptr);
    assert(sz_out != nullptr);
    return drain_one(seq_out, out, sz_out);
}

void SwinFecDecoder::tick(uint64_t now_ms) {
    last_tick_ms_ = now_ms;
    if (!has_any_source_) return;

    // Retire repairs whose window has slid out of the ring (keeps
    // the repair_store_ from growing unbounded). A repair is
    // relevant only while its window overlaps [next_emit_seq_,
    // max_seq_received_]. Once next_emit_seq_ passes the window's
    // tail, the repair can't help any remaining unemitted seq.
    while (!repair_store_.empty()) {
        auto it = repair_store_.begin();
        if (it->first.window_tail_seq >= next_emit_seq_) break;
        free(it->second.data);
        repair_store_.erase(it);
    }

    // Force-advance past T_flushed gaps. Find the oldest slot with
    // RECEIVED or RECOVERED state that's behind max_seq_received_
    // and has age ≥ T_flush_ms. When found, advance next_emit_seq_
    // up to that slot, count_w_flush_ once per flush event.
    //
    // Single-pass scan across the ring for the oldest qualifying
    // slot. Size is bounded by W_rx_ (≤ 256 at W=128), so O(W_rx)
    // per tick.
    while (next_emit_seq_ <= max_seq_received_) {
        SourceSlot& slot = ring_[next_emit_seq_ % W_rx_];
        if (slot.seq != next_emit_seq_ ||
            slot.state == SourceSlot::EMITTED)
        {
            // Slot was overwritten or already emitted; skip.
            next_emit_seq_ += 1;
            continue;
        }
        if (slot.state != SourceSlot::EMPTY) {
            // Front is ready to pop — caller will drain via
            // pop_ready. Don't flush.
            break;
        }
        // Front is a gap. Look ahead for any RECEIVED/RECOVERED
        // slot that's overdue. If such exists, force-advance past
        // this gap.
        bool overdue_behind = false;
        for (uint64_t look = next_emit_seq_ + 1;
             look <= max_seq_received_ && look < next_emit_seq_ + W_rx_;
             look++)
        {
            SourceSlot& ls = ring_[look % W_rx_];
            if (ls.seq == look &&
                (ls.state == SourceSlot::RECEIVED ||
                 ls.state == SourceSlot::RECOVERED) &&
                now_ms >= ls.arrival_time_ms + T_flush_ms_)
            {
                overdue_behind = true;
                break;
            }
        }
        if (!overdue_behind) break;   // no forcing needed yet

        // Force-flush this gap.
        count_w_flush_ += 1;
        // Notify loss listener (on_packet_loss expects flat
        // packet_seq).
        if (loss_listener_ != nullptr) {
            // last_seq should be the seq of the most recent
            // successfully emitted source. If none yet, pass 0.
            uint64_t last = (next_emit_seq_ > 0)
                                ? (next_emit_seq_ - 1)
                                : 0;
            loss_listener_->on_packet_loss(1, last, next_emit_seq_);
        }
        next_emit_seq_ += 1;
    }
}
