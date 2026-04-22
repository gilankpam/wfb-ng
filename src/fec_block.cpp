// src/fec_block.cpp
// See fec_block.hpp for the block FEC interface contract. This file
// also hosts the factory functions declared in fec_iface.hpp —
// make_fec_encoder and make_fec_decoder. A3a lands the encoder and a
// make_fec_decoder stub; A3b replaces the stub with BlockFecDecoder.

#include "fec_block.hpp"
#include "fec_swin.hpp"
#include "wifibroadcast.hpp"

#include <cassert>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <stdexcept>

BlockFecEncoder::BlockFecEncoder(int k, int n)
    : fec_p_(nullptr),
      fec_k_(k),
      fec_n_(n),
      block_(nullptr),
      cur_block_idx_(0),
      frag_accum_(0),
      parity_drain_(0),
      max_packet_size_(0)
{
    assert(k >= 1);
    assert(n >= 1);
    assert(n < 256);
    assert(k <= n);

    zfex_status_code_t rc = fec_new(fec_k_, fec_n_, &fec_p_);
    assert(rc == ZFEX_SC_OK);

    block_ = new uint8_t*[fec_n_];
    for (int i = 0; i < fec_n_; i++) {
        int rc2 = posix_memalign((void**)&block_[i],
                                 ZFEX_SIMD_ALIGNMENT,
                                 ZFEX_ROUND_UP_SIMD(MAX_FEC_PAYLOAD));
        assert(rc2 == 0);
    }
}

BlockFecEncoder::~BlockFecEncoder() {
    for (int i = 0; i < fec_n_; i++) {
        free(block_[i]);
    }
    delete[] block_;

    zfex_status_code_t rc = fec_free(fec_p_);
    assert(rc == ZFEX_SC_OK);
}

void BlockFecEncoder::on_source_packet(uint64_t seq,
                                       const uint8_t* payload,
                                       size_t sz)
{
    // seq carries the wire data_nonce layout for block FEC:
    //   bits 55..8  : block_idx
    //   bits  7..0  : fragment_idx
    // (See fec_iface.hpp §9.3 D2 for why we reuse the wire layout.)
    const uint64_t block_idx = (seq >> 8) & BLOCK_IDX_MASK;
    const uint8_t  frag_idx  = (uint8_t)(seq & 0xff);

    assert(frag_idx < fec_k_);
    assert(sz <= MAX_FEC_PAYLOAD);
    assert(frag_accum_ < fec_k_);  // must drain repairs before new block

    if (frag_accum_ == 0) {
        // Starting a new block. The first source's block_idx defines it.
        cur_block_idx_ = block_idx;
        max_packet_size_ = 0;
    }
    assert(block_idx == cur_block_idx_);
    assert(frag_idx == frag_accum_);

    // Copy payload into the next slot, zero-padding the tail to
    // MAX_FEC_PAYLOAD so fec_encode_simd reads a uniform buffer. The
    // caller has already written the inner wpacket_hdr_t into the
    // first 3 bytes of payload.
    std::memcpy(block_[frag_accum_], payload, sz);
    std::memset(block_[frag_accum_] + sz, 0, MAX_FEC_PAYLOAD - sz);

    max_packet_size_ = std::max(max_packet_size_, sz);
    frag_accum_ += 1;

    if (frag_accum_ == fec_k_) {
        // Block complete: compute all n-k parity rows in one call and
        // let next_repair drain them one at a time.
        zfex_status_code_t rc = fec_encode_simd(
            fec_p_,
            (const uint8_t**)block_,
            block_ + fec_k_,
            ZFEX_ROUND_UP_SIMD(max_packet_size_));
        if (rc != ZFEX_SC_OK) {
            throw std::runtime_error("BlockFecEncoder: fec_encode_simd failed");
        }
        parity_drain_ = 0;
    }
}

bool BlockFecEncoder::next_repair(uint8_t* out,
                                  size_t* sz_out,
                                  uint64_t* nonce_out)
{
    // Only drain once a block is complete.
    if (frag_accum_ < fec_k_) return false;
    if (parity_drain_ >= fec_n_ - fec_k_) return false;

    assert(out != nullptr);
    assert(sz_out != nullptr);
    assert(nonce_out != nullptr);

    const int frag_idx = fec_k_ + parity_drain_;
    std::memcpy(out, block_[frag_idx], ZFEX_ROUND_UP_SIMD(max_packet_size_));
    *sz_out = max_packet_size_;
    *nonce_out = ((cur_block_idx_ & BLOCK_IDX_MASK) << 8) | (uint8_t)frag_idx;

    parity_drain_ += 1;

    if (parity_drain_ == fec_n_ - fec_k_) {
        // Last parity of this block handed out. Advance to the next
        // block; the caller (Transmitter) will do the same to its own
        // wire-level block_idx. See tx.cpp send_packet.
        cur_block_idx_ = (cur_block_idx_ + 1) & BLOCK_IDX_MASK;
        frag_accum_ = 0;
        parity_drain_ = 0;
        max_packet_size_ = 0;
    }

    return true;
}

void BlockFecEncoder::tick(uint64_t /*now_ms*/) {
    // Block FEC has no wall-clock state; fec_delay pacing is handled by
    // Transmitter around the next_repair drain loop, not inside the
    // codec.
}

// ----- Factories (from fec_iface.hpp) ------------------------------------

std::unique_ptr<IFecEncoder> make_fec_encoder(const fec_params_t& params) {
    switch (params.fec_type) {
        case WFB_FEC_VDM_RS:
            return std::unique_ptr<IFecEncoder>(
                new BlockFecEncoder(params.k, params.n));
        case WFB_FEC_SWIN_RS:
            // B2: SwinFecEncoder lands here. SwinFecDecoder is B3.
            return std::unique_ptr<IFecEncoder>(
                new SwinFecEncoder(params.swin_w,
                                   params.swin_r_num,
                                   params.swin_r_den));
        default:
            throw std::runtime_error(
                "make_fec_encoder: unknown fec_type");
    }
}

std::unique_ptr<IFecDecoder> make_fec_decoder(const fec_params_t& params,
                                              PacketLossListener* loss_listener) {
    switch (params.fec_type) {
        case WFB_FEC_VDM_RS:
            return std::unique_ptr<IFecDecoder>(
                new BlockFecDecoder(params.k, params.n, loss_listener));
        case WFB_FEC_SWIN_RS:
            // Phase 2b commit B3 lands SwinFecDecoder and replaces this
            // branch.
            throw std::runtime_error(
                "make_fec_decoder: SWIN decoder not yet implemented "
                "(Phase 2b commit B3 pending)");
        default:
            throw std::runtime_error(
                "make_fec_decoder: unknown fec_type");
    }
}


// ========================================================================
// BlockFecDecoder
// ========================================================================

BlockFecDecoder::BlockFecDecoder(int k, int n,
                                 PacketLossListener* loss_listener)
    : fec_p_(nullptr),
      fec_k_(k),
      fec_n_(n),
      loss_listener_(loss_listener),
      count_p_fec_recovered_(0),
      count_p_override_(0),
      rx_ring_{},
      rx_ring_front_(0),
      rx_ring_alloc_(0),
      last_known_block_((uint64_t)-1),
      ready_queue_()
{
    assert(k >= 1);
    assert(n >= 1);
    assert(n < 256);
    assert(k <= n);

    zfex_status_code_t rc = fec_new(fec_k_, fec_n_, &fec_p_);
    assert(rc == ZFEX_SC_OK);

    // Same rx_ring layout as the pre-A3b Aggregator::init_fec at
    // rx.cpp:326. Each slot holds fec_n_ SIMD-aligned fragment buffers
    // and a size-map; all are allocated once and reused as slots cycle
    // through the ring.
    for (int ring_idx = 0; ring_idx < RX_RING_SIZE; ring_idx++) {
        rx_ring_[ring_idx].block_idx = 0;
        rx_ring_[ring_idx].fragment_to_send_idx = 0;
        rx_ring_[ring_idx].has_fragments = 0;
        rx_ring_[ring_idx].fragments = new uint8_t*[fec_n_];
        for (int i = 0; i < fec_n_; i++) {
            int rc2 = posix_memalign((void**)&rx_ring_[ring_idx].fragments[i],
                                     ZFEX_SIMD_ALIGNMENT,
                                     ZFEX_ROUND_UP_SIMD(MAX_FEC_PAYLOAD));
            assert(rc2 == 0);
        }
        rx_ring_[ring_idx].fragment_map = new size_t[fec_n_];
        std::memset(rx_ring_[ring_idx].fragment_map, 0, fec_n_ * sizeof(size_t));
    }
}

BlockFecDecoder::~BlockFecDecoder() {
    for (int ring_idx = 0; ring_idx < RX_RING_SIZE; ring_idx++) {
        if (rx_ring_[ring_idx].fragments != nullptr) {
            for (int i = 0; i < fec_n_; i++) {
                free(rx_ring_[ring_idx].fragments[i]);
            }
            delete[] rx_ring_[ring_idx].fragments;
        }
        delete[] rx_ring_[ring_idx].fragment_map;
    }
    zfex_status_code_t rc = fec_free(fec_p_);
    assert(rc == ZFEX_SC_OK);
}

void BlockFecDecoder::on_source_packet(uint64_t seq,
                                       const uint8_t* payload,
                                       size_t sz)
{
    // seq uses the block-FEC wire layout: (block_idx << 8) | fragment_idx.
    const uint64_t block_idx  = (seq >> 8) & BLOCK_IDX_MASK;
    const uint8_t  fragment_idx = (uint8_t)(seq & 0xff);
    assert(fragment_idx < fec_k_);
    ingest_fragment(block_idx, fragment_idx, payload, sz);
}

void BlockFecDecoder::on_repair_packet(uint64_t repair_nonce,
                                       uint64_t window_tail_seq,
                                       uint8_t  repair_idx,
                                       const uint8_t* payload,
                                       size_t sz)
{
    // Block routing: repair_nonce is the wire data_nonce, whose low
    // byte carries fragment_idx and whose next 56 bits are block_idx.
    // repair_idx and window_tail_seq are provided for interface
    // symmetry with SWIN; on the block path we validate them against
    // the nonce and discard.
    const uint64_t block_idx  = (repair_nonce >> 8) & BLOCK_IDX_MASK;
    const uint8_t  fragment_idx = (uint8_t)(repair_nonce & 0xff);
    assert(fragment_idx >= fec_k_);
    assert(fragment_idx == (uint8_t)(fec_k_ + repair_idx));
    assert(window_tail_seq == ((block_idx << 8) | (uint8_t)(fec_k_ - 1)));
    (void)window_tail_seq;
    (void)repair_idx;
    ingest_fragment(block_idx, fragment_idx, payload, sz);
}

bool BlockFecDecoder::pop_ready(uint64_t* seq_out,
                                uint8_t* out,
                                size_t* sz_out)
{
    if (ready_queue_.empty()) return false;
    assert(seq_out != nullptr);
    assert(out != nullptr);
    assert(sz_out != nullptr);

    const QueuedReady& q = ready_queue_.front();
    *seq_out = q.seq;
    assert(q.payload.size() == MAX_FEC_PAYLOAD);
    std::memcpy(out, q.payload.data(), q.payload.size());
    *sz_out = q.payload.size();
    ready_queue_.pop_front();
    return true;
}

void BlockFecDecoder::tick(uint64_t /*now_ms*/) {
    // Block FEC has no wall-clock state.
}

// ------ Internals ---------------------------------------------------------

void BlockFecDecoder::queue_fragment(int ring_idx, int fragment_idx) {
    rx_ring_item_t& p = rx_ring_[ring_idx];
    assert(p.fragments != nullptr);
    // Copy the full ZFEX-padded fragment buffer (MAX_FEC_PAYLOAD
    // bytes) into a queue entry. The caller unwraps wpacket_hdr_t.
    QueuedReady q;
    // B0: seq is now the flat packet_seq for loss-listener tracking
    // (block_idx * fec_k_ + fragment_idx), not the data_nonce view.
    q.seq = p.block_idx * (uint64_t)fec_k_ + (uint64_t)fragment_idx;
    q.payload.assign(p.fragments[fragment_idx],
                     p.fragments[fragment_idx] + MAX_FEC_PAYLOAD);
    ready_queue_.push_back(std::move(q));
}

int BlockFecDecoder::rx_ring_push() {
    // See Aggregator::rx_ring_push pre-A3b (rx.cpp:425-460). Semantics
    // are unchanged; the only difference is that the override-flush
    // call now goes through queue_fragment instead of emitting on
    // socket directly. Because queue_fragment copies bytes out of the
    // ring slot before returning, the caller may safely overwrite the
    // slot later in the same ingest_fragment call.
    if (rx_ring_alloc_ < RX_RING_SIZE) {
        int idx = modN(rx_ring_front_ + rx_ring_alloc_, RX_RING_SIZE);
        rx_ring_alloc_ += 1;
        return idx;
    }

    // Ring is full. Override the front block: flush any received
    // fragments to the ready queue, then advance rx_ring_front_ and
    // hand that slot back to the caller.
    WFB_DBG("AGG: Override block 0x%" PRIx64 " flush %d fragments\n",
            rx_ring_[rx_ring_front_].block_idx,
            rx_ring_[rx_ring_front_].has_fragments);
    count_p_override_ += 1;

    for (int f_idx = rx_ring_[rx_ring_front_].fragment_to_send_idx;
         f_idx < fec_k_; f_idx++) {
        if (rx_ring_[rx_ring_front_].fragment_map[f_idx]) {
            queue_fragment(rx_ring_front_, f_idx);
        }
    }

    int ring_idx = rx_ring_front_;
    rx_ring_front_ = modN(rx_ring_front_ + 1, RX_RING_SIZE);
    return ring_idx;
}

int BlockFecDecoder::get_block_ring_idx(uint64_t block_idx) {
    // Is this block already in the ring?
    for (int i = rx_ring_front_, c = rx_ring_alloc_; c > 0;
         i = modN(i + 1, RX_RING_SIZE), c--) {
        if (rx_ring_[i].block_idx == block_idx) return i;
    }

    // Already-processed / out-of-order past — skip. Matches the
    // pre-A3b behavior at rx.cpp:470.
    if (last_known_block_ != (uint64_t)-1 && block_idx <= last_known_block_) {
        return -1;
    }

    int new_blocks = (int)std::min(
        last_known_block_ != (uint64_t)-1 ? block_idx - last_known_block_ : (uint64_t)1,
        (uint64_t)RX_RING_SIZE);
    last_known_block_ = block_idx;

    int ring_idx = -1;
    for (int i = 0; i < new_blocks; i++) {
        ring_idx = rx_ring_push();
        rx_ring_[ring_idx].block_idx = block_idx + i + 1 - new_blocks;
        rx_ring_[ring_idx].fragment_to_send_idx = 0;
        rx_ring_[ring_idx].has_fragments = 0;
        std::memset(rx_ring_[ring_idx].fragment_map, 0, fec_n_ * sizeof(size_t));
    }
    return ring_idx;
}

void BlockFecDecoder::apply_fec(int ring_idx) {
    // Straight port from Aggregator::apply_fec pre-A3b (rx.cpp:907).
    assert(fec_p_ != nullptr);

    unsigned index[fec_k_];
    uint8_t* in_blocks[fec_k_];
    uint8_t* out_blocks[fec_n_ - fec_k_];
    int j = fec_k_;
    int ob_idx = 0;
    size_t max_packet_size = 0;

    rx_ring_item_t& p = rx_ring_[ring_idx];

    for (int i = 0; i < fec_k_; i++) {
        if (p.fragment_map[i]) {
            in_blocks[i] = p.fragments[i];
            index[i] = i;
        } else {
            while (j < fec_n_ && !p.fragment_map[j]) j++;
            assert(j < fec_n_);
            max_packet_size = std::max(max_packet_size, p.fragment_map[j]);
            in_blocks[i] = p.fragments[j];
            out_blocks[ob_idx++] = p.fragments[i];
            index[i] = j++;
        }
    }

    assert(max_packet_size > 0);
    assert(max_packet_size <= MAX_FEC_PAYLOAD);

    zfex_status_code_t rc = fec_decode_simd(fec_p_, (const uint8_t**)in_blocks,
                                            out_blocks, index,
                                            ZFEX_ROUND_UP_SIMD(max_packet_size));
    if (rc != ZFEX_SC_OK) {
        throw std::runtime_error("BlockFecDecoder: fec_decode_simd failed");
    }
}

void BlockFecDecoder::ingest_fragment(uint64_t block_idx, uint8_t fragment_idx,
                                      const uint8_t* payload, size_t sz)
{
    // Logic mirrors Aggregator::process_packet at rx.cpp:747-868 with
    // every inline send_packet replaced by queue_fragment. Aggregator
    // drains the queue via pop_ready before the next on_*_packet call.
    assert(fragment_idx < fec_n_);
    assert(sz <= MAX_FEC_PAYLOAD);

    int ring_idx = get_block_ring_idx(block_idx);
    if (ring_idx < 0) return;

    rx_ring_item_t& p = rx_ring_[ring_idx];
    if (p.fragment_map[fragment_idx]) return;  // duplicate fragment

    std::memset(p.fragments[fragment_idx], 0, MAX_FEC_PAYLOAD);
    std::memcpy(p.fragments[fragment_idx], payload, sz);
    p.fragment_map[fragment_idx] = sz;
    p.has_fragments += 1;

    // Fast path: drain contiguous received fragments from the front.
    if (ring_idx == rx_ring_front_) {
        while (p.fragment_to_send_idx < fec_k_ &&
               p.fragment_map[p.fragment_to_send_idx]) {
            queue_fragment(ring_idx, p.fragment_to_send_idx);
            p.fragment_to_send_idx += 1;
        }
        if (p.fragment_to_send_idx == fec_k_) {
            rx_ring_front_ = modN(rx_ring_front_ + 1, RX_RING_SIZE);
            rx_ring_alloc_ -= 1;
            assert(rx_ring_alloc_ >= 0);
            return;
        }
    }

    // Slow path: this block has k fragments (with gaps) — recoverable.
    if (p.fragment_to_send_idx < fec_k_ && p.has_fragments == fec_k_) {
        // Flush stalled predecessors first.
        int nrm = modN(ring_idx - rx_ring_front_, RX_RING_SIZE);
        while (nrm > 0) {
            for (int f_idx = rx_ring_[rx_ring_front_].fragment_to_send_idx;
                 f_idx < fec_k_; f_idx++) {
                if (rx_ring_[rx_ring_front_].fragment_map[f_idx]) {
                    queue_fragment(rx_ring_front_, f_idx);
                }
            }
            rx_ring_front_ = modN(rx_ring_front_ + 1, RX_RING_SIZE);
            rx_ring_alloc_ -= 1;
            nrm -= 1;
        }
        assert(rx_ring_alloc_ > 0);
        assert(ring_idx == rx_ring_front_);

        // Apply FEC if any source fragment is still missing.
        for (int f_idx = p.fragment_to_send_idx; f_idx < fec_k_; f_idx++) {
            if (!p.fragment_map[f_idx]) {
                uint32_t fec_count = 0;
                apply_fec(ring_idx);
                for (; f_idx < fec_k_; f_idx++) {
                    if (!p.fragment_map[f_idx]) fec_count += 1;
                }
                if (fec_count) {
                    count_p_fec_recovered_ += fec_count;
                    WFB_DBG("FEC recovered %u packets\n", fec_count);
                }
                break;
            }
        }

        while (p.fragment_to_send_idx < fec_k_) {
            queue_fragment(ring_idx, p.fragment_to_send_idx);
            p.fragment_to_send_idx += 1;
        }

        rx_ring_front_ = modN(rx_ring_front_ + 1, RX_RING_SIZE);
        rx_ring_alloc_ -= 1;
        assert(rx_ring_alloc_ >= 0);
    }
}
