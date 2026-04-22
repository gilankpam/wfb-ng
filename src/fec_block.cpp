// src/fec_block.cpp
// See fec_block.hpp for the block FEC interface contract. This file
// also hosts the factory functions declared in fec_iface.hpp —
// make_fec_encoder and make_fec_decoder. A3a lands the encoder and a
// make_fec_decoder stub; A3b replaces the stub with BlockFecDecoder.

#include "fec_block.hpp"
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
    // Phase 2a: only block FEC is wired through. SWIN lands in Phase 2b.
    assert(params.fec_type == WFB_FEC_VDM_RS);
    return std::unique_ptr<IFecEncoder>(new BlockFecEncoder(params.k, params.n));
}

std::unique_ptr<IFecDecoder> make_fec_decoder(const fec_params_t& /*params*/,
                                              PacketLossListener* /*loss_listener*/) {
    // A3a stub — A3b replaces this with a real BlockFecDecoder. Keeping
    // a throwing stub here means the linker is happy (fec_iface.hpp
    // declares the symbol and every TU that includes rx.hpp transitively
    // sees it) while any accidental call during A3a is caught loudly.
    throw std::runtime_error("make_fec_decoder: not yet implemented (Phase 2a commit A3b pending)");
}
