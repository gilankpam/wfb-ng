// src/fec_block.hpp
// Block FEC (WFB_FEC_VDM_RS) implementation of IFecEncoder / IFecDecoder.
// Replaces the inline fec_p / block[] / rx_ring state that used to live
// in Transmitter (src/tx.cpp:686) and Aggregator (src/rx.cpp:895).
// Wire format is byte-identical to pre-Phase-2a; Phase 1.5 baseline
// tests verify this at every commit.

#ifndef FEC_BLOCK_HPP
#define FEC_BLOCK_HPP

#include "fec_iface.hpp"
#include "zfex.h"

#include <cstdint>
#include <cstddef>

// BlockFecEncoder — encoder half of the block-FEC codec.
//
// Wire model: source packets fill fragment_idx 0..k-1 of a block; once
// the k-th source arrives we run a single fec_encode_simd() and produce
// (n - k) parity rows at fragment_idx k..n-1. Transmitter drains all
// parities via next_repair() before starting the next block.
//
// Ownership: one instance per Transmitter, held as unique_ptr. No
// thread-safety; see the §9.3 contract in fec_iface.hpp.
class BlockFecEncoder : public IFecEncoder {
public:
    BlockFecEncoder(int k, int n);
    ~BlockFecEncoder() override;

    void on_source_packet(uint64_t seq,
                          const uint8_t* payload,
                          size_t sz) override;

    bool next_repair(uint8_t* out,
                     size_t* sz_out,
                     uint64_t* nonce_out) override;

    void tick(uint64_t now_ms) override;

private:
    BlockFecEncoder(const BlockFecEncoder&) = delete;
    BlockFecEncoder& operator=(const BlockFecEncoder&) = delete;

    fec_t* fec_p_;
    const int fec_k_;
    const int fec_n_;
    uint8_t** block_;         // fec_n_ SIMD-aligned slots of
                              // ZFEX_ROUND_UP_SIMD(MAX_FEC_PAYLOAD) bytes

    uint64_t cur_block_idx_;  // block_idx of the block being assembled
    uint8_t  frag_accum_;     // 0..fec_k_ source fragments seen so far
    uint8_t  parity_drain_;   // next parity index to emit, 0..(n-k)
    size_t   max_packet_size_;// largest unpadded source size seen so
                              // far in the current block; zfex encode
                              // uses ZFEX_ROUND_UP_SIMD of this
};

#endif // FEC_BLOCK_HPP
