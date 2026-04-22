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
#include <deque>
#include <utility>
#include <vector>

// Ring-arithmetic helpers — block-FEC internal. Moved here from rx.hpp
// in A3b because Aggregator no longer manages the ring directly. The
// baseline harness's C10 memory-arithmetic test references RX_RING_SIZE,
// so fec_block.hpp is now the single source of truth.
#define RX_RING_SIZE 40

static inline int modN(int x, int base)
{
    return (base + (x % base)) % base;
}

// Per-block storage in the RX ring. Each slot holds one wire block's
// worth of fragments; a slot is reused once its source fragments have
// been drained through pop_ready. Moved from rx.hpp in A3b.
typedef struct {
    uint64_t block_idx;
    uint8_t** fragments;
    size_t *fragment_map;
    uint8_t fragment_to_send_idx;
    uint8_t has_fragments;
} rx_ring_item_t;


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


// BlockFecDecoder — decoder half of the block-FEC codec.
//
// Wire model: fragments arrive in any order over the 40-slot rx_ring;
// a block decodes either as soon as fragment_to_send_idx reaches
// fec_k_ on the front slot (fast path, no FEC work) or once the block
// has accumulated k fragments anywhere in the ring (slow path, apply
// FEC, then drain). Ring overrides fire when a late block arrives and
// rx_ring is full, flushing partial predecessors.
//
// Ownership: one instance per Aggregator, held as unique_ptr. No
// thread-safety.
//
// The two uint32_t* counter pointers are internal bookkeeping that
// Aggregator uses to mirror block-FEC events into its public
// count_p_fec_recovered / count_p_override members (for the SESSION
// log and stats dump). The factory make_fec_decoder does NOT receive
// these — Aggregator constructs BlockFecDecoder directly via this
// ctor for Phase 2a. When SWIN lands in Phase 2b and the factory
// dispatches between codecs, we will either widen the factory or
// expose equivalent accessors on IFecDecoder.
class BlockFecDecoder : public IFecDecoder {
public:
    BlockFecDecoder(int k, int n,
                    PacketLossListener* loss_listener,
                    uint32_t* count_p_fec_recovered_ptr,
                    uint32_t* count_p_override_ptr);
    ~BlockFecDecoder() override;

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

private:
    BlockFecDecoder(const BlockFecDecoder&) = delete;
    BlockFecDecoder& operator=(const BlockFecDecoder&) = delete;

    void ingest_fragment(uint64_t block_idx, uint8_t fragment_idx,
                         const uint8_t* payload, size_t sz);
    int rx_ring_push();
    int get_block_ring_idx(uint64_t block_idx);
    void apply_fec(int ring_idx);
    void queue_fragment(int ring_idx, int fragment_idx);

    fec_t* fec_p_;
    const int fec_k_;
    const int fec_n_;
    PacketLossListener* loss_listener_;   // not used on the block path;
                                          // Aggregator handles block-
                                          // FEC loss tracking because
                                          // packet_seq uses its own
                                          // flat uint32_t counter.
    uint32_t* count_p_fec_recovered_ptr_; // non-null; Aggregator's
    uint32_t* count_p_override_ptr_;      // counters, bumped on events.

    rx_ring_item_t rx_ring_[RX_RING_SIZE];
    int rx_ring_front_;
    int rx_ring_alloc_;
    uint64_t last_known_block_;

    // Queue of source packets ready for pop_ready to drain. Each
    // entry holds a copy of the fragment's full ZFEX-padded buffer so
    // that rx_ring_push's override path — which both queues partial
    // front-block fragments AND advances rx_ring_front within the
    // same ingest_fragment call — stays correct regardless of which
    // fragment_idx the incoming packet lands on. Heap-allocating per
    // entry costs one memcpy + one alloc per source packet; at typical
    // 1 Kpps / MAX_FEC_PAYLOAD ≈ 4 KB this is well under 1 ms/sec of
    // CPU on any target.
    struct QueuedReady {
        uint64_t seq;
        std::vector<uint8_t> payload; // full fragment buffer,
                                      // size == MAX_FEC_PAYLOAD.
    };
    std::deque<QueuedReady> ready_queue_;
};

#endif // FEC_BLOCK_HPP
