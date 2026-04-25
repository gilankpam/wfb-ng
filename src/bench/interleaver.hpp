// -*- mode: c++; -*-
// Reference block interleaver.
//
// PHASE 0.5 scope: this header is the SHARED SPEC that Phase 1's
// production interleaver in src/interleaver.{hpp,cpp} must match
// bit-for-bit. It is also what `fec_bench --interleave-depth D`
// simulates against in the harness. It does NOT ship in wfb_tx or
// wfb_rx.
//
// --------------------------------------------------------------------
// WHY BLOCK, NOT CONVOLUTIONAL
// --------------------------------------------------------------------
// Plan §3.3 says "triangular convolutional interleaver" but its
// latency math in §4.2 is `(depth - 1) * block_duration`, which only
// balances for a block (matrix) interleaver. A Forney convolutional
// interleaver with the same D gives the same burst-dispersal
// guarantee but (a) ~n/2 larger memory footprint
// (O(D * n^2 / 2) vs O(D * n)) and (b) a delay profile the adaptive
// latency controller in Phase 3 does not model.
//
// We pick the block interleaver. Both fit §4.2's ceilings; block
// uses less memory on the drone SoC and matches the latency math
// the Phase 3 controller will enforce.
//
// --------------------------------------------------------------------
// THE SCHEDULE
// --------------------------------------------------------------------
// Group D consecutive FEC blocks into a "D-frame". Within a D-frame,
// arrange fragments into a D-row by n-column grid:
//
//     row r (= block_idx mod D), column f (= fragment_idx).
//
// Emit in COLUMN-MAJOR order: column 0 top-to-bottom first, then
// column 1, ..., column n-1.
//
// Concrete (D=2, n=4):
//
//     D-frame 0 holds blocks 0 and 1:
//       grid       col 0   col 1   col 2   col 3
//       row 0  : (0,0)   (0,1)   (0,2)   (0,3)
//       row 1  : (1,0)   (1,1)   (1,2)   (1,3)
//
//     Emission order: (0,0) (1,0) (0,1) (1,1) (0,2) (1,2) (0,3) (1,3)
//
//     D-frame 1 holds blocks 2 and 3:
//       Emission: (2,0) (3,0) (2,1) (3,1) (2,2) (3,2) (2,3) (3,3)
//
// A burst of up to D consecutive lost slots hits at most 1 fragment
// per FEC block (that is the whole point). This holds at D-frame
// boundaries too: any D consecutive emit slots always span D
// different (block, fragment) pairs, which map to D different blocks.
//
// --------------------------------------------------------------------
// THE FORMULA
// --------------------------------------------------------------------
// Given block index b and fragment index f, the absolute emit slot
// (counted from the start of the stream) is:
//
//     frame         = b / D
//     row_in_frame  = b mod D
//     slot_in_frame = f * D + row_in_frame
//     slot          = frame * (D * n) + slot_in_frame
//
// For D = 1, this reduces to `slot = b * n + f`, i.e. every fragment
// goes out in (block, fragment)-sequential order. So D = 1 IS
// byte-identical to no interleaver at all — which is exactly what
// the plan requires so that `--interleave-depth 1` stays
// wire-compatible with master.
//
// --------------------------------------------------------------------
// MEMORY OWNERSHIP / POINTER / THREADING NOTES
// --------------------------------------------------------------------
// This class is pure math. It does not allocate, does not free, does
// not take pointers to data buffers, does not touch heap memory, is
// trivially copyable, trivially destructible, trivially thread-safe
// (const methods are re-entrant). Nothing in here needs the review
// attention the plan's §4.5 list flags for the production
// interleaver; those concerns come up in Phase 1 when this schedule
// drives real buffered fragments.

#ifndef FEC_BENCH_INTERLEAVER_HPP
#define FEC_BENCH_INTERLEAVER_HPP

#include <cassert>
#include <cstdint>
#include <utility>

namespace fec_bench {

class BlockInterleaver {
public:
    // n is the FEC codec's total fragments per block (inputs + parity).
    // D is the interleaver depth. D == 1 disables interleaving.
    BlockInterleaver(unsigned n, unsigned D)
        : n_(n), D_(D) {
        assert(n >= 1);
        assert(D >= 1);
    }

    unsigned n() const { return n_; }
    unsigned depth() const { return D_; }

    // Given block index b and fragment index f (with 0 <= f < n),
    // return the absolute emit slot on the wire (counted from 0).
    // Blocks are expected to be fed in increasing b; emit_slot()
    // depends only on (b, f, D, n), so it is safe to call on any
    // (b, f) in any order.
    uint64_t emit_slot(uint64_t b, unsigned f) const {
        assert(f < n_);
        const uint64_t D  = uint64_t(D_);
        const uint64_t N  = uint64_t(n_);
        const uint64_t frame        = b / D;
        const uint64_t row_in_frame = b % D;
        const uint64_t slot_in_frame = uint64_t(f) * D + row_in_frame;
        return frame * (D * N) + slot_in_frame;
    }

    // Inverse of emit_slot: given an absolute emit slot, return the
    // (block_idx, fragment_idx) pair it carries. Used by the schedule
    // test to cross-check round-trip identity, and by the harness
    // channel loop to walk slots in emit order.
    std::pair<uint64_t, unsigned> fragment_at(uint64_t slot) const {
        const uint64_t D  = uint64_t(D_);
        const uint64_t N  = uint64_t(n_);
        const uint64_t frame_slots  = D * N;
        const uint64_t frame         = slot / frame_slots;
        const uint64_t slot_in_frame = slot % frame_slots;
        const unsigned f    = unsigned(slot_in_frame / D);
        const unsigned row  = unsigned(slot_in_frame % D);
        const uint64_t b    = frame * D + row;
        return { b, f };
    }

    // Total emit slots for num_blocks blocks. If num_blocks is not a
    // multiple of D, the last partial D-frame still occupies a full
    // frame of D*n slots on the wire (the unused row slots would be
    // padding in the production TX). Callers that do not want
    // padding should feed a multiple of D blocks; the harness does.
    uint64_t total_slots(uint64_t num_blocks) const {
        const uint64_t D = uint64_t(D_);
        const uint64_t N = uint64_t(n_);
        const uint64_t frames = (num_blocks + D - 1) / D;
        return frames * D * N;
    }

    // Peak TX-side memory footprint of the interleaver matrix, in
    // bytes, assuming full-width fragments of `fragment_bytes`.
    // RX side is symmetric. This is informational; the harness
    // reports it in the CSV for regression tracking.
    uint64_t peak_tx_bytes(uint64_t fragment_bytes) const {
        return uint64_t(D_) * uint64_t(n_) * fragment_bytes;
    }

private:
    unsigned n_;
    unsigned D_;
};

} // namespace fec_bench

#endif // FEC_BENCH_INTERLEAVER_HPP
