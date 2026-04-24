// Schedule pinning test for the reference block interleaver.
//
// This test exists for two reasons:
//
// 1. It pins the Phase 0.5 reference interleaver's emission schedule
//    bit-for-bit in hand-written expected vectors. Any accidental
//    change to BlockInterleaver::emit_slot / fragment_at is caught.
//
// 2. In the Phase 1 PR, the same test will be extended to run the
//    production src/interleaver.cpp against the same expected
//    vectors. Both implementations MUST agree, byte-for-byte. That
//    is the whole point of a "shared spec" interleaver — the plan's
//    §3.8 layer 1.
//
// The expected vectors below are derived by hand from the formula in
// interleaver.hpp. A small case (D=2, n=4) is typed out in full so a
// human reviewer can eyeball it against the ASCII grid in the header
// doc comment. Larger cases check (a) slot round-trips through
// emit_slot → fragment_at → same (b, f), and (b) the D=1 degeneracy
// (no interleaving).

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_session.hpp>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <utility>
#include <vector>

#include "bench/interleaver.hpp"

using fec_bench::BlockInterleaver;

namespace {

// Helpers to make the expected-sequence tables readable.
using Frag = std::pair<uint64_t, unsigned>;  // (block_idx, fragment_idx)

std::vector<Frag> all_slots(const BlockInterleaver& il, uint64_t num_blocks) {
    std::vector<Frag> out;
    const uint64_t total = il.total_slots(num_blocks);
    out.reserve(total);
    for (uint64_t s = 0; s < total; ++s) {
        out.push_back(il.fragment_at(s));
    }
    return out;
}

} // namespace

// =====================================================================
// Small-case expected sequences typed out by hand.
// =====================================================================

TEST_CASE("D=1 is block-sequential (byte-identical to no interleaver)", "[schedule]") {
    // D=1 must reduce to emitting fragment 0 of block 0, fragment 1
    // of block 0, ..., fragment n-1 of block 0, fragment 0 of block 1,
    // ... — i.e. no change from master's wire schedule.
    BlockInterleaver il(4, 1);

    const std::vector<Frag> expected = {
        {0,0}, {0,1}, {0,2}, {0,3},
        {1,0}, {1,1}, {1,2}, {1,3},
        {2,0}, {2,1}, {2,2}, {2,3},
    };
    REQUIRE(all_slots(il, 3) == expected);
}

TEST_CASE("D=2, n=4 matches the ASCII-grid example in interleaver.hpp",
          "[schedule]") {
    // Two D-frames, blocks 0..3. From the header's ASCII diagram:
    //   frame 0: (0,0)(1,0)(0,1)(1,1)(0,2)(1,2)(0,3)(1,3)
    //   frame 1: (2,0)(3,0)(2,1)(3,1)(2,2)(3,2)(2,3)(3,3)
    BlockInterleaver il(4, 2);

    const std::vector<Frag> expected = {
        {0,0}, {1,0}, {0,1}, {1,1}, {0,2}, {1,2}, {0,3}, {1,3},
        {2,0}, {3,0}, {2,1}, {3,1}, {2,2}, {3,2}, {2,3}, {3,3},
    };
    REQUIRE(all_slots(il, 4) == expected);
}

TEST_CASE("D=3, n=4, one complete D-frame", "[schedule]") {
    // Frame 0 holds blocks 0,1,2. Column-major: (0,f)(1,f)(2,f) for
    // each f.
    BlockInterleaver il(4, 3);

    const std::vector<Frag> expected = {
        {0,0}, {1,0}, {2,0},
        {0,1}, {1,1}, {2,1},
        {0,2}, {1,2}, {2,2},
        {0,3}, {1,3}, {2,3},
    };
    REQUIRE(all_slots(il, 3) == expected);
}

// =====================================================================
// Invariants that hold for ALL (D, n) — no hand-typed tables needed.
// =====================================================================

TEST_CASE("emit_slot ↔ fragment_at round-trip is the identity",
          "[schedule][invariant]") {
    const std::pair<unsigned, unsigned> cases[] = {
        {4, 1}, {4, 2}, {4, 3}, {12, 1}, {12, 2}, {12, 4}, {12, 8},
        {20, 1}, {20, 2}, {20, 4}, {20, 8}, {32, 16}, {8, 1}, {8, 4},
    };
    for (auto [n, D] : cases) {
        BlockInterleaver il(n, D);

        // Forward: (b, f) -> slot -> (b, f) must be identity.
        for (uint64_t b = 0; b < 4 * uint64_t(D); ++b) {
            for (unsigned f = 0; f < n; ++f) {
                const uint64_t s = il.emit_slot(b, f);
                const auto [b2, f2] = il.fragment_at(s);
                INFO("n=" << n << " D=" << D << " b=" << b << " f=" << f);
                REQUIRE(b2 == b);
                REQUIRE(f2 == f);
            }
        }
    }
}

TEST_CASE("A full D-frame occupies exactly D*n contiguous slots",
          "[schedule][invariant]") {
    const std::pair<unsigned, unsigned> cases[] = {
        {4, 2}, {12, 4}, {20, 8},
    };
    for (auto [n, D] : cases) {
        BlockInterleaver il(n, D);
        // The last fragment of frame 0 (block D-1, fragment n-1) must
        // sit at slot (D*n - 1). The first fragment of frame 1
        // (block D, fragment 0) must sit at slot (D*n).
        REQUIRE(il.emit_slot(D - 1, n - 1) == uint64_t(D) * uint64_t(n) - 1);
        REQUIRE(il.emit_slot(D,     0    ) == uint64_t(D) * uint64_t(n));
    }
}

TEST_CASE("Burst dispersal: any window of D slots spans D distinct blocks",
          "[schedule][invariant]") {
    // The whole reason this interleaver exists. For every starting
    // slot s, the fragments at slots [s, s+D) must belong to D
    // different blocks. This is what guarantees "burst of ≤D lost
    // slots hits ≤1 fragment per block."
    const std::pair<unsigned, unsigned> cases[] = {
        {4, 2}, {4, 3}, {12, 4}, {20, 8},
    };
    for (auto [n, D] : cases) {
        BlockInterleaver il(n, D);
        const uint64_t total = il.total_slots(3 * uint64_t(D));  // 3 frames
        for (uint64_t s = 0; s + D <= total; ++s) {
            std::vector<uint64_t> blocks;
            blocks.reserve(D);
            for (unsigned i = 0; i < D; ++i) {
                blocks.push_back(il.fragment_at(s + i).first);
            }
            // All D entries must be distinct.
            std::vector<uint64_t> sorted = blocks;
            std::sort(sorted.begin(), sorted.end());
            sorted.erase(std::unique(sorted.begin(), sorted.end()), sorted.end());
            INFO("n=" << n << " D=" << D << " slot=" << s);
            REQUIRE(sorted.size() == D);
        }
    }
}

TEST_CASE("D=1 emit_slot matches the trivial b*n + f formula",
          "[schedule][invariant]") {
    // Master's wire schedule. The Phase 1 production code must
    // reproduce this identically when the --interleave-depth flag is
    // left at its default of 1.
    for (unsigned n : {4u, 8u, 12u, 20u}) {
        BlockInterleaver il(n, 1);
        for (uint64_t b = 0; b < 10; ++b) {
            for (unsigned f = 0; f < n; ++f) {
                REQUIRE(il.emit_slot(b, f) == b * uint64_t(n) + uint64_t(f));
            }
        }
    }
}

int main(int argc, char* argv[]) {
    return Catch::Session().run(argc, argv);
}
