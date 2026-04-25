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
#include "../interleaver.hpp"  // Phase 1 production impl at src/interleaver.hpp

using fec_bench::BlockInterleaver;
// The Phase 1 production class is wfb::BlockInterleaver; qualified
// in tests that exercise it so the existing reference-only tests
// above keep their simple unqualified usage.

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

// =====================================================================
// Phase 1 production interleaver tests.
//
// These exercise wfb::BlockInterleaver (src/interleaver.cpp). For
// each (n, D) pair, we:
//   1. Push a known "payload" through the production interleaver,
//      frame by frame. The payload encodes (block, fragment) so the
//      drain order is self-identifying.
//   2. Capture drain order into a vector.
//   3. Ask the reference (fec_bench::BlockInterleaver) for the same
//      schedule via fragment_at().
//   4. Assert byte-for-byte equality.
//
// Any drift between the two implementations fails this test.
// =====================================================================

namespace {
// Encode (block_idx, fragment_idx) into a small payload that can be
// decoded back on emit. 4 bytes: 2-byte BE block, 1-byte fragment,
// 1-byte sentinel 0xEE. Fits a fragment of the minimum reasonable
// size without ambiguity.
std::vector<std::uint8_t> make_payload(std::uint64_t b, unsigned f) {
    return {
        std::uint8_t((b >> 8) & 0xff),
        std::uint8_t(b & 0xff),
        std::uint8_t(f),
        0xee
    };
}

std::pair<std::uint64_t, unsigned> decode_payload(const std::uint8_t* p, std::size_t size) {
    // Caller asserts size; this is internal helper.
    return { (std::uint64_t(p[0]) << 8) | p[1], unsigned(p[2]) };
}
} // namespace

TEST_CASE("Production interleaver emits in reference schedule order",
          "[production][schedule]") {
    const std::pair<unsigned, unsigned> cases[] = {
        {4, 1}, {4, 2}, {4, 3}, {12, 2}, {12, 4}, {12, 8}, {20, 8}, {32, 16},
    };
    const unsigned num_frames = 3;

    for (auto [n, D] : cases) {
        BlockInterleaver       ref(n, D);
        wfb::BlockInterleaver  prod(n, D, /*max_frag_size=*/64);

        std::vector<std::pair<std::uint64_t, unsigned>> emitted;

        for (unsigned frame = 0; frame < num_frames; ++frame) {
            // Fill one frame: push block-by-block, fragment-by-fragment.
            for (unsigned d = 0; d < D; ++d) {
                const std::uint64_t b = std::uint64_t(frame) * D + d;
                for (unsigned f = 0; f < n; ++f) {
                    const auto payload = make_payload(b, f);
                    prod.push(b, f, payload.data(), payload.size());
                }
            }
            INFO("n=" << n << " D=" << D << " frame=" << frame);
            REQUIRE(prod.is_frame_full());

            // Drain into `emitted`, decoding the payload so we know
            // *which* fragment each slot actually carries.
            prod.drain([&](const std::uint8_t* buf, std::size_t size) {
                REQUIRE(size == 4);
                REQUIRE(buf[3] == 0xee);
                emitted.push_back(decode_payload(buf, size));
            });

            // After drain, frame state must be reset.
            REQUIRE_FALSE(prod.is_frame_full());
        }

        // Reference schedule across the same num_frames * D blocks.
        std::vector<std::pair<std::uint64_t, unsigned>> expected;
        const std::uint64_t total_slots = ref.total_slots(num_frames * std::uint64_t(D));
        for (std::uint64_t s = 0; s < total_slots; ++s) {
            expected.push_back(ref.fragment_at(s));
        }

        INFO("n=" << n << " D=" << D);
        REQUIRE(emitted == expected);
    }
}

TEST_CASE("Production interleaver preserves fragment bytes",
          "[production][bytes]") {
    // Push a variety of payload sizes up to max_frag_size, then make
    // sure drain returns the same bytes back. Catches any buffer-
    // overlap or memcpy size bug.
    const unsigned n = 8, D = 2;
    const std::size_t max_frag = 256;
    wfb::BlockInterleaver prod(n, D, max_frag);

    std::vector<std::vector<std::uint8_t>> expected_bufs;
    for (unsigned d = 0; d < D; ++d) {
        const std::uint64_t b = d;
        for (unsigned f = 0; f < n; ++f) {
            // Payload size varies: 1, 2, ..., up to max_frag.
            const std::size_t sz = 1 + (unsigned(d) * n + f) * 13;
            std::vector<std::uint8_t> buf(std::min(sz, max_frag));
            for (std::size_t i = 0; i < buf.size(); ++i) {
                buf[i] = std::uint8_t((b * 13 + f * 7 + i) & 0xff);
            }
            expected_bufs.push_back(buf);
            prod.push(b, f, buf.data(), buf.size());
        }
    }
    REQUIRE(prod.is_frame_full());

    // Drain, indexing each emit by its corresponding expected entry
    // via the production's schedule (which we've already tested above).
    // For this test we use the reference schedule to look up which
    // (b, f) each emit slot carries, then grab the matching expected
    // buffer from expected_bufs.
    BlockInterleaver ref(n, D);
    std::size_t slot = 0;
    prod.drain([&](const std::uint8_t* buf, std::size_t size) {
        auto [b, f] = ref.fragment_at(slot++);
        // expected_bufs is indexed in push order: (d=0,f=0..n-1),
        // (d=1,f=0..n-1). d here = b mod D.
        const unsigned d    = unsigned(b % D);
        const std::size_t ei = std::size_t(d) * n + f;
        INFO("slot=" << (slot - 1) << " b=" << b << " f=" << f);
        REQUIRE(size == expected_bufs[ei].size());
        for (std::size_t i = 0; i < size; ++i) {
            REQUIRE(buf[i] == expected_bufs[ei][i]);
        }
    });
}

TEST_CASE("Production interleaver flush() discards partial frame",
          "[production][flush]") {
    wfb::BlockInterleaver prod(/*n=*/4, /*D=*/2, /*max_frag_size=*/16);

    // Push half a frame's worth of fragments.
    for (unsigned d = 0; d < 2; ++d) {
        for (unsigned f = 0; f < 2; ++f) {  // only 2 of 4 fragments
            const auto p = make_payload(d, f);
            prod.push(d, f, p.data(), p.size());
        }
    }
    REQUIRE_FALSE(prod.is_frame_full());

    prod.flush();

    // After flush, the frame state must be empty and accept a fresh
    // frame starting at any block index.
    const auto p = make_payload(100, 0);
    prod.push(100, 0, p.data(), p.size());  // anchors new frame at b=100/D=50
    REQUIRE_FALSE(prod.is_frame_full());

    // Completing the frame from here must produce a single-frame's
    // worth of emits with the expected schedule anchored at b=100.
    // Fill the rest of frame 50.
    for (unsigned f = 0; f < 4; ++f) {
        if (f == 0) continue;  // already pushed (100, 0)
        const auto pf = make_payload(100, f);
        prod.push(100, f, pf.data(), pf.size());
    }
    for (unsigned f = 0; f < 4; ++f) {
        const auto pf = make_payload(101, f);
        prod.push(101, f, pf.data(), pf.size());
    }
    REQUIRE(prod.is_frame_full());
}

TEST_CASE("Production interleaver D=1 degenerates to per-block sequential",
          "[production][degenerate]") {
    // D=1 is the wire-identical-to-master case. The drain order for
    // a single block must be exactly (b, 0), (b, 1), ..., (b, n-1).
    wfb::BlockInterleaver prod(/*n=*/12, /*D=*/1, /*max_frag_size=*/32);

    const std::uint64_t b = 42;
    for (unsigned f = 0; f < 12; ++f) {
        const auto p = make_payload(b, f);
        prod.push(b, f, p.data(), p.size());
    }
    REQUIRE(prod.is_frame_full());

    unsigned expected_f = 0;
    prod.drain([&](const std::uint8_t* buf, std::size_t size) {
        REQUIRE(size == 4);
        auto [bb, ff] = decode_payload(buf, size);
        REQUIRE(bb == b);
        REQUIRE(ff == expected_f);
        ++expected_f;
    });
    REQUIRE(expected_f == 12);
}

int main(int argc, char* argv[]) {
    return Catch::Session().run(argc, argv);
}
