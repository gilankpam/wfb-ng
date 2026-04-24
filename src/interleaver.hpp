// -*- mode: c++; -*-
// Phase 1 TX-side block interleaver (production).
//
// This header declares `wfb::BlockInterleaver`, a single class that
// buffers D consecutive FEC blocks on the TX side and emits their
// n·D fragments in the schedule pinned by the Phase 0.5 reference at
// src/bench/interleaver.hpp. The schedule is:
//
//     frame          = block_idx / D
//     row_in_frame   = block_idx mod D
//     slot_in_frame  = fragment_idx * D + row_in_frame
//     absolute_slot  = frame * (D * n) + slot_in_frame
//
// For D == 1 the schedule degenerates to `slot = b*n + f` — byte-
// identical to master. Step C will only route fragments through this
// class when depth > 1, so D == 1 preserves existing behavior.
//
// See plan §4.5 for the C-level concerns that inform the shape of
// this class: alignment (item 1), packed-struct casts (item 2),
// endianness (item 3), pointer arrays (item 4), ownership across
// the interleaver (item 5 — the direct reason this class exists).
//
// --------------------------------------------------------------------
// MEMORY OWNERSHIP
// --------------------------------------------------------------------
// The interleaver OWNS all D*n fragment buffers. On construction it
// allocates one aligned heap buffer per slot, sized
// ZFEX_ROUND_UP_SIMD(max_frag_size). Aligned to ZFEX_SIMD_ALIGNMENT
// so ARM strict-alignment targets don't trap on memcpy/SIMD.
// push(b, f, buf, size) memcpy's the caller's bytes into the owned
// slot; the caller's buffer is free to be reused immediately after
// push returns.
// drain(fn) passes INTERLEAVER-OWNED pointers to `fn`. Those pointers
// are valid for the duration of that callback only; after drain
// returns, the frame state is reset and the buffers may be
// overwritten by the next frame's pushes.
// The destructor frees all D*n buffers.
//
// --------------------------------------------------------------------
// THREADING
// --------------------------------------------------------------------
// Not thread-safe. Matches master's single-threaded poll() loop.
// Callers in tx.cpp use it from one thread only.
//
// --------------------------------------------------------------------
// LIFECYCLE
// --------------------------------------------------------------------
// Typical use, one frame per cycle:
//
//     interleaver.push(b,   0, buf, sz);   // fragment (b,   0)
//     interleaver.push(b,   1, buf, sz);   //        ...
//     ...
//     interleaver.push(b+D-1, n-1, ...);   // last fragment of frame
//     assert(interleaver.is_frame_full());
//     interleaver.drain([&](const uint8_t* p, size_t s){
//         // caller's transmit-it-now code (sendmsg, pcap_inject, etc.)
//     });
//     // interleaver is now ready for the next frame.
//
// On a depth/fec change (plan v2.1 R1 option 1C refresh), caller
// invokes flush() to drop any partial frame before reconfiguring.

#ifndef WFB_INTERLEAVER_HPP
#define WFB_INTERLEAVER_HPP

#include <cstddef>
#include <cstdint>
#include <functional>

namespace wfb {

class BlockInterleaver {
public:
    // n: the FEC codec's total fragments per block (must match
    //    Transmitter::fec_n at construction time).
    // D: interleaver depth (1..255; 1 means "pass-through", but the
    //    caller is expected to bypass the interleaver entirely at
    //    D == 1 for byte-identical-to-master behaviour).
    // max_frag_size: the largest fragment the caller will ever push
    //    (bounded by MAX_FORWARDER_PACKET_SIZE).
    BlockInterleaver(unsigned n, unsigned D, std::size_t max_frag_size);
    ~BlockInterleaver();

    BlockInterleaver(const BlockInterleaver&) = delete;
    BlockInterleaver& operator=(const BlockInterleaver&) = delete;

    unsigned n() const { return n_; }
    unsigned depth() const { return D_; }
    std::size_t max_frag_size() const { return max_frag_size_; }

    // Copy a fragment into the (b, f) slot of the currently-being-
    // filled D-frame. Size must be <= max_frag_size. The first push
    // of a frame defines the current frame via `b / D`; subsequent
    // pushes must target the same frame.
    //
    // Precondition (asserted in debug builds):
    //   - f < n
    //   - size <= max_frag_size
    //   - b / D == current frame index
    //   - the (b % D, f) slot has not already been pushed this frame
    void push(uint64_t b, unsigned f, const std::uint8_t* buf, std::size_t size);

    // True once every (d, f) slot of the current frame has been
    // pushed exactly once (pushed_count_ == D * n).
    bool is_frame_full() const;

    // Iterate the full frame in schedule order, calling fn(buf,
    // size) on each fragment. Precondition: is_frame_full().
    // After drain returns, the frame is considered emitted and the
    // interleaver is ready for the next frame's pushes.
    using EmitCallback = std::function<void(const std::uint8_t* buf, std::size_t size)>;
    void drain(const EmitCallback& fn);

    // Discard any partial-frame state. Used on session refresh
    // (plan §4.7 TX-side drain idiom under 1C) when a pending frame
    // must NOT be transmitted because (k, n, D) is about to change.
    void flush();

    // For tests and diagnostics.
    std::size_t slot_capacity() const { return slot_capacity_; }
    std::size_t bytes_owned() const {
        return std::size_t(D_) * std::size_t(n_) * slot_capacity_;
    }

private:
    const unsigned    n_;
    const unsigned    D_;
    const std::size_t max_frag_size_;
    const std::size_t slot_capacity_;  // max_frag_size rounded up to SIMD alignment

    // Parallel arrays, one entry per (d, f) grid cell, indexed
    // row-major as d * n + f. See `grid_index()`.
    std::uint8_t**    slots_;          // D*n aligned heap buffers
    std::uint16_t*    sizes_;          // actual bytes written per slot
    std::uint8_t*     filled_mask_;    // 1 = slot was pushed this frame

    std::uint32_t     pushed_count_;   // slots filled in the current frame
    std::uint64_t     current_frame_;  // floor(b / D) for the frame being filled

    std::size_t grid_index(unsigned d, unsigned f) const {
        return std::size_t(d) * std::size_t(n_) + std::size_t(f);
    }

    void free_slots_();
    void reset_frame_state_();
};

} // namespace wfb

#endif // WFB_INTERLEAVER_HPP
