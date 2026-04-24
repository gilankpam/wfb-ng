// Phase 1 TX-side block interleaver. See interleaver.hpp.

#include "interleaver.hpp"

#include <cassert>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>

extern "C" {
#include "zfex.h"
}

namespace wfb {

namespace {

// Allocate `size` bytes aligned to `alignment`. Throws on failure
// (posix_memalign returns an errno on failure, never sets errno).
// The returned pointer must be freed with free().
void* xaligned_alloc(std::size_t alignment, std::size_t size)
{
    void* p = nullptr;
    const int rc = ::posix_memalign(&p, alignment, size);
    if (rc != 0 || p == nullptr) {
        throw std::runtime_error(
            std::string("BlockInterleaver: posix_memalign failed, rc=") +
            std::to_string(rc));
    }
    return p;
}

} // anonymous namespace


BlockInterleaver::BlockInterleaver(unsigned n, unsigned D, std::size_t max_frag_size)
    : n_(n),
      D_(D),
      max_frag_size_(max_frag_size),
      slot_capacity_(ZFEX_ROUND_UP_SIMD(max_frag_size)),
      slots_(nullptr),
      sizes_(nullptr),
      filled_mask_(nullptr),
      pushed_count_(0),
      current_frame_(0)
{
    if (n < 1 || n > 255) {
        throw std::runtime_error("BlockInterleaver: n out of range (1..255)");
    }
    if (D < 1 || D > 255) {
        throw std::runtime_error("BlockInterleaver: D out of range (1..255)");
    }
    if (max_frag_size < 1) {
        throw std::runtime_error("BlockInterleaver: max_frag_size must be > 0");
    }

    const std::size_t total = std::size_t(D) * std::size_t(n);

    // Parallel arrays. Any exception thrown mid-allocation must not
    // leak; use a guard lambda to free whatever we've allocated so
    // far.
    slots_       = new std::uint8_t*[total]();  // zero-initialised
    sizes_       = new std::uint16_t[total]();
    filled_mask_ = new std::uint8_t[total]();

    try {
        for (std::size_t i = 0; i < total; ++i) {
            slots_[i] = static_cast<std::uint8_t*>(
                xaligned_alloc(ZFEX_SIMD_ALIGNMENT, slot_capacity_));
        }
    } catch (...) {
        free_slots_();
        delete[] sizes_;        sizes_ = nullptr;
        delete[] filled_mask_;  filled_mask_ = nullptr;
        throw;
    }
}


BlockInterleaver::~BlockInterleaver()
{
    free_slots_();
    delete[] sizes_;
    delete[] filled_mask_;
}


void BlockInterleaver::free_slots_()
{
    if (slots_ == nullptr) return;
    const std::size_t total = std::size_t(D_) * std::size_t(n_);
    for (std::size_t i = 0; i < total; ++i) {
        if (slots_[i] != nullptr) {
            std::free(slots_[i]);
            slots_[i] = nullptr;
        }
    }
    delete[] slots_;
    slots_ = nullptr;
}


void BlockInterleaver::reset_frame_state_()
{
    const std::size_t total = std::size_t(D_) * std::size_t(n_);
    std::memset(sizes_,       0, total * sizeof(sizes_[0]));
    std::memset(filled_mask_, 0, total);
    pushed_count_ = 0;
}


void BlockInterleaver::push(std::uint64_t b, unsigned f,
                            const std::uint8_t* buf, std::size_t size)
{
    assert(f < n_);
    assert(size <= max_frag_size_);
    assert(buf != nullptr);

    const std::uint64_t frame_of_b = b / D_;
    if (pushed_count_ == 0) {
        // First push of a fresh frame anchors the frame index.
        current_frame_ = frame_of_b;
    } else {
        // Subsequent pushes must stay inside the current frame.
        assert(frame_of_b == current_frame_ &&
               "BlockInterleaver: push() across frame boundary "
               "without drain()/flush()");
    }

    const unsigned d    = unsigned(b % D_);
    const std::size_t gi = grid_index(d, f);
    assert(gi < std::size_t(D_) * std::size_t(n_));
    assert(filled_mask_[gi] == 0 &&
           "BlockInterleaver: same (b, f) slot pushed twice in one frame");

    // Copy the caller's fragment bytes into the owned slot. Zero
    // the tail (between `size` and `slot_capacity_`) so a later
    // over-read by aligned SIMD code yields zeros, not stale data.
    // Required by plan §4.5 item 1 (alignment) and item 10 (don't
    // leak ciphertext on discard paths).
    std::memcpy(slots_[gi], buf, size);
    if (size < slot_capacity_) {
        std::memset(slots_[gi] + size, 0, slot_capacity_ - size);
    }
    sizes_[gi]       = std::uint16_t(size);
    filled_mask_[gi] = 1;
    pushed_count_   += 1;
}


bool BlockInterleaver::is_frame_full() const
{
    return pushed_count_ == std::uint32_t(D_) * std::uint32_t(n_);
}


void BlockInterleaver::drain(const EmitCallback& fn)
{
    assert(is_frame_full());
    assert(fn);

    // Column-major emission over the D x n grid.
    //
    //   slot_in_frame = f * D + d
    //
    // matches the reference at src/bench/interleaver.hpp. At D == 1
    // this degenerates to `f = 0..n-1` — same as master's per-block
    // emission order — so the D == 1 fast path is byte-identical to
    // master when callers bypass the interleaver entirely.
    for (unsigned f = 0; f < n_; ++f) {
        for (unsigned d = 0; d < D_; ++d) {
            const std::size_t gi = grid_index(d, f);
            fn(slots_[gi], sizes_[gi]);
        }
    }

    reset_frame_state_();
    current_frame_ += 1;
}


void BlockInterleaver::flush()
{
    reset_frame_state_();
    // Deliberately do NOT advance current_frame_: the next push() is
    // about to re-anchor it from the caller's current b anyway.
}

} // namespace wfb
