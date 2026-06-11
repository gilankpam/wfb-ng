#ifndef FEC_SWFEC_HPP
#define FEC_SWFEC_HPP
// swfec: sliding-window FEC. The wire format and the coefficient PRNG are
// FROZEN PROTOCOL — changing them breaks interop with any deployed node.
// Differential tests in fec_swfec_test.cpp pin byte-exact wire stability
// against pre-generated vectors (run when a local test_vectors/ directory
// is present).

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <ctime>
#include <deque>
#include <map>
#include <new>
#include <vector>

namespace swfec {

// 16-byte-aligned byte buffer: zfex's SIMD addmul assumes aligned dst+src.
// All symbol operations start at offset 0 of these buffers, so alignment of
// the base pointer is sufficient.
template <typename T, size_t Align = 16>
struct aligned_alloc_t {
    typedef T value_type;
    aligned_alloc_t() {}
    template <class U> aligned_alloc_t(const aligned_alloc_t<U, Align>&) {}
    T* allocate(size_t n) {
        void* p = NULL;
        if (posix_memalign(&p, Align, n != 0 ? n * sizeof(T) : Align) != 0)
            throw std::bad_alloc();
        return static_cast<T*>(p);
    }
    void deallocate(T* p, size_t) { free(p); }
    template <class U> struct rebind { typedef aligned_alloc_t<U, Align> other; };
    bool operator==(const aligned_alloc_t&) const { return true; }
    bool operator!=(const aligned_alloc_t&) const { return false; }
};
typedef std::vector<uint8_t, aligned_alloc_t<uint8_t> > abuf_t;

// Wire constants (frozen protocol)
enum {
    SWFEC_WIRE_SOURCE = 0x01,
    SWFEC_WIRE_REPAIR = 0x02,
    SWFEC_SOURCE_HDR = 5,   // type + seq u32 BE
    SWFEC_REPAIR_HDR = 12,  // type + repair_id + window_start + window_len u8 + symbol_len u16 BE
    SWFEC_WINDOW_CAP = 64
};
static const uint64_t SWFEC_FLUSH_GAP_US = 2000;

// Deterministic coefficient stream (splitmix64) — part of the wire protocol;
// its output sequence must never change.
class CoeffGen {
public:
    explicit CoeffGen(uint32_t repair_id)
        : state_(uint64_t(repair_id) ^ 0x9E3779B97F4A7C15ULL) {}
    uint64_t next_u64() {
        state_ += 0x9E3779B97F4A7C15ULL;
        uint64_t z = state_;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
    }
    // First n coefficient bytes (little-endian u64 stream; prefix-stable in n).
    static void coeffs(uint32_t repair_id, size_t n, uint8_t* out);
private:
    uint64_t state_;
};

struct Delivered {
    uint32_t seq;
    bool late;
    std::vector<uint8_t> payload;
};

struct DecoderStats {
    uint64_t sources_received;
    uint64_t repairs_received;
    uint64_t repairs_redundant;
    uint64_t recovered;
    uint64_t abandoned;
    uint64_t malformed;
};

// Systematic sliding-window encoder:
// sources pass through unmodified; repairs are RLC combinations of the
// deadline-bounded window (64-packet hard cap). Time is injected (now_us).
class SwfecEncoder {
public:
    SwfecEncoder(float overhead, uint64_t deadline_us);
    // Appends wire packets to out: the source packet first, then due repairs.
    void push_source(const uint8_t* payload, size_t len, uint64_t now_us,
                     std::vector<std::vector<uint8_t> >& out);
    // Quiet-gap flush; appends at most one repair.
    void poll(uint64_t now_us, std::vector<std::vector<uint8_t> >& out);
    void set_overhead(float v) { overhead_ = v; }            // live, TX-only
    void set_deadline_us(uint64_t v) { deadline_us_ = v; }
    float overhead() const { return overhead_; }
    uint64_t deadline_us() const { return deadline_us_; }
private:
    struct Entry {
        uint32_t seq;
        uint64_t arrived_us;
        abuf_t symbol;  // [len u16 BE | payload], unpadded
    };
    void trim(uint64_t now_us);
    bool make_repair(std::vector<uint8_t>& pkt);
    float overhead_;
    uint64_t deadline_us_;
    uint32_t next_seq_;
    uint32_t next_repair_id_;
    float credit_;
    std::deque<Entry> window_;
    uint64_t last_source_us_;
    bool flushed_since_source_;
};

// Incremental Gaussian-elimination decoder:
// no reordering, no head-of-line blocking; sources deliver on arrival,
// recovered packets deliver when solved (late). Never throws on bad input.
class SwfecDecoder {
public:
    explicit SwfecDecoder(uint64_t deadline_us);
    void push(const uint8_t* pkt, size_t len, uint64_t now_us,
              std::vector<Delivered>& out);
    void set_deadline_us(uint64_t v) { deadline_us_ = v; }   // param-only session update
    const DecoderStats& stats() const { return stats_; }
    size_t pivot_count() const { return pivots_.size(); }
private:
    struct Known {
        abuf_t symbol;
        uint64_t t_us;
    };
    struct Row {
        std::map<uint64_t, uint8_t> coeffs;
        abuf_t symbol;
        uint64_t arrived_us;
    };
    uint64_t unwrap_seq(uint32_t seq);
    void learn(uint64_t useq, abuf_t& symbol, uint64_t now_us, bool deliver,
               std::vector<Delivered>& out);
    void insert_row(Row& row, uint64_t now_us, std::vector<Delivered>& out);
    void try_solve(uint64_t now_us, std::vector<Delivered>& out);
    void expire(uint64_t now_us);
    uint64_t deadline_us_;
    std::map<uint64_t, Known> known_;
    std::map<uint64_t, Row> pivots_;
    std::map<uint64_t, uint64_t> first_seen_;
    uint64_t highest_;
    DecoderStats stats_;
};

// In-order release buffer for the swfec decode path. SwfecDecoder delivers
// source packets on arrival (any order) and recovered packets late; a
// zero-jitter RTP consumer (e.g. pixelpilot --rtp-jitter-ms 0) treats every
// reorder as a gap and forces an IDR, which glitches the video even though
// nothing was actually lost. This buffer restores the in-order delivery
// contract of the RS-block path (rx.cpp): packets are released strictly in
// sequence order, a gap is held up to the deadline for the missing packet to
// arrive/recover, then skipped as lost. Latency is added only on a gap, not on
// the loss-free path. Kept separate from SwfecDecoder so the decoder's wire
// behavior stays untouched (pinned by the differential tests).
//
// Sequence numbers are the raw 32-bit wire seqs. Like the rx.cpp loss tracker,
// this relies on a session rekeying long before the u32 seq could wrap, so no
// unwrap is needed; reset() is called on every session change.
class SwfecReorder {
public:
    struct Out {
        std::vector<uint8_t> payload;
        bool late;   // recovered by FEC (decoder marked it late)
    };
    explicit SwfecReorder(uint64_t deadline_us);
    void set_deadline_us(uint64_t v) { deadline_us_ = v; }   // param-only session update
    void reset();
    // Feed one decoder-delivered packet; appends in-order releases to out and
    // adds the count of gap packets abandoned past the deadline to skipped.
    void push(uint32_t seq, bool late, const uint8_t* data, size_t len,
              uint64_t now_us, std::vector<Out>& out, uint32_t& skipped);
    // Time-based drain without a new packet (honors the deadline during a
    // quiet gap). Appends releases to out and abandoned counts to skipped.
    void poll(uint64_t now_us, std::vector<Out>& out, uint32_t& skipped);
private:
    struct Item {
        std::vector<uint8_t> payload;
        bool late;
        uint64_t arrived_us;
    };
    void drain(uint64_t now_us, std::vector<Out>& out, uint32_t& skipped);
    uint64_t deadline_us_;
    bool started_;
    uint32_t next_seq_;               // next seq to emit (in-order cursor)
    std::map<uint32_t, Item> buf_;    // pending seqs awaiting their predecessor
};

// Big-endian helpers shared by encoder/decoder/tests.
static inline uint32_t swfec_be32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static inline uint16_t swfec_be16(const uint8_t* p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}
static inline void swfec_put_be32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}
static inline void swfec_put_be16(uint8_t* p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v;
}

// Monotonic clock in microseconds — shared by tx.cpp and rx.cpp
static inline uint64_t monotonic_us(void) {
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

} // namespace swfec

#endif // FEC_SWFEC_HPP
