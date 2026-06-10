// Implementation of the swfec C++ port. See fec_swfec.hpp for provenance.
#include "fec_swfec.hpp"

#include <cstring>
#include "zfex.h"   // zfex_swfec_{init,mul,inv,addmul}

namespace swfec {

void CoeffGen::coeffs(uint32_t repair_id, size_t n, uint8_t* out)
{
    CoeffGen g(repair_id);
    size_t i = 0;
    while (i < n) {
        uint64_t v = g.next_u64();
        for (int b = 0; b < 8 && i < n; b++, i++)
            out[i] = (uint8_t)(v >> (8 * b));   // little-endian byte order
    }
}

SwfecEncoder::SwfecEncoder(float overhead, uint64_t deadline_us)
    : overhead_(overhead), deadline_us_(deadline_us), next_seq_(0),
      next_repair_id_(0), credit_(0.0f), last_source_us_(0),
      flushed_since_source_(true)
{
    zfex_swfec_init();
}

void SwfecEncoder::push_source(const uint8_t* payload, size_t len, uint64_t now_us,
                               std::vector<std::vector<uint8_t> >& out)
{
    uint32_t seq = next_seq_++;   // unsigned wrap == Rust wrapping_add

    Entry e;
    e.seq = seq;
    e.arrived_us = now_us;
    e.symbol.resize(2 + len);
    swfec_put_be16(&e.symbol[0], (uint16_t)len);
    if (len)
        memcpy(&e.symbol[2], payload, len);
    window_.push_back(Entry());
    window_.back().seq = e.seq;
    window_.back().arrived_us = e.arrived_us;
    window_.back().symbol.swap(e.symbol);

    trim(now_us);
    last_source_us_ = now_us;
    flushed_since_source_ = false;

    std::vector<uint8_t> src(SWFEC_SOURCE_HDR + len);
    src[0] = SWFEC_WIRE_SOURCE;
    swfec_put_be32(&src[1], seq);
    if (len)
        memcpy(&src[5], payload, len);
    out.push_back(std::vector<uint8_t>());
    out.back().swap(src);

    credit_ += overhead_;
    while (credit_ >= 1.0f) {
        credit_ -= 1.0f;
        std::vector<uint8_t> rep;
        if (make_repair(rep)) {
            out.push_back(std::vector<uint8_t>());
            out.back().swap(rep);
        }
    }
}

void SwfecEncoder::poll(uint64_t now_us, std::vector<std::vector<uint8_t> >& out)
{
    trim(now_us);
    uint64_t gap = now_us >= last_source_us_ ? now_us - last_source_us_ : 0;
    if (credit_ > 0.0f && !flushed_since_source_ && !window_.empty()
        && gap >= SWFEC_FLUSH_GAP_US) {
        credit_ -= 1.0f;   // may go negative: borrows to keep long-run overhead
        flushed_since_source_ = true;
        std::vector<uint8_t> rep;
        if (make_repair(rep)) {
            out.push_back(std::vector<uint8_t>());
            out.back().swap(rep);
        }
    }
}

void SwfecEncoder::trim(uint64_t now_us)
{
    while (window_.size() > SWFEC_WINDOW_CAP)
        window_.pop_front();
    while (!window_.empty()) {
        uint64_t age = now_us >= window_.front().arrived_us
                           ? now_us - window_.front().arrived_us : 0;
        if (age > deadline_us_)
            window_.pop_front();
        else
            break;
    }
}

bool SwfecEncoder::make_repair(std::vector<uint8_t>& pkt)
{
    if (window_.empty())
        return false;
    uint32_t window_start = window_.front().seq;
    size_t n = window_.size();
    size_t symbol_len = 0;
    for (std::deque<Entry>::const_iterator it = window_.begin(); it != window_.end(); ++it)
        if (it->symbol.size() > symbol_len)
            symbol_len = it->symbol.size();
    uint32_t repair_id = next_repair_id_++;

    std::vector<uint8_t> coeffs(n);
    CoeffGen::coeffs(repair_id, n, coeffs.data());

    abuf_t symbol(symbol_len, 0);
    size_t i = 0;
    for (std::deque<Entry>::const_iterator it = window_.begin(); it != window_.end(); ++it, ++i)
        zfex_swfec_addmul(symbol.data(), it->symbol.data(), coeffs[i], it->symbol.size());

    pkt.resize(SWFEC_REPAIR_HDR + symbol_len);
    pkt[0] = SWFEC_WIRE_REPAIR;
    swfec_put_be32(&pkt[1], repair_id);
    swfec_put_be32(&pkt[5], window_start);
    pkt[9] = (uint8_t)n;
    swfec_put_be16(&pkt[10], (uint16_t)symbol_len);
    memcpy(&pkt[12], symbol.data(), symbol_len);
    return true;
}

} // namespace swfec
