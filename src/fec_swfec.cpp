// swfec implementation. See fec_swfec.hpp for the protocol contract.
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
    uint32_t seq = next_seq_++;   // wraps mod 2^32 by design

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

SwfecDecoder::SwfecDecoder(uint64_t deadline_us)
    : deadline_us_(deadline_us), highest_(0)
{
    memset(&stats_, 0, sizeof(stats_));
    zfex_swfec_init();
}

uint64_t SwfecDecoder::unwrap_seq(uint32_t seq)
{
    // Map a 32-bit wire sequence number to a monotonically-increasing 64-bit
    // counter by finding the u64 value closest to highest_ that has the same
    // low 32 bits as seq.
    //
    // Originally used __int128 for intermediate arithmetic, but __int128 is
    // not supported on 32-bit ARM (armv7l). Rewritten with uint64_t abs-diff;
    // the "base - SPAN" candidate is only evaluated when base >= SPAN (i.e.
    // it would not have underflowed in the signed formulation either).
    const uint64_t SPAN = (uint64_t)1 << 32;
    uint64_t base = highest_ & ~(SPAN - 1);           // align to 2^32 boundary
    uint64_t best = base + (uint64_t)seq;
    uint64_t cands[2] = {
        base - SPAN + (uint64_t)seq,                  // cands[0]: epoch - 1
        base + SPAN + (uint64_t)seq                   // cands[1]: epoch + 1
    };
    for (int i = 0; i < 2; i++) {
        if (i == 0 && base < SPAN) continue;          // would have been negative
        uint64_t c = cands[i];
        uint64_t da = (c    >= highest_) ? (c    - highest_) : (highest_ - c);
        uint64_t db = (best >= highest_) ? (best - highest_) : (highest_ - best);
        if (da < db) best = c;
    }
    if (best > highest_) highest_ = best;
    return best;
}

void SwfecDecoder::push(const uint8_t* pkt, size_t len, uint64_t now_us,
                        std::vector<Delivered>& out)
{
    expire(now_us);
    if (len < 1) { stats_.malformed++; return; }
    if (pkt[0] == SWFEC_WIRE_SOURCE) {
        if (len < SWFEC_SOURCE_HDR) { stats_.malformed++; return; }
        stats_.sources_received++;
        uint32_t seq = swfec_be32(pkt + 1);
        uint64_t useq = unwrap_seq(seq);
        if (known_.count(useq))
            return;   // duplicate
        size_t plen = len - SWFEC_SOURCE_HDR;
        abuf_t symbol(2 + plen);
        swfec_put_be16(&symbol[0], (uint16_t)plen);
        if (plen)
            memcpy(&symbol[2], pkt + SWFEC_SOURCE_HDR, plen);
        Delivered d;
        d.seq = seq;
        d.late = false;
        d.payload.assign(pkt + SWFEC_SOURCE_HDR, pkt + len);
        out.push_back(Delivered());
        out.back().seq = d.seq; out.back().late = d.late;
        out.back().payload.swap(d.payload);
        learn(useq, symbol, now_us, false, out);
    } else if (pkt[0] == SWFEC_WIRE_REPAIR) {
        if (len < SWFEC_REPAIR_HDR) { stats_.malformed++; return; }
        uint16_t symbol_len = swfec_be16(pkt + 10);
        if (len != SWFEC_REPAIR_HDR + (size_t)symbol_len) { stats_.malformed++; return; }
        stats_.repairs_received++;
        uint32_t repair_id = swfec_be32(pkt + 1);
        uint32_t window_start = swfec_be32(pkt + 5);
        size_t n = pkt[9];
        uint64_t start = unwrap_seq(window_start);
        std::vector<uint8_t> coeffs(n);
        if (n) CoeffGen::coeffs(repair_id, n, coeffs.data());
        Row row;
        row.arrived_us = now_us;
        row.symbol.assign(pkt + SWFEC_REPAIR_HDR, pkt + len);
        for (size_t i = 0; i < n; i++) {
            uint8_t c = coeffs[i];
            if (!c) continue;
            uint64_t s = start + i;
            std::map<uint64_t, Known>::iterator it = known_.find(s);
            if (it != known_.end()) {
                const abuf_t& sym = it->second.symbol;
                if (row.symbol.size() < sym.size())
                    row.symbol.resize(sym.size(), 0);
                zfex_swfec_addmul(row.symbol.data(), sym.data(), c, sym.size());
            } else {
                row.coeffs[s] = c;
                if (!first_seen_.count(s))
                    first_seen_[s] = now_us;
            }
        }
        insert_row(row, now_us, out);
    } else {
        stats_.malformed++;
    }
}

void SwfecDecoder::insert_row(Row& row, uint64_t now_us, std::vector<Delivered>& out)
{
    for (;;) {
        if (row.coeffs.empty()) {
            stats_.repairs_redundant++;
            return;
        }
        uint64_t lead = row.coeffs.begin()->first;
        uint8_t c = row.coeffs.begin()->second;
        std::map<uint64_t, Row>::iterator pit = pivots_.find(lead);
        if (pit != pivots_.end()) {
            // row -= c * pivot (snapshot pivot data; the maps may not alias)
            std::vector<std::pair<uint64_t, uint8_t> > pc(
                pit->second.coeffs.begin(), pit->second.coeffs.end());
            abuf_t psym = pit->second.symbol;   // deliberate copy (snapshot)
            for (size_t i = 0; i < pc.size(); i++) {
                uint8_t prod = zfex_swfec_mul(c, pc[i].second);
                uint8_t& e = row.coeffs[pc[i].first];
                e = (uint8_t)(e ^ prod);
                if (e == 0)
                    row.coeffs.erase(pc[i].first);
            }
            if (row.symbol.size() < psym.size())
                row.symbol.resize(psym.size(), 0);
            zfex_swfec_addmul(row.symbol.data(), psym.data(), c, psym.size());
        } else {
            uint8_t inv = zfex_swfec_inv(c);
            for (std::map<uint64_t, uint8_t>::iterator it = row.coeffs.begin();
                 it != row.coeffs.end(); ++it)
                it->second = zfex_swfec_mul(it->second, inv);
            if (inv != 1)
                for (size_t i = 0; i < row.symbol.size(); i++)
                    row.symbol[i] = zfex_swfec_mul(inv, row.symbol[i]);
            Row& slot = pivots_[lead];
            slot.coeffs.swap(row.coeffs);
            slot.symbol.swap(row.symbol);
            slot.arrived_us = row.arrived_us;
            try_solve(now_us, out);
            return;
        }
    }
}

void SwfecDecoder::try_solve(uint64_t now_us, std::vector<Delivered>& out)
{
    for (;;) {
        uint64_t k = 0;
        bool found = false;
        for (std::map<uint64_t, Row>::iterator it = pivots_.begin();
             it != pivots_.end(); ++it)
            if (it->second.coeffs.size() == 1) { k = it->first; found = true; break; }
        if (!found)
            return;
        abuf_t symbol;
        symbol.swap(pivots_[k].symbol);
        pivots_.erase(k);
        // normalized single coefficient == 1: symbol IS the packet symbol
        learn(k, symbol, now_us, true, out);
    }
}

void SwfecDecoder::learn(uint64_t useq, abuf_t& symbol, uint64_t now_us,
                         bool deliver, std::vector<Delivered>& out)
{
    if (deliver && symbol.size() >= 2) {
        size_t plen = ((size_t)symbol[0] << 8) | symbol[1];
        if (symbol.size() >= 2 + plen) {
            stats_.recovered++;
            out.push_back(Delivered());
            out.back().seq = (uint32_t)useq;
            out.back().late = true;
            out.back().payload.assign(symbol.begin() + 2, symbol.begin() + 2 + plen);
        }
    }
    first_seen_.erase(useq);
    Known& kn = known_[useq];
    kn.symbol.swap(symbol);
    kn.t_us = now_us;

    std::vector<uint64_t> affected;
    for (std::map<uint64_t, Row>::iterator it = pivots_.begin();
         it != pivots_.end(); ++it)
        if (it->second.coeffs.count(useq))
            affected.push_back(it->first);
    for (size_t i = 0; i < affected.size(); i++) {
        std::map<uint64_t, Row>::iterator it = pivots_.find(affected[i]);
        if (it == pivots_.end())
            continue;   // already consumed by recursion
        Row row;
        row.coeffs.swap(it->second.coeffs);
        row.symbol.swap(it->second.symbol);
        row.arrived_us = it->second.arrived_us;
        pivots_.erase(it);
        uint8_t c = row.coeffs[useq];
        row.coeffs.erase(useq);
        const abuf_t& sym = known_[useq].symbol;
        if (row.symbol.size() < sym.size())
            row.symbol.resize(sym.size(), 0);
        zfex_swfec_addmul(row.symbol.data(), sym.data(), c, sym.size());
        insert_row(row, now_us, out);
    }
}

void SwfecDecoder::expire(uint64_t now_us)
{
    uint64_t dl = deadline_us_;
    std::vector<uint64_t> expired;
    for (std::map<uint64_t, uint64_t>::iterator it = first_seen_.begin();
         it != first_seen_.end(); ++it) {
        uint64_t age = now_us >= it->second ? now_us - it->second : 0;
        if (age > dl)
            expired.push_back(it->first);
    }
    for (size_t i = 0; i < expired.size(); i++) {
        first_seen_.erase(expired[i]);
        stats_.abandoned++;
        std::vector<uint64_t> dead;
        for (std::map<uint64_t, Row>::iterator it = pivots_.begin();
             it != pivots_.end(); ++it)
            if (it->second.coeffs.count(expired[i]))
                dead.push_back(it->first);
        for (size_t j = 0; j < dead.size(); j++)
            pivots_.erase(dead[j]);
    }
    for (std::map<uint64_t, Row>::iterator it = pivots_.begin(); it != pivots_.end();) {
        uint64_t age = now_us >= it->second.arrived_us ? now_us - it->second.arrived_us : 0;
        if (age > dl) pivots_.erase(it++); else ++it;
    }
    for (std::map<uint64_t, Known>::iterator it = known_.begin(); it != known_.end();) {
        uint64_t age = now_us >= it->second.t_us ? now_us - it->second.t_us : 0;
        if (age > 2 * dl) known_.erase(it++); else ++it;
    }
}

// --- SwfecReorder: in-order release buffer ---
SwfecReorder::SwfecReorder(uint64_t deadline_us)
    : deadline_us_(deadline_us), started_(false), next_seq_(0) {}

void SwfecReorder::reset()
{
    started_ = false;
    next_seq_ = 0;
    buf_.clear();
}

void SwfecReorder::push(uint32_t seq, bool late, const uint8_t* data, size_t len,
                        uint64_t now_us, std::vector<Out>& out, uint32_t& skipped)
{
    if (!started_) {
        started_ = true;
        next_seq_ = seq;
    }
    // Already emitted (or its gap was skipped): too late to deliver in order.
    // No-wrap within a session, so a plain comparison is safe.
    if (seq < next_seq_)
        return;
    // First writer wins; ignore duplicate deliveries of the same seq.
    if (buf_.find(seq) != buf_.end())
        return;
    Item& it = buf_[seq];
    it.payload.assign(data, data + len);
    it.late = late;
    it.arrived_us = now_us;
    drain(now_us, out, skipped);
}

void SwfecReorder::poll(uint64_t now_us, std::vector<Out>& out, uint32_t& skipped)
{
    drain(now_us, out, skipped);
}

void SwfecReorder::drain(uint64_t now_us, std::vector<Out>& out, uint32_t& skipped)
{
    for (;;) {
        // Release the contiguous run starting at the cursor.
        std::map<uint32_t, Item>::iterator it;
        while ((it = buf_.find(next_seq_)) != buf_.end()) {
            out.push_back(Out());
            out.back().payload.swap(it->second.payload);
            out.back().late = it->second.late;
            buf_.erase(it);
            next_seq_ += 1;
        }
        if (buf_.empty())
            return;
        // A gap blocks the cursor. The oldest pending packet (smallest buffered
        // seq) is the one waiting behind the gap; if it has waited longer than
        // the deadline, the missing packet will never come (the decoder abandons
        // unrecoverable seqs within the same deadline), so skip the gap.
        std::map<uint32_t, Item>::iterator head = buf_.begin();
        uint64_t age = now_us >= head->second.arrived_us
                           ? now_us - head->second.arrived_us : 0;
        if (age > deadline_us_) {
            skipped += head->first - next_seq_;
            next_seq_ = head->first;
            continue;   // release the now-contiguous run
        }
        return;         // still within deadline: keep holding
    }
}

} // namespace swfec
