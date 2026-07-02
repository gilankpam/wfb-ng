// -*- C++ -*-
// dynlink tap wire v1: real-time side-channel wfb_rx -> GS dynamic-link
// controller (localhost UDP, binary, little-endian, packed). Encoder only;
// the GS decoder lives in fpvd gs/fpvdgs/dynlink/tap_wire.py. Golden-hex
// tested on both sides (src/dynlink_tap_test.cpp).
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <vector>

static const uint8_t TAP_TYPE_MICRO = 0x01;
static const uint8_t TAP_TYPE_LOSS  = 0x02;
static const uint8_t TAP_WIRE_VERSION = 0x01;
static const size_t TAP_MICRO_HDR_SIZE = 33;
static const size_t TAP_MICRO_BUCKET_SIZE = 28;
static const size_t TAP_LOSS_SIZE = 24;
static const size_t TAP_MAX_BUCKETS = 64;

struct tap_bucket_t {
    uint16_t freq;
    uint8_t mcs;
    uint8_t bw;
    uint64_t ant_id;
    uint32_t pkt_recv;
    int8_t rssi_min, rssi_avg, rssi_max;
    int8_t snr_min, snr_avg, snr_max;
    int16_t evm_min, evm_avg, evm_max; // -1 = absent (matches the :8103 sentinel)
};

struct tap_counters_t {
    uint32_t all = 0, data = 0, fec_rec = 0, lost = 0, out = 0;
    void clear() { all = data = fec_rec = lost = out = 0; }
};

static inline void tap_put_u16(uint8_t *p, uint16_t v) { p[0] = v & 0xff; p[1] = v >> 8; }
static inline void tap_put_u32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (v >> (8 * i)) & 0xff; }
static inline void tap_put_u64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (v >> (8 * i)) & 0xff; }

static inline size_t tap_encode_micro(uint8_t *buf, size_t cap, uint16_t seq, uint64_t ts_ms,
                                      const tap_counters_t &c, const std::vector<tap_bucket_t> &buckets)
{
    size_t n = buckets.size() > TAP_MAX_BUCKETS ? TAP_MAX_BUCKETS : buckets.size();
    if (cap < TAP_MICRO_HDR_SIZE + n * TAP_MICRO_BUCKET_SIZE) return 0;
    uint8_t *p = buf;
    *p++ = TAP_TYPE_MICRO;
    *p++ = TAP_WIRE_VERSION;
    tap_put_u16(p, seq); p += 2;
    tap_put_u64(p, ts_ms); p += 8;
    tap_put_u32(p, c.all); p += 4;
    tap_put_u32(p, c.data); p += 4;
    tap_put_u32(p, c.fec_rec); p += 4;
    tap_put_u32(p, c.lost); p += 4;
    tap_put_u32(p, c.out); p += 4;
    *p++ = (uint8_t)n;
    for (size_t i = 0; i < n; i++) {
        const tap_bucket_t &b = buckets[i];
        tap_put_u16(p, b.freq); p += 2;
        *p++ = b.mcs;
        *p++ = b.bw;
        tap_put_u64(p, b.ant_id); p += 8;
        tap_put_u32(p, b.pkt_recv); p += 4;
        *p++ = (uint8_t)b.rssi_min; *p++ = (uint8_t)b.rssi_avg; *p++ = (uint8_t)b.rssi_max;
        *p++ = (uint8_t)b.snr_min;  *p++ = (uint8_t)b.snr_avg;  *p++ = (uint8_t)b.snr_max;
        tap_put_u16(p, (uint16_t)b.evm_min); p += 2;
        tap_put_u16(p, (uint16_t)b.evm_avg); p += 2;
        tap_put_u16(p, (uint16_t)b.evm_max); p += 2;
    }
    return (size_t)(p - buf);
}

static inline size_t tap_encode_loss(uint8_t *buf, size_t cap, uint16_t seq, uint64_t ts_ms,
                                     uint32_t lost_count, uint32_t last_seq, uint32_t new_seq)
{
    if (cap < TAP_LOSS_SIZE) return 0;
    uint8_t *p = buf;
    *p++ = TAP_TYPE_LOSS;
    *p++ = TAP_WIRE_VERSION;
    tap_put_u16(p, seq); p += 2;
    tap_put_u64(p, ts_ms); p += 8;
    tap_put_u32(p, lost_count); p += 4;
    tap_put_u32(p, last_seq); p += 4;
    tap_put_u32(p, new_seq); p += 4;
    return TAP_LOSS_SIZE;
}

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// Owns the tap UDP socket + the LOSS coalescer. Fire-and-forget: send
// failures increment drop_count and are otherwise ignored — the radio
// loop must never block or throw on tap I/O.
class TapEmitter
{
public:
    static const int LOSS_HOLDOFF_MS = 2;

    ~TapEmitter() { if (fd_ >= 0) close(fd_); }
    bool enabled(void) const { return fd_ >= 0; }
    uint16_t take_seq(void) { return seq_++; }
    uint32_t drop_count(void) const { return drop_count_; }

    void init(int port)
    {
        fd_ = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        if (fd_ < 0) return; // tap stays disabled; video path unaffected
        memset(&dst_, 0, sizeof(dst_));
        dst_.sin_family = AF_INET;
        dst_.sin_port = htons((uint16_t)port);
        dst_.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }

    void send_buf(const uint8_t *buf, size_t len)
    {
        if (fd_ < 0) return;
        if (sendto(fd_, buf, len, 0, (struct sockaddr *)&dst_, sizeof(dst_)) < 0)
            drop_count_ += 1;
    }

    // First loss in a quiet period is sent immediately; losses inside the
    // 2 ms holdoff accumulate and flush from flush_loss() (called every
    // poll-loop iteration) — a burst can never become a datagram storm.
    void note_loss(uint32_t lost, uint32_t last_seq, uint32_t new_seq, uint64_t ts_ms)
    {
        if (fd_ < 0 || lost == 0) return;
        if (pend_lost_ == 0 && ts_ms >= hold_until_ms_) {
            uint8_t buf[TAP_LOSS_SIZE];
            size_t n = tap_encode_loss(buf, sizeof(buf), take_seq(), ts_ms, lost, last_seq, new_seq);
            send_buf(buf, n);
            hold_until_ms_ = ts_ms + LOSS_HOLDOFF_MS;
        } else {
            if (pend_lost_ == 0) { pend_last_ = last_seq; }
            pend_lost_ += lost;
            pend_new_ = new_seq;
        }
    }

    void flush_loss(uint64_t ts_ms)
    {
        if (fd_ < 0 || pend_lost_ == 0 || ts_ms < hold_until_ms_) return;
        uint8_t buf[TAP_LOSS_SIZE];
        size_t n = tap_encode_loss(buf, sizeof(buf), take_seq(), ts_ms, pend_lost_, pend_last_, pend_new_);
        send_buf(buf, n);
        pend_lost_ = 0;
        hold_until_ms_ = ts_ms + LOSS_HOLDOFF_MS;
    }

    // ms until the held loss may flush; -1 = nothing held
    int loss_deadline_ms(uint64_t ts_ms) const
    {
        if (fd_ < 0 || pend_lost_ == 0) return -1;
        return hold_until_ms_ > ts_ms ? (int)(hold_until_ms_ - ts_ms) : 0;
    }

private:
    int fd_ = -1;
    struct sockaddr_in dst_;
    uint16_t seq_ = 0;
    uint32_t drop_count_ = 0;
    uint64_t hold_until_ms_ = 0;
    uint32_t pend_lost_ = 0;
    uint32_t pend_last_ = 0;
    uint32_t pend_new_ = 0;
};
