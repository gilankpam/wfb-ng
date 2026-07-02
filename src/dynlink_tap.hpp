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
