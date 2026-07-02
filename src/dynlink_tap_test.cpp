// Golden-hex tests for the dynlink tap encoder (tap wire v1).
// Vectors are normative — shared byte-for-byte with the fpvd GS decoder
// tests (fpvd spec 2026-07-02-wfb-rx-dynlink-tap-design.md).
#include <assert.h>
#include <stdio.h>
#include <string>
#include <vector>
#include "dynlink_tap.hpp"

static std::string hex(const uint8_t *b, size_t n)
{
    static const char *d = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; i++) { s += d[b[i] >> 4]; s += d[b[i] & 0xf]; }
    return s;
}

int main(void)
{
    uint8_t buf[2048];

    tap_counters_t c;
    c.all = 142; c.data = 130; c.fec_rec = 3; c.lost = 1; c.out = 141;
    std::vector<tap_bucket_t> buckets;
    tap_bucket_t b1 = {5805, 5, 20, 0x100, 88, -71, -66, -62, 22, 26, 29, 14, 18, 21};
    tap_bucket_t b2 = {5805, 5, 20, 0x101, 54, -78, -74, -70, 15, 19, 22, -1, -1, -1};
    buckets.push_back(b1);
    buckets.push_back(b2);
    size_t len = tap_encode_micro(buf, sizeof(buf), 258, 1719900000123ULL, c, buckets);
    assert(len == TAP_MICRO_HDR_SIZE + 2 * TAP_MICRO_BUCKET_SIZE);
    assert(hex(buf, len) ==
        "010102017b4f0772900100008e0000008200000003000000010000008d00000002"
        "ad160514000100000000000058000000b9bec2161a1d0e0012001500"
        "ad160514010100000000000036000000b2b6ba0f1316ffffffffffff");

    // heartbeat: zero counters, zero buckets — header only
    tap_counters_t z;
    len = tap_encode_micro(buf, sizeof(buf), 0, 0, z, std::vector<tap_bucket_t>());
    assert(len == TAP_MICRO_HDR_SIZE);

    // cap too small -> 0, nothing written
    assert(tap_encode_micro(buf, 10, 0, 0, z, std::vector<tap_bucket_t>()) == 0);

    len = tap_encode_loss(buf, sizeof(buf), 259, 1719900000131ULL, 4, 118272, 118277);
    assert(len == TAP_LOSS_SIZE);
    assert(hex(buf, len) == "02010301834f0772900100000400000000ce010005ce0100");

    printf("dynlink_tap_test OK\n");
    return 0;
}
