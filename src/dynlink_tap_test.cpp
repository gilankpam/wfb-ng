// Golden-hex tests for the dynlink tap encoder (tap wire v1).
// Vectors are normative — shared byte-for-byte with the fpvd GS decoder
// tests (fpvd spec 2026-07-02-wfb-rx-dynlink-tap-design.md).
#include <assert.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
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

    // --- LOSS coalescing: N gaps inside the 2 ms holdoff -> 1 datagram ---
    {
        int rxfd = socket(AF_INET, SOCK_DGRAM, 0);
        assert(rxfd >= 0);
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0;
        assert(bind(rxfd, (struct sockaddr *)&a, sizeof(a)) == 0);
        socklen_t alen = sizeof(a);
        assert(getsockname(rxfd, (struct sockaddr *)&a, &alen) == 0);

        TapEmitter e;
        e.init(ntohs(a.sin_port));
        assert(e.enabled());
        e.note_loss(1, 10, 12, 1000);   // immediate
        e.note_loss(2, 13, 16, 1001);   // inside holdoff -> held
        e.note_loss(3, 17, 21, 1001);   // accumulates
        e.flush_loss(1001);             // holdoff not expired -> nothing
        e.flush_loss(1002);             // expired -> one coalesced datagram

        uint8_t pkt[64];
        ssize_t n = recv(rxfd, pkt, sizeof(pkt), 0);
        assert(n == (ssize_t)TAP_LOSS_SIZE && pkt[0] == TAP_TYPE_LOSS);
        uint32_t lost1 = pkt[12] | pkt[13] << 8 | pkt[14] << 16 | (uint32_t)pkt[15] << 24;
        assert(lost1 == 1);
        n = recv(rxfd, pkt, sizeof(pkt), 0);
        assert(n == (ssize_t)TAP_LOSS_SIZE);
        uint32_t lost2 = pkt[12] | pkt[13] << 8 | pkt[14] << 16 | (uint32_t)pkt[15] << 24;
        assert(lost2 == 5); // 2 + 3 coalesced
        n = recv(rxfd, pkt, sizeof(pkt), MSG_DONTWAIT);
        assert(n < 0); // exactly two datagrams, no storm
        close(rxfd);
    }

    printf("dynlink_tap_test OK\n");
    return 0;
}
