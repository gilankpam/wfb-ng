// Differential and unit tests for the swfec C++ port.
// Stage 1: verify zfex's GF(2^8) field matches swfec's wire protocol
// (poly 0x11D): anchors mirror crates/swfec/src/gf256.rs tests.
#include <cassert>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include "zfex.h"

static void test_gf_anchors(void)
{
    zfex_swfec_init();
    // poly 0x11D, same anchors as the Rust reference: 2*2=4, 0x80*2=0x1D
    assert(zfex_swfec_mul(0, 5) == 0);
    assert(zfex_swfec_mul(1, 0xAB) == 0xAB);
    assert(zfex_swfec_mul(2, 2) == 4);
    assert(zfex_swfec_mul(0x80, 2) == 0x1D);
    for (int a = 1; a <= 255; a++)
        assert(zfex_swfec_mul((gf)a, zfex_swfec_inv((gf)a)) == 1);
    printf("gf anchors: OK (zfex field is 0x11D)\n");
}

static void test_addmul_matches_naive(void)
{
    zfex_swfec_init();
    // aligned buffers, odd length to exercise the scalar tail
    static uint8_t dst[1203] __attribute__((aligned(16)));
    static uint8_t ref[1203] __attribute__((aligned(16)));
    static uint8_t src[1203] __attribute__((aligned(16)));
    static uint8_t expect[1203] __attribute__((aligned(16)));
    for (int i = 0; i < 1203; i++) {
        src[i] = (uint8_t)(i * 31 + 7);
        dst[i] = ref[i] = (uint8_t)(i * 5);
    }
    for (int c = 0; c <= 255; c++) {
        memcpy(dst, ref, sizeof(dst));
        for (int i = 0; i < 1203; i++)
            expect[i] = ref[i] ^ zfex_swfec_mul((gf)c, src[i]);
        zfex_swfec_addmul(dst, src, (gf)c, sizeof(dst));
        assert(memcmp(dst, expect, sizeof(dst)) == 0);
    }
    printf("addmul vs naive: OK (all 256 coefficients)\n");
}

int main(void)
{
    test_gf_anchors();
    test_addmul_matches_naive();
    printf("fec_swfec_test: ALL OK\n");
    return 0;
}
