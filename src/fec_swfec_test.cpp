// Differential and unit tests for the swfec C++ port.
// Stage 1: verify zfex's GF(2^8) field matches swfec's wire protocol
// (poly 0x11D): anchors mirror crates/swfec/src/gf256.rs tests.
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>
#include "zfex.h"
#include "fec_swfec.hpp"

// --- minimal vector-file reader (format: plan "Vector file format") ---
struct VecReader {
    FILE* f;
    explicit VecReader(const char* path) {
        f = fopen(path, "rb");
        if (!f) { fprintf(stderr, "cannot open %s\n", path); exit(2); }
    }
    ~VecReader() { fclose(f); }
    bool eof() {
        int c = fgetc(f);
        if (c == EOF) return true;
        ungetc(c, f);
        return false;
    }
    uint8_t u8() { uint8_t v; assert(fread(&v, 1, 1, f) == 1); return v; }
    uint32_t u32() { uint32_t v; assert(fread(&v, 4, 1, f) == 1); return v; }  // LE host assumed (x86/ARM LE)
    uint64_t u64() { uint64_t v; assert(fread(&v, 8, 1, f) == 1); return v; }
    void bytes(uint8_t* p, size_t n) { if (n) assert(fread(p, 1, n, f) == n); }
    void header(uint32_t expect_kind) {
        assert(u32() == 0x53574643u);
        assert(u32() == 1);
        assert(u32() == expect_kind);
        u32(); // param
    }
};

static void test_coeff_vectors(const char* path)
{
    VecReader r(path);
    r.header(1);
    int checked = 0;
    while (!r.eof()) {
        uint32_t repair_id = r.u32();
        uint32_t n = r.u32();
        std::vector<uint8_t> expect(n), got(n);
        r.bytes(expect.data(), n);
        swfec::CoeffGen::coeffs(repair_id, n, got.data());
        assert(memcmp(expect.data(), got.data(), n) == 0);
        checked++;
    }
    printf("coeff vectors: OK (%d cases byte-exact)\n", checked);
}

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

static void test_encoder_vectors(const char* path)
{
    VecReader r(path);
    r.header(2);
    // Config is encoded in the scenario: deadline 30ms always; overhead from
    // the file's param field re-read here:
    fseek(r.f, 12, SEEK_SET);
    uint32_t overhead_pct;
    assert(fread(&overhead_pct, 4, 1, r.f) == 1);
    swfec::SwfecEncoder enc(overhead_pct / 100.0f, 30000);
    int ops = 0, pkts_checked = 0;
    while (!r.eof()) {
        uint8_t op = r.u8();
        uint64_t now = r.u64();
        std::vector<std::vector<uint8_t> > got;
        if (op == 0) {
            uint32_t plen = r.u32();
            std::vector<uint8_t> payload(plen);
            r.bytes(payload.data(), plen);
            enc.push_source(payload.data(), plen, now, got);
        } else {
            assert(op == 1);
            enc.poll(now, got);
        }
        uint32_t expect_n = r.u32();
        assert(got.size() == expect_n);
        for (uint32_t i = 0; i < expect_n; i++) {
            uint32_t elen = r.u32();
            std::vector<uint8_t> expect(elen);
            r.bytes(expect.data(), elen);
            assert(got[i].size() == elen);
            assert(memcmp(got[i].data(), expect.data(), elen) == 0);
            pkts_checked++;
        }
        ops++;
    }
    printf("encoder vectors %s: OK (%d ops, %d packets byte-exact)\n", path, ops, pkts_checked);
}

static void test_decoder_vectors(const char* path)
{
    VecReader r(path);
    r.header(3);
    swfec::SwfecDecoder dec(30000);
    int pushes = 0, deliveries = 0;
    for (;;) {
        uint8_t op = r.u8();
        if (op == 255) break;
        assert(op == 0);
        uint64_t now = r.u64();
        uint32_t plen = r.u32();
        std::vector<uint8_t> pkt(plen);
        r.bytes(pkt.data(), plen);
        std::vector<swfec::Delivered> got;
        dec.push(pkt.data(), plen, now, got);
        uint32_t expect_n = r.u32();
        assert(got.size() == expect_n);
        for (uint32_t i = 0; i < expect_n; i++) {
            uint32_t seq = r.u32();
            uint8_t late = r.u8();
            uint32_t dlen = r.u32();
            std::vector<uint8_t> dpay(dlen);
            r.bytes(dpay.data(), dlen);
            assert(got[i].seq == seq);
            assert((uint8_t)got[i].late == late);
            assert(got[i].payload.size() == dlen);
            assert(memcmp(got[i].payload.data(), dpay.data(), dlen) == 0);
            deliveries++;
        }
        pushes++;
    }
    const swfec::DecoderStats& s = dec.stats();
    uint64_t expect_stats[6];
    for (int i = 0; i < 6; i++) expect_stats[i] = r.u64();
    assert(s.sources_received == expect_stats[0]);
    assert(s.repairs_received == expect_stats[1]);
    assert(s.repairs_redundant == expect_stats[2]);
    assert(s.recovered == expect_stats[3]);
    assert(s.abandoned == expect_stats[4]);
    assert(s.malformed == expect_stats[5]);
    printf("decoder vectors: OK (%d pushes, %d deliveries, stats exact)\n", pushes, deliveries);
}

// Self-contained roundtrip fuzz: encoder->lossy channel->decoder, seeded LCG.
// Invariants: delivered payloads byte-identical, no duplicate seqs, pivot
// state bounded by the window cap.
static uint8_t fuzz_payload_byte(uint32_t seq, size_t j) {
    return (uint8_t)(seq * 31u + (uint32_t)j * 7u + 3u);
}
static void test_fuzz_roundtrip(void)
{
    swfec::SwfecEncoder enc(0.5f, 30000);
    swfec::SwfecDecoder dec(30000);
    uint64_t lcg = 0xDEADBEEFCAFEF00DULL;
    std::map<uint32_t, bool> seen;
    for (uint32_t i = 0; i < 10000; i++) {
        size_t len = 20 + (i * 13) % 1380;
        std::vector<uint8_t> payload(len);
        for (size_t j = 0; j < len; j++) payload[j] = fuzz_payload_byte(i, j);
        std::vector<std::vector<uint8_t> > pkts;
        uint64_t now = (uint64_t)i * 1000;
        enc.push_source(payload.data(), len, now, pkts);
        for (size_t p = 0; p < pkts.size(); p++) {
            lcg = lcg * 6364136223846793005ULL + 1442695040888963407ULL;
            if ((lcg >> 33) % 100 < 20) continue;   // 20% loss
            std::vector<swfec::Delivered> out;
            dec.push(pkts[p].data(), pkts[p].size(), now + 100, out);
            for (size_t d = 0; d < out.size(); d++) {
                assert(!seen.count(out[d].seq));
                seen[out[d].seq] = true;
                size_t elen = 20 + (out[d].seq * 13) % 1380;
                assert(out[d].payload.size() == elen);
                for (size_t j = 0; j < elen; j++)
                    assert(out[d].payload[j] == fuzz_payload_byte(out[d].seq, j));
            }
        }
        assert(dec.pivot_count() <= 64);
    }
    printf("fuzz roundtrip: OK (%zu/10000 delivered, no dups, state bounded)\n", seen.size());
}

int main(void)
{
    test_gf_anchors();
    test_addmul_matches_naive();
    test_coeff_vectors("test_vectors/coeffs.bin");
    test_encoder_vectors("test_vectors/encoder_oh50.bin");
    test_encoder_vectors("test_vectors/encoder_oh150.bin");
    test_encoder_vectors("test_vectors/encoder_flush_oh30.bin");
    test_decoder_vectors("test_vectors/decoder_mixed.bin");
    test_fuzz_roundtrip();
    printf("fec_swfec_test: ALL OK\n");
    return 0;
}
