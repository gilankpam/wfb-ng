// -*- C++ -*-
//
// Block-FEC characterization harness for wfb-ng (Phase 1b, pre sliding-window).
// See doc/FEC_BASELINE.md for what each TEST_CASE measures and why.
//
// This file uses the existing virtual seams in Transmitter / Aggregator
// (inject_packet, send_to_socket) to observe block-FEC behavior in-process.
// No production code is modified.

#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_session.hpp>

// System headers needed before the wfb-ng headers (mirrors tx.cpp's include
// order). tx.hpp has inline method bodies that reference POSIX/Linux types
// like ifreq, sockaddr_ll, PACKET_QDISC_BYPASS, ioctl(), etc., and uses
// unqualified std:: identifiers — these must all be visible at include time.
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <sys/resource.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/random.h>
#include <inttypes.h>
#include <endian.h>
#include <sodium.h>
#include <pcap.h>

#include <cstring>
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <set>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "zfex.h"

using namespace std;  // required by tx.hpp's inline bodies

#include "wifibroadcast.hpp"

// tx.hpp and rx.hpp both declare an unqualified global `LOCAL` (in
// tx_mode_t / rx_mode_t respectively). We don't use either enum — alias
// tx.hpp's to keep the symbols out of each other's way.
#define LOCAL tx_mode_LOCAL_hack_
#include "tx.hpp"
#undef LOCAL

#include "rx.hpp"

// ---------------------------------------------------------------------------
// Test-only utilities
// ---------------------------------------------------------------------------

namespace {

constexpr uint64_t kEpoch = 1;
constexpr uint32_t kChannelId = 0x01020304;

// Generates a fresh matched keypair and writes both halves to tmpfiles:
//   tx_path: [tx_secret (32B)] [rx_public (32B)]
//   rx_path: [rx_secret (32B)] [tx_public (32B)]
// Layout mirrors what Transmitter / Aggregator read from keypair files.
struct TestKeys {
    std::string tx_path;
    std::string rx_path;
    uint8_t tx_secret[crypto_box_SECRETKEYBYTES];
    uint8_t tx_public[crypto_box_PUBLICKEYBYTES];
    uint8_t rx_secret[crypto_box_SECRETKEYBYTES];
    uint8_t rx_public[crypto_box_PUBLICKEYBYTES];

    TestKeys() {
        crypto_box_keypair(tx_public, tx_secret);
        crypto_box_keypair(rx_public, rx_secret);
        tx_path = write_pair(tx_secret, rx_public);
        rx_path = write_pair(rx_secret, tx_public);
    }

    ~TestKeys() {
        if (!tx_path.empty()) unlink(tx_path.c_str());
        if (!rx_path.empty()) unlink(rx_path.c_str());
    }

    TestKeys(const TestKeys&) = delete;
    TestKeys& operator=(const TestKeys&) = delete;

private:
    static std::string write_pair(const uint8_t* a, const uint8_t* b) {
        char tmpl[] = "/tmp/fec_baseline_key_XXXXXX";
        int fd = mkstemp(tmpl);
        REQUIRE(fd >= 0);
        REQUIRE(write(fd, a, crypto_box_SECRETKEYBYTES) == (ssize_t)crypto_box_SECRETKEYBYTES);
        REQUIRE(write(fd, b, crypto_box_PUBLICKEYBYTES) == (ssize_t)crypto_box_PUBLICKEYBYTES);
        close(fd);
        return std::string(tmpl);
    }
};


// Captures every inject_packet() call into a vector of byte-vectors.
// All other Transmitter pure-virtuals are no-ops.
class MockTransmitter : public Transmitter {
public:
    MockTransmitter(int k, int n, const std::string& keypair,
                    std::vector<tags_item_t>& tags, uint32_t fec_delay = 0)
        : Transmitter(k, n, keypair, kEpoch, kChannelId, fec_delay, tags) {}

    std::vector<std::vector<uint8_t>> sent;

    void select_output(int) override {}
    void dump_stats(uint64_t, uint32_t&, uint32_t&, uint32_t&) override {}
    void update_radiotap_header(radiotap_header_t&) override {}
    radiotap_header_t get_radiotap_header() override { return {}; }

protected:
    void inject_packet(const uint8_t* buf, size_t size) override {
        sent.emplace_back(buf, buf + size);
    }
    void set_mark(uint32_t) override {}
};


// Captures every send_to_socket() call (i.e. every payload delivered).
class MockAggregator : public Aggregator {
public:
    MockAggregator(const std::string& keypair)
        : Aggregator(keypair, kEpoch, kChannelId) {}

    std::vector<std::vector<uint8_t>> delivered;

protected:
    void send_to_socket(const uint8_t* payload, uint16_t packet_size) override {
        delivered.emplace_back(payload, payload + packet_size);
    }
};


// Records every on_packet_loss() notification from Aggregator.
class LoggingLossListener : public PacketLossListener {
public:
    struct Event {
        uint32_t lost_count;
        uint32_t last_seq;
        uint32_t new_seq;
    };
    std::vector<Event> events;

    void on_packet_loss(uint32_t lost_count, uint32_t last_seq, uint32_t new_seq) override {
        events.push_back({lost_count, last_seq, new_seq});
    }
};


// Loss filters. All are deterministic.
class LossFilter {
public:
    virtual ~LossFilter() = default;
    // Returns true to deliver, false to drop.
    virtual bool deliver(size_t tx_packet_idx, const uint8_t* buf, size_t size) = 0;
};

class PassThrough : public LossFilter {
public:
    bool deliver(size_t, const uint8_t*, size_t) override { return true; }
};

class DropIndex : public LossFilter {
public:
    DropIndex(std::initializer_list<size_t> drops) : drops_(drops) {}
    DropIndex(std::set<size_t> drops) : drops_(std::move(drops)) {}
    bool deliver(size_t idx, const uint8_t*, size_t) override {
        return drops_.find(idx) == drops_.end();
    }
private:
    std::set<size_t> drops_;
};

// Drop by parsed (block_idx, fragment_idx). Session packets always pass.
class DropFragment : public LossFilter {
public:
    DropFragment(std::initializer_list<std::pair<uint64_t, uint8_t>> drops)
        : drops_(drops.begin(), drops.end()) {}
    DropFragment(std::set<std::pair<uint64_t, uint8_t>> drops) : drops_(std::move(drops)) {}
    bool deliver(size_t, const uint8_t* buf, size_t size) override {
        if (size < sizeof(wblock_hdr_t)) return true;
        if (buf[0] != WFB_PACKET_DATA) return true;
        uint64_t nonce_be;
        std::memcpy(&nonce_be, buf + offsetof(wblock_hdr_t, data_nonce), sizeof(nonce_be));
        uint64_t nonce = be64toh(nonce_be);
        uint64_t block = nonce >> 8;
        uint8_t frag = (uint8_t)(nonce & 0xff);
        return drops_.find({block, frag}) == drops_.end();
    }
private:
    std::set<std::pair<uint64_t, uint8_t>> drops_;
};


// Replay all captured TX packets through `filter` into rx.process_packet.
// Clears tx.sent afterwards.
void run_pipeline(MockTransmitter& tx, MockAggregator& rx, LossFilter& filter) {
    uint8_t antenna[RX_ANT_MAX] = {0, 0xff, 0xff, 0xff};
    int8_t rssi[RX_ANT_MAX] = {-42, 0, 0, 0};
    int8_t noise[RX_ANT_MAX];
    std::memset(noise, SCHAR_MAX, sizeof(noise));
    noise[0] = -70;

    for (size_t i = 0; i < tx.sent.size(); i++) {
        const auto& pkt = tx.sent[i];
        if (!filter.deliver(i, pkt.data(), pkt.size())) continue;
        rx.process_packet(pkt.data(), pkt.size(),
                          /*wlan_idx=*/0, antenna, rssi, noise,
                          /*freq=*/5805, /*mcs_index=*/1, /*bandwidth=*/20,
                          /*sockaddr=*/nullptr);
    }
    tx.sent.clear();
}


// Everything a single test needs. Session key is established in the ctor
// so the RX already has the session key by the time the test body runs.
struct Fixture {
    TestKeys keys;
    std::vector<tags_item_t> empty_tags;
    MockTransmitter tx;
    MockAggregator rx;

    Fixture(int k = 8, int n = 12, uint32_t fec_delay = 0)
        : keys(),
          empty_tags(),
          tx(k, n, keys.tx_path, empty_tags, fec_delay),
          rx(keys.rx_path)
    {
        tx.send_session_key();
        PassThrough pt;
        run_pipeline(tx, rx, pt);
        REQUIRE(rx.count_p_session == 1);
    }

    // Send `count` data packets; each packet is `size` bytes of the value `seed+i`.
    void send_data(int count, size_t size, uint8_t seed = 0) {
        std::vector<uint8_t> payload(size);
        for (int i = 0; i < count; i++) {
            std::memset(payload.data(), (uint8_t)(seed + i), size);
            REQUIRE(tx.send_packet(payload.data(), size, 0) == true);
        }
    }
};


// Extract the 64-bit data_nonce from a captured TX packet (host byte order).
// Returns 0 if the buffer is too short or not a DATA packet.
uint64_t parse_data_nonce(const std::vector<uint8_t>& pkt) {
    if (pkt.size() < sizeof(wblock_hdr_t)) return 0;
    if (pkt[0] != WFB_PACKET_DATA) return 0;
    uint64_t nonce_be;
    std::memcpy(&nonce_be, pkt.data() + offsetof(wblock_hdr_t, data_nonce), sizeof(nonce_be));
    return be64toh(nonce_be);
}


// Forge a SESSION packet with fec_type == WFB_FEC_SWIN_RS (0x2), encrypted
// under the given keypair. Mirrors Transmitter::init_session's output layout.
// Used to exercise the rx.cpp:659-664 fail-closed guard without producing
// a real SWIN TX (which does not yet exist).
std::vector<uint8_t> forge_swin_session_packet(const TestKeys& keys,
                                               uint64_t epoch,
                                               uint32_t channel_id,
                                               uint8_t fec_type) {
    uint8_t plain[sizeof(wsession_data_t)];
    wsession_data_t* sd = (wsession_data_t*)plain;
    sd->epoch = htobe64(epoch);
    sd->channel_id = htobe32(channel_id);
    sd->fec_type = fec_type;
    // Use plausible block-FEC k/n so the rx.cpp:659-664 fec_type guard is the
    // only path that can reject this packet. With k=0 or n=0 the downstream
    // "Invalid FEC N/K" guards at rx.cpp:666-678 would also reject, masking
    // the absence of the SWIN guard during mutation testing.
    sd->k = 8;
    sd->n = 12;
    randombytes_buf(sd->session_key, sizeof(sd->session_key));

    std::vector<uint8_t> packet(sizeof(wsession_hdr_t) + sizeof(plain) + crypto_box_MACBYTES);
    wsession_hdr_t* hdr = (wsession_hdr_t*)packet.data();
    hdr->packet_type = WFB_PACKET_SESSION;
    randombytes_buf(hdr->session_nonce, sizeof(hdr->session_nonce));

    int rc = crypto_box_easy(packet.data() + sizeof(wsession_hdr_t),
                             plain, sizeof(plain),
                             hdr->session_nonce,
                             keys.rx_public, keys.tx_secret);
    REQUIRE(rc == 0);
    return packet;
}


// Feed a single already-formed wire packet to the aggregator.
void feed_raw(MockAggregator& rx, const uint8_t* buf, size_t size) {
    uint8_t antenna[RX_ANT_MAX] = {0, 0xff, 0xff, 0xff};
    int8_t rssi[RX_ANT_MAX] = {-42, 0, 0, 0};
    int8_t noise[RX_ANT_MAX];
    std::memset(noise, SCHAR_MAX, sizeof(noise));
    noise[0] = -70;
    rx.process_packet(buf, size, 0, antenna, rssi, noise, 5805, 1, 20, nullptr);
}


// Read a file into a string. Tiny helper for grep-style checks.
std::string slurp(const char* path) {
    std::ifstream f(path);
    REQUIRE(f.good());
    std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return s;
}

}  // namespace


// ---------------------------------------------------------------------------
// C15: PacketLossListener signature is (uint32_t, uint32_t, uint32_t).
// Design §9.4 — the sliding-window proposal would widen last two to uint64_t.
// This is a compile-time structural fact; static_assert nails it.
// ---------------------------------------------------------------------------
static_assert(std::is_same<
    decltype(&PacketLossListener::on_packet_loss),
    void (PacketLossListener::*)(uint32_t, uint32_t, uint32_t)
>::value, "PacketLossListener::on_packet_loss signature drifted");

// ---------------------------------------------------------------------------
// C10: RX_RING_SIZE is 40 and MAX_FEC_PAYLOAD is 3996.
// Design §8.1 uses these for the memory estimate.
// ---------------------------------------------------------------------------
static_assert(RX_RING_SIZE == 40, "RX_RING_SIZE changed");


// ===========================================================================
// TEST CASES
// ===========================================================================

TEST_CASE("C19 smoke: new RX decodes new TX (dir-2 of §5.7)", "[baseline][C19]") {
    Fixture f;
    f.send_data(8, 128);  // one full block
    PassThrough pt;
    run_pipeline(f.tx, f.rx, pt);

    REQUIRE(f.rx.count_p_dec_err == 0);
    REQUIRE(f.rx.delivered.size() == 8);
    for (size_t i = 0; i < 8; i++) {
        for (uint8_t b : f.rx.delivered[i]) REQUIRE(b == (uint8_t)i);
    }
}


TEST_CASE("C4 fast path: in-order no-gap stream emits synchronously, no FEC", "[baseline][C4]") {
    Fixture f;
    f.send_data(8, 128);
    PassThrough pt;
    run_pipeline(f.tx, f.rx, pt);

    REQUIRE(f.rx.delivered.size() == 8);
    REQUIRE(f.rx.count_p_fec_recovered == 0);   // no decode required
}


TEST_CASE("C1 FM1: front-block gap stalls all later fragments in same block",
          "[baseline][C1]") {
    // k=8 n=12. Drop primary frag 3 AND parity frags 8..11 of block 0.
    // RX receives frags {0,1,2,4,5,6,7} = 7 < fec_k. No FEC decode possible.
    // Fast path should emit only {0,1,2} before stalling on the gap.
    Fixture f;
    f.send_data(8, 128);
    DropFragment dropper({{0,3},{0,8},{0,9},{0,10},{0,11}});
    run_pipeline(f.tx, f.rx, dropper);

    REQUIRE(f.rx.delivered.size() == 3);           // only seqs 0,1,2
    REQUIRE(f.rx.count_p_fec_recovered == 0);      // FEC not triggered
    REQUIRE(f.rx.count_p_lost == 0);               // no gap-emitted-yet -> no loss report
}


TEST_CASE("C2 FM2: fully-received later block held behind stalled front block",
          "[baseline][C2]") {
    // Block 0 stalls on gap (as C1). Block 1 also receives only 7 primaries,
    // never reaches fec_k, so does NOT trigger the line-795 flush-and-decode
    // branch. Block 1 stays in the ring, gated on ring_idx == rx_ring_front.
    Fixture f;
    f.send_data(16, 128);  // 2 blocks
    DropFragment dropper({
        {0,3},{0,8},{0,9},{0,10},{0,11},
        {1,3},{1,8},{1,9},{1,10},{1,11},
    });
    run_pipeline(f.tx, f.rx, dropper);

    // Only block 0 frags 0..2 delivered. Nothing from block 1 escapes the ring.
    REQUIRE(f.rx.delivered.size() == 3);
    for (size_t i = 0; i < 3; i++) {
        REQUIRE(f.rx.delivered[i][0] == (uint8_t)i);   // seed matches
    }
    REQUIRE(f.rx.count_p_fec_recovered == 0);
}


TEST_CASE("C3 FM3: block-boundary burst is unrecoverable on both blocks",
          "[baseline][C3]") {
    // Contiguous 16-packet burst at wire positions 4..19 (of 24 total).
    // Block 0: primaries 0..3 kept, 4..7 lost, all parity lost ->  4 < 8.
    // Block 1: primaries 0..3 lost, 4..7 lost, parity 0..3 lost   ->  0 parity
    //   available, only primaries 0..3 kept? Actually block1 wire order is
    //   frags 0..11 at positions 12..23. Wire 12..15 = primaries 0..3 lost;
    //   16..19 = primaries 4..7 lost; 20..23 = all 4 parity kept. 4 < 8.
    // Neither block can decode.
    Fixture f;
    f.send_data(16, 128);  // 2 blocks
    std::set<size_t> burst;
    for (size_t i = 4; i <= 19; i++) burst.insert(i);
    DropIndex dropper(burst);
    run_pipeline(f.tx, f.rx, dropper);

    REQUIRE(f.rx.count_p_fec_recovered == 0);
    // Delivered count: block 0 fast-path emits frags 0..3 before gap at 4.
    // Block 1 never reaches front and cannot decode, so its kept frags (4..7
    // as parity) never surface. Exactly 4 delivered.
    REQUIRE(f.rx.delivered.size() == 4);
}


TEST_CASE("C5 ring eviction bumps count_p_override after 40+ incomplete blocks",
          "[baseline][C5]") {
    // Produce 41 full blocks on the TX side but drop all non-frag-0 packets.
    // Each block hits the ring with only fragment 0, never reaches fec_k.
    // Block 0 is LRU-evicted when block 40's fragment 0 arrives.
    Fixture f;
    const int kNumBlocks = 41;
    f.send_data(kNumBlocks * 8, 128);

    std::set<std::pair<uint64_t, uint8_t>> drops;
    for (uint64_t b = 0; b < (uint64_t)kNumBlocks; b++) {
        for (uint8_t frag = 1; frag < 12; frag++) {
            drops.insert({b, frag});
        }
    }
    DropFragment dropper(std::move(drops));
    run_pipeline(f.tx, f.rx, dropper);

    REQUIRE(f.rx.count_p_override >= 1);
}


TEST_CASE("C6 seq = block*fec_k + frag; on_packet_loss reports gap correctly",
          "[baseline][C6]") {
    // Deliver block 0 complete, skip blocks 1..4 entirely, deliver block 5
    // complete. First emission from block 5 triggers on_packet_loss with
    // last_seq=7 (last of block 0), new_seq=40 (= 5*8+0), lost=32.
    Fixture f;
    LoggingLossListener listener;
    f.rx.set_packet_loss_listener(&listener);

    f.send_data(48, 128);  // 6 blocks

    std::set<std::pair<uint64_t, uint8_t>> drops;
    for (uint64_t b = 1; b <= 4; b++) {
        for (uint8_t frag = 0; frag < 12; frag++) drops.insert({b, frag});
    }
    DropFragment dropper(std::move(drops));
    run_pipeline(f.tx, f.rx, dropper);

    REQUIRE(listener.events.size() >= 1);
    const auto& ev = listener.events.front();
    REQUIRE(ev.last_seq == 7);
    REQUIRE(ev.new_seq == 40);
    REQUIRE(ev.lost_count == 32);
}


TEST_CASE("C7 fail-closed on unknown fec_type (hand-forged SWIN session)",
          "[baseline][C7]") {
    // Before test: rx has already accepted the fixture's block session.
    // Forge session packets with fec_type values that today's RX does not
    // recognise. RX should reject at rx.cpp:659-664 with count_p_dec_err += 1
    // and leave count_p_session unchanged.
    //
    // The forged packets carry plausible (k=8, n=12) so that the SWIN guard
    // is the only path that can reject them — see forge_swin_session_packet.
    //
    // Two values are tested: 0x2 (WFB_FEC_SWIN_RS, the live concern) and 0xFE
    // (an arbitrary other unknown), to confirm the test is keyed on
    // "fec_type != WFB_FEC_VDM_RS" and not accidentally on the literal 0x2.
    const uint8_t kForgedTypes[] = { 0x02, 0xFE };
    for (uint8_t ft : kForgedTypes) {
        Fixture f;
        const uint32_t dec_err_before = f.rx.count_p_dec_err;
        const uint32_t session_before = f.rx.count_p_session;

        auto forged = forge_swin_session_packet(
            f.keys, kEpoch, kChannelId, /*fec_type=*/ft);
        feed_raw(f.rx, forged.data(), forged.size());

        REQUIRE(f.rx.count_p_dec_err == dec_err_before + 1);
        REQUIRE(f.rx.count_p_session == session_before);   // not counted as session
    }
}


TEST_CASE("C8 block-FEC nonce layout: (block<<8|frag) unique per session",
          "[baseline][C8]") {
    Fixture f;
    f.send_data(8 * 10, 128);   // 10 blocks
    PassThrough pt;
    run_pipeline(f.tx, f.rx, pt);

    // Parse and collect nonces from every captured TX DATA packet in rx input
    // via rx.count_p_uniq (keyed on full be64 data_nonce). Every distinct
    // (block_idx, fragment_idx) should appear at most once.
    REQUIRE(f.rx.count_p_uniq.size() == 12 * 10);  // n * blocks

    // Also verify layout directly on the raw TX bytes we just cleared.
    // Re-run a small scenario capturing tx.sent before it is cleared.
    Fixture g;
    g.send_data(8 * 3, 128);
    std::set<uint64_t> seen;
    size_t data_count = 0;
    for (const auto& pkt : g.tx.sent) {
        if (pkt.empty() || pkt[0] != WFB_PACKET_DATA) continue;
        uint64_t n = parse_data_nonce(pkt);
        data_count++;
        // Layout: high 56 bits = block_idx, low 8 bits = fragment_idx.
        uint64_t block = n >> 8;
        uint8_t frag = (uint8_t)(n & 0xff);
        REQUIRE(block < 3);
        REQUIRE(frag < 12);
        seen.insert(n);
    }
    REQUIRE(data_count == 12 * 3);
    REQUIRE(seen.size() == data_count);
}


TEST_CASE("C9 block path has no T_flush / count_w_flush", "[baseline][C9]") {
    std::string rx_src = slurp("src/rx.cpp");
    REQUIRE(rx_src.find("count_w_flush") == std::string::npos);
    REQUIRE(rx_src.find("T_flush") == std::string::npos);
}


TEST_CASE("C10 RX ring memory arithmetic", "[baseline][C10]") {
    REQUIRE(MAX_FEC_PAYLOAD == 3996);
    const size_t fec_n_video = 12;
    const size_t bytes = (size_t)RX_RING_SIZE * fec_n_video * MAX_FEC_PAYLOAD;
    REQUIRE(bytes == (size_t)(40 * 12 * 3996));   // 1,918,080 ≈ 1.83 MiB per design §8.1
    printf("[C10] RX ring bytes at video defaults: %zu (%.2f MiB)\n",
           bytes, bytes / 1048576.0);
}


TEST_CASE("C11 encode benchmarks (pure zfex)", "[baseline][C11][benchmark]") {
    auto bench_one = [](int k, int n, int P) {
        fec_t* fec_p = nullptr;
        fec_new(k, n, &fec_p);
        REQUIRE(fec_p != nullptr);
        std::vector<uint8_t*> block(n);
        for (int i = 0; i < n; i++) {
            int rc = posix_memalign((void**)&block[i],
                                    ZFEX_SIMD_ALIGNMENT, ZFEX_ROUND_UP_SIMD(P));
            REQUIRE(rc == 0);
            if (i < k) std::memset(block[i], (uint8_t)i, P);
        }
        BENCHMARK("encode") {
            zfex_status_code_t rc = fec_encode_simd(
                fec_p, (const uint8_t**)block.data(), block.data() + k,
                ZFEX_ROUND_UP_SIMD(P));
            REQUIRE(rc == ZFEX_SC_OK);
            return rc;
        };
        for (int i = 0; i < n; i++) free(block[i]);
        fec_free(fec_p);
    };

    SECTION("k=8 n=12 P=1400")  { bench_one(8, 12, 1400); }
    SECTION("k=4 n=8  P=1400")  { bench_one(4, 8,  1400); }
    SECTION("k=8 n=12 P=3996")  { bench_one(8, 12, 3996); }
}


TEST_CASE("C12 decode benchmark (pure zfex, 1-erasure)", "[baseline][C12][benchmark]") {
    const int k = 8, n = 12, P = 1400;
    fec_t* fec_p = nullptr;
    fec_new(k, n, &fec_p);
    std::vector<uint8_t*> block(n);
    for (int i = 0; i < n; i++) {
        int rc = posix_memalign((void**)&block[i],
                                ZFEX_SIMD_ALIGNMENT, ZFEX_ROUND_UP_SIMD(P));
        REQUIRE(rc == 0);
        if (i < k) std::memset(block[i], (uint8_t)i, P);
    }
    REQUIRE(fec_encode_simd(fec_p, (const uint8_t**)block.data(),
                            block.data() + k, ZFEX_ROUND_UP_SIMD(P)) == ZFEX_SC_OK);

    // Simulate 1 erasure: drop primary 7, replace with first parity (row k).
    uint8_t* in_ptrs[8];
    uint8_t* out_ptrs[1];
    unsigned index[8];
    for (int i = 0; i < 7; i++) { in_ptrs[i] = block[i]; index[i] = i; }
    in_ptrs[7] = block[k];  // first parity
    index[7] = k;
    out_ptrs[0] = block[7];

    BENCHMARK("decode k=8 n=12 1-erasure") {
        // Must re-zero the output each iteration; Catch2 re-runs the body.
        std::memset(block[7], 0, ZFEX_ROUND_UP_SIMD(P));
        zfex_status_code_t rc = fec_decode_simd(
            fec_p, (const uint8_t**)in_ptrs, out_ptrs, index, ZFEX_ROUND_UP_SIMD(P));
        REQUIRE(rc == ZFEX_SC_OK);
        return rc;
    };

    for (int i = 0; i < n; i++) free(block[i]);
    fec_free(fec_p);
}


TEST_CASE("C13 counter semantics: all relevant counters increment", "[baseline][C13]") {
    Fixture f;

    // Produce recovery: 1 block with 1 erasure (frag 7 dropped, parity present).
    // First 8 primaries are fed; block fills with parity, gap at 7, FEC kicks in.
    f.send_data(8, 128);
    DropFragment d1({{0, 7}});
    run_pipeline(f.tx, f.rx, d1);
    REQUIRE(f.rx.count_p_fec_recovered >= 1);

    // Produce a straddle loss to bump count_p_lost: deliver later block after
    // skipping intermediate ones. count_p_lost only increments when a DELIVERED
    // packet has packet_seq > seq+1 — i.e. a later block must actually decode.
    LoggingLossListener listener;
    f.rx.set_packet_loss_listener(&listener);
    f.send_data(6 * 8, 128);  // blocks 1..6 (block 0 was used above)
    std::set<std::pair<uint64_t, uint8_t>> drops;
    for (uint64_t b = 2; b <= 5; b++) {
        for (uint8_t fr = 0; fr < 12; fr++) drops.insert({b, fr});
    }
    DropFragment d2(std::move(drops));
    run_pipeline(f.tx, f.rx, d2);
    REQUIRE(f.rx.count_p_lost > 0);

    // Produce a ring overflow for count_p_override.
    f.send_data(41 * 8, 128);
    std::set<std::pair<uint64_t, uint8_t>> drops2;
    for (uint64_t b = 6; b < 6 + 41; b++) {
        for (uint8_t fr = 1; fr < 12; fr++) drops2.insert({b, fr});
    }
    DropFragment d3(std::move(drops2));
    run_pipeline(f.tx, f.rx, d3);

    // Dec err via hand-forged SWIN session packet.
    const uint32_t dec_err_before = f.rx.count_p_dec_err;
    auto forged = forge_swin_session_packet(f.keys, kEpoch, kChannelId, 0x2);
    feed_raw(f.rx, forged.data(), forged.size());
    REQUIRE(f.rx.count_p_dec_err == dec_err_before + 1);

    // count_p_bad via unknown packet type.
    uint8_t bad[4] = {0xFF, 0, 0, 0};
    feed_raw(f.rx, bad, sizeof(bad));

    REQUIRE(f.rx.count_p_all       > 0);
    REQUIRE(f.rx.count_b_all       > 0);
    REQUIRE(f.rx.count_p_session   >= 1);
    REQUIRE(f.rx.count_p_data      > 0);
    REQUIRE(f.rx.count_p_uniq.size() > 0);
    REQUIRE(f.rx.count_p_fec_recovered > 0);
    REQUIRE(f.rx.count_p_lost      > 0);
    REQUIRE(f.rx.count_p_override  > 0);
    REQUIRE(f.rx.count_p_outgoing  > 0);
    REQUIRE(f.rx.count_b_outgoing  > 0);
    REQUIRE(f.rx.count_p_dec_err   > 0);
    REQUIRE(f.rx.count_p_bad       > 0);
}


TEST_CASE("C14 SESSION IPC log hardcodes WFB_FEC_VDM_RS", "[baseline][C14]") {
    std::string rx_src = slurp("src/rx.cpp");
    // Look for the literal token in the SESSION IPC_MSG arg list near line 698.
    // We're not parsing C; just confirming the identifier exists and there is
    // an IPC_MSG that mentions SESSION.
    REQUIRE(rx_src.find("WFB_FEC_VDM_RS") != std::string::npos);
    const bool session_ipc_present =
        rx_src.find("\"%\" PRIu64 \"\\tSESSION") != std::string::npos ||
        rx_src.find("SESSION\\t") != std::string::npos;
    REQUIRE(session_ipc_present);
}


TEST_CASE("C16 K-sized padding: one large frag inflates n-k parity packets",
          "[baseline][C16]") {
    Fixture f;
    // Send k-1 small payloads + 1 big payload inside a single block.
    const size_t kSmall = 64;
    const size_t kBig = 1400;
    std::vector<uint8_t> small(kSmall, 0x11);
    std::vector<uint8_t> big(kBig, 0x22);
    for (int i = 0; i < 7; i++) {
        REQUIRE(f.tx.send_packet(small.data(), small.size(), 0) == true);
    }
    REQUIRE(f.tx.send_packet(big.data(), big.size(), 0) == true);

    // At this point the block has been encoded and all n=12 DATA packets
    // were injected. Find the 12 DATA packets (skip session packets) and
    // inspect the last n-k=4 (parity) sizes.
    std::vector<size_t> data_sizes;
    for (const auto& p : f.tx.sent) {
        if (!p.empty() && p[0] == WFB_PACKET_DATA) data_sizes.push_back(p.size());
    }
    REQUIRE(data_sizes.size() == 12);
    // Parity on the wire is send_block_fragment(max_packet_size) — i.e.
    //   wblock_hdr + [wpacket_hdr + big_payload] + AEAD MAC.
    // The SIMD round-up only affects the encode buffer size, not what
    // reaches inject_packet.
    const size_t parity_expected = sizeof(wblock_hdr_t)
                                   + sizeof(wpacket_hdr_t) + kBig
                                   + crypto_aead_chacha20poly1305_ABYTES;
    for (size_t i = 8; i < 12; i++) {
        REQUIRE(data_sizes[i] == parity_expected);
    }
    // Primary data packets are also padded to max of the block when emitted
    // through send_block_fragment — but the primary at fragment_idx=i is
    // only padded to sizeof(wpacket_hdr_t)+size_i on ITS own fragment write.
    // Key claim: parity packets are all max-sized (= inflated by the outlier).
    printf("[C16] parity size under (7 small + 1 big) block: %zu bytes (big=%zu)\n",
           parity_expected, kBig);
}


TEST_CASE("C17 single-primary-loss recovery on frag 7 with parity present",
          "[baseline][C17]") {
    Fixture f;
    f.send_data(8, 128);
    DropFragment dropper({{0, 7}});
    run_pipeline(f.tx, f.rx, dropper);

    REQUIRE(f.rx.delivered.size() == 8);
    REQUIRE(f.rx.count_p_fec_recovered == 1);
    // Guard against a vacuous byte-content check: if FEC decode is skipped,
    // fragments[7] stays zeroed, the wpacket_hdr's packet_size is 0, and
    // delivered[7] becomes a 0-byte vector — the loop below would then
    // iterate zero times and silently pass.
    REQUIRE(f.rx.delivered[7].size() == 128);
    // Recovered frag 7 should equal seed byte 7 across its payload.
    for (uint8_t b : f.rx.delivered[7]) REQUIRE(b == 7);
}


TEST_CASE("C18 partial-block close primitive: WFB_PACKET_FEC_ONLY injects padding + parity",
          "[baseline][C18]") {
    Fixture f;   // k=8, n=12
    const size_t sent_before = f.tx.sent.size();  // session packet

    // Send one real data packet: fragment_idx goes 0 -> 1, one inject.
    uint8_t payload[128] = {0};
    REQUIRE(f.tx.send_packet(payload, sizeof(payload), 0) == true);
    REQUIRE(f.tx.sent.size() == sent_before + 1);

    // Now loop WFB_PACKET_FEC_ONLY until it returns false (block closed).
    int close_calls = 0;
    while (f.tx.send_packet(nullptr, 0, WFB_PACKET_FEC_ONLY)) {
        close_calls++;
        REQUIRE(close_calls < 20);  // safety
    }
    // After close, total DATA packets injected = fec_n = 12.
    REQUIRE(f.tx.sent.size() == sent_before + 12);
    // Number of close-call returns that were TRUE:
    //   fragment_idx starts at 1, advances to 2..7 (6 trues with 1 inject each),
    //   then call at idx=7 advances to 8, triggers FEC -> that call injects
    //   padding + n-k parity = 5 injects, fragment_idx wraps to 0, returns true.
    //   Next call is refused (fragment_idx==0 && FEC_ONLY), returns false.
    // So close_calls == 7.
    REQUIRE(close_calls == 7);
}


TEST_CASE("C20 malformed input does not crash; valid packets still deliver",
          "[baseline][C20]") {
    Fixture f;
    const uint32_t bad_before = f.rx.count_p_bad;

    // 1) Unknown packet type (1 byte).
    uint8_t t1[1] = {0xFF};
    feed_raw(f.rx, t1, sizeof(t1));

    // 2) Short SESSION packet.
    uint8_t t2[4] = {WFB_PACKET_SESSION, 0, 0, 0};
    feed_raw(f.rx, t2, sizeof(t2));

    // 3) Short DATA packet (shorter than wblock_hdr_t + AEAD + wpacket_hdr_t).
    uint8_t t3[5] = {WFB_PACKET_DATA, 0, 0, 0, 0};
    feed_raw(f.rx, t3, sizeof(t3));

    REQUIRE(f.rx.count_p_bad >= bad_before + 3);

    // Valid packet still processes.
    f.send_data(8, 128);
    PassThrough pt;
    run_pipeline(f.tx, f.rx, pt);
    REQUIRE(f.rx.delivered.size() == 8);
}


TEST_CASE("pipeline end-to-end benchmark (encode + AEAD + ring + decode, 1-erasure)",
          "[baseline][bench]") {
    BENCHMARK("e2e pipeline 1 block, 1 erasure") {
        Fixture f;
        f.send_data(8, 1400);
        DropFragment d({{0, 7}});
        run_pipeline(f.tx, f.rx, d);
        REQUIRE(f.rx.delivered.size() == 8);
        return f.rx.delivered.size();
    };
}


int main(int argc, char* argv[]) {
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }
    printf("FEC baseline harness (block FEC, k=8 n=12 defaults)\n");
    printf("FEC acceleration: %s\n", zfex_opt);
    return Catch::Session().run(argc, argv);
}
