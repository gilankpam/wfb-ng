// src/wire_capture.cpp — Gate G2 structural wire-diff tool.
//
// Drives a Transmitter with a deterministic payload sequence and
// dumps one line per injected wire packet in a text format stable
// enough to diff between pre-Phase-2a and post-Phase-2a builds.
//
// Compares: packet_type, data_nonce (DATA packets only), frame size.
// Skips: session-packet nonce + every ciphertext byte. These depend on
// libsodium's non-deterministic randombytes_buf for session_key and
// session_nonce, so they differ between runs even with identical code.
// Frame SIZE is deterministic for both DATA and SESSION packets.

// tx.hpp has inline subclass bodies that reference a lot of platform
// headers (if_packet.h, ioctl.h, net/if.h, ...) plus unqualified
// runtime_error / vector / assert. Match tx.cpp's include block so
// wire_capture.cpp compiles against the same set of dependencies.
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
#include <inttypes.h>
#include <string>
#include <memory>
#include <vector>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <endian.h>
#include <sodium.h>

using namespace std;

#include "zfex.h"
#include "wifibroadcast.hpp"
#include "tx.hpp"

class CapturingTransmitter : public Transmitter {
public:
    CapturingTransmitter(const fec_params_t& p, const string& keypair,
                         vector<tags_item_t>& tags)
        : Transmitter(p, keypair,
                      /*epoch=*/0xdeadbeef,
                      /*channel_id=*/0x12345678,
                      /*fec_delay=*/0,
                      tags) {}

    void select_output(int) override {}
    void dump_stats(uint64_t, uint32_t&, uint32_t&, uint32_t&) override {}
    void update_radiotap_header(radiotap_header_t&) override {}
    radiotap_header_t get_radiotap_header() override { return radiotap_header_t{}; }

    vector<vector<uint8_t>> sent;

protected:
    void inject_packet(const uint8_t* buf, size_t size) override {
        sent.emplace_back(buf, buf + size);
    }
    void set_mark(uint32_t) override {}
};

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <keypair_file>\n", argv[0]);
        return 1;
    }
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    vector<tags_item_t> tags;
    fec_params_t p = {WFB_FEC_VDM_RS, 8, 12, 0, 0, 0};
    CapturingTransmitter tx(p, argv[1], tags);

    // Session announce, then 3 blocks worth of deterministic payloads:
    // 24 sources of 256 bytes, each filled with a rolling byte marker.
    // That yields 24 DATA sources + 3 blocks' worth of 4 parity
    // packets each (at n - k = 4), so 24 + 12 = 36 DATA frames plus
    // one SESSION frame from send_session_key.
    tx.send_session_key();
    uint8_t payload[256];
    for (int i = 0; i < 24; i++) {
        memset(payload, (uint8_t)i, sizeof(payload));
        tx.send_packet(payload, sizeof(payload), 0);
    }

    for (size_t i = 0; i < tx.sent.size(); i++) {
        const auto& pkt = tx.sent[i];
        if (pkt.empty()) {
            printf("EMPTY\n");
            continue;
        }
        const uint8_t ptype = pkt[0];
        if (ptype == WFB_PACKET_DATA && pkt.size() >= sizeof(wblock_hdr_t)) {
            const wblock_hdr_t* h = (const wblock_hdr_t*)pkt.data();
            uint64_t nonce = be64toh(h->data_nonce);
            printf("DATA    nonce=%016" PRIx64 " size=%zu\n", nonce, pkt.size());
        } else if (ptype == WFB_PACKET_SESSION) {
            // nonce + ciphertext vary run-to-run (random session_nonce,
            // random session_key). Only size is structurally comparable.
            printf("SESSION size=%zu\n", pkt.size());
        } else {
            printf("OTHER   type=0x%02x size=%zu\n", ptype, pkt.size());
        }
    }
    return 0;
}
