#pragma once
// -*- C++ -*-
//
// Copyright (C) 2017 - 2024 Vasily Evseenko <svpcom@p2ptech.org>

/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 3.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <unordered_map>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>
#include <string>
#include <set>
#include <string.h>
#include <stdexcept>

#include "wifibroadcast.hpp"
#include "zfex.h"

// Forward declaration for isolated packet loss notification
class PacketLossListener
{
public:
    virtual ~PacketLossListener() = default;
    virtual void on_packet_loss(uint32_t lost_count, uint32_t last_seq, uint32_t new_seq) = 0;
};

typedef enum {
    LOCAL,
    FORWARDER,
    AGGREGATOR
} rx_mode_t;

class BaseAggregator
{
public:
    virtual ~BaseAggregator(){}
    virtual void process_packet(const uint8_t *buf, size_t size, uint8_t wlan_idx, const uint8_t *antenna,
                                const int8_t *rssi, const int8_t *noise, uint16_t freq, uint8_t mcs_index,
                                uint8_t bandwidth, sockaddr_in *sockaddr) = 0;

    virtual void dump_stats(void) = 0;
};


class Forwarder : public BaseAggregator
{
public:
    Forwarder(const std::string &client_addr, int client_port, int snd_buf_size);
    virtual ~Forwarder();
    virtual void process_packet(const uint8_t *buf, size_t size, uint8_t wlan_idx, const uint8_t *antenna,
                                const int8_t *rssi, const int8_t *noise, uint16_t freq, uint8_t mcs_index,
                                uint8_t bandwidth,sockaddr_in *sockaddr);
    virtual void dump_stats(void) {}
private:
    int sockfd;
    struct sockaddr_in saddr;
};


typedef struct {
    uint64_t block_idx;
    uint8_t** fragments;
    size_t *fragment_map;
    uint8_t fragment_to_send_idx;
    uint8_t has_fragments;
    // Phase 1 Step D (plan §4.7). At interleave_depth == 1, both are
    // untouched and the master flush path runs unchanged.
    //   deadline_ms == 0: no deadline set (default; also used as the
    //       "never trip" value when interleaving is off).
    //   deadline_ms  > 0: CLOCK_MONOTONIC ms wall-time by which this
    //       block must be emitted (whatever primaries we have by then).
    //   ready:        true once the block has all k primaries
    //       available (either directly received or FEC-recovered).
    uint64_t deadline_ms;
    bool ready;
} rx_ring_item_t;


// Plan §4.2 / §4.7: RX_RING_SIZE bumped from master's 40 -> 64 to
// accommodate D up to 8 (a D-frame contains D blocks, plus slack).
// Valid at every supported depth. Memory budget quantified in
// plan §4.2: worst case fec_n=32 -> 64 * 32 * 1466 ~= 3 MB.
// Startup refuses fec_n > 32 when depth > 1, bounding the memory.
#define RX_RING_SIZE 64
#define MAX_INTERLEAVE_DEPTH 8  // ceiling per plan §4.2 bulk@60fps
static_assert(RX_RING_SIZE >= MAX_INTERLEAVE_DEPTH * 4,
              "RX_RING_SIZE must be at least 4x max interleaver depth");

// Defaults for plan §4.7 deadline computation. IPI is conservative
// for FPV operating points (MCS1..MCS7 at typical video bitrates).
// Slack covers OS scheduling jitter. Both are hard-coded for Phase 1;
// a future Phase 3 adaptive daemon may drive them through the
// control socket.
//
//   hold_off_ms = (fec_n - 1) * depth * IPI_MS + SLACK_MS
//
// At D=4, n=12: (12-1) * 4 * 2 + 5 = 93 ms.
#define WFB_RX_HOLDOFF_IPI_MS   2
#define WFB_RX_HOLDOFF_SLACK_MS 5

static inline int modN(int x, int base)
{
    return (base + (x % base)) % base;
}

class rxAntennaItem
{
public:
    rxAntennaItem(void) : count_all(0),
                          rssi_sum(0), rssi_min(0), rssi_max(0),
                          snr_sum(0), snr_min(0), snr_max(0) {}

    void log_rssi(int8_t rssi, int8_t noise){
        int8_t snr = (noise != SCHAR_MAX) ? rssi - noise : 0;

        if(count_all == 0){
            rssi_min = rssi;
            rssi_max = rssi;
            snr_min = snr;
            snr_max = snr;
        } else {
            rssi_min = std::min(rssi, rssi_min);
            rssi_max = std::max(rssi, rssi_max);
            snr_min = std::min(snr, snr_min);
            snr_max = std::max(snr, snr_max);
        }
        rssi_sum += rssi;
        snr_sum += snr;
        count_all += 1;
    }

    int32_t count_all;
    int32_t rssi_sum;
    int8_t rssi_min;
    int8_t rssi_max;
    int32_t snr_sum;
    int8_t snr_min;
    int8_t snr_max;
};

struct rxAntennaKey
{
    uint16_t freq;
    uint64_t antenna_id;
    uint8_t mcs_index;
    uint8_t bandwidth;

    bool operator==(const rxAntennaKey &other) const
    {
        return (freq == other.freq && \
                antenna_id == other.antenna_id && \
                mcs_index == other.mcs_index && \
                bandwidth == other.bandwidth);
    }
};


template <typename T>
void hash_combine(std::size_t& seed, const T& v)
{
    seed ^= std::hash<T>{}(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}


template<>
struct std::hash<rxAntennaKey>
{
    std::size_t operator()(const rxAntennaKey& k) const noexcept
    {
        std::size_t h = 0;
        hash_combine(h, k.freq);
        hash_combine(h, k.antenna_id);
        hash_combine(h, k.mcs_index);
        hash_combine(h, k.bandwidth);
        return h;
    }
};

typedef std::unordered_map<rxAntennaKey, rxAntennaItem> rx_antenna_stat_t;

class Aggregator : public BaseAggregator
{
public:
    Aggregator(const std::string &keypair, uint64_t epoch, uint32_t channel_id);
    virtual ~Aggregator();
    virtual void process_packet(const uint8_t *buf, size_t size, uint8_t wlan_idx, const uint8_t *antenna,
                                const int8_t *rssi, const int8_t *noise, uint16_t freq, uint8_t mcs_index,
                                uint8_t bandwidth, sockaddr_in *sockaddr);
    virtual void dump_stats(void);

    // Packet loss listener for immediate notifications
    void set_packet_loss_listener(PacketLossListener* listener) { packet_loss_listener_ = listener; }

    // Make stats public for android userspace receiver
    void clear_stats(void)
    {
        antenna_stat.clear();
        count_p_all = 0;
        count_b_all = 0;
        count_p_dec_err = 0;
        count_p_session = 0;
        count_p_data = 0;
        count_p_uniq.clear();
        count_p_fec_recovered = 0;
        count_p_lost = 0;
        count_p_bad = 0;
        count_p_override = 0;
        count_p_outgoing = 0;
        count_b_outgoing = 0;
        count_bursts_recovered = 0;
        count_holdoff_fired = 0;
        count_late_after_deadline = 0;
    }

    rx_antenna_stat_t antenna_stat;
    uint32_t count_p_all;
    uint32_t count_b_all;
    uint32_t count_p_dec_err;
    uint32_t count_p_session;
    uint32_t count_p_data;
    std::set<uint64_t> count_p_uniq;
    uint32_t count_p_fec_recovered;
    uint32_t count_p_lost;
    uint32_t count_p_bad;
    uint32_t count_p_override;
    uint32_t count_p_outgoing;
    uint32_t count_b_outgoing;
    // Phase 1 Step A counters. Append-only to the RX `PKT` IPC line
    // as fields #12-#14 (plan §2 Phase 4 / §2.1 stability commitment).
    // They stay at zero until Phase 1 Step D wires the deadline state
    // machine in; they are declared here now so the IPC contract
    // stabilises in this PR.
    uint32_t count_bursts_recovered;
    uint32_t count_holdoff_fired;
    uint32_t count_late_after_deadline;

protected:
    virtual void send_to_socket(const uint8_t *payload, uint16_t packet_size) = 0;

private:
    Aggregator(const Aggregator&);
    Aggregator& operator=(const Aggregator&);

    void init_fec(int k, int n);
    void deinit_fec(void);
    void send_packet(int ring_idx, int fragment_idx);
    void apply_fec(int ring_idx);
    // Phase 1 Step D (plan §4.7):
    //   recompute_hold_off_ms_: called after SESSION parse updates
    //       (fec_n, interleave_depth); sets hold_off_ms to 0 at D==1
    //       (so deadline_ms comparisons never trip under master-
    //       compatible depth).
    //   advance_front_interleaved_: emits and drops the oldest ring
    //       slots while they're either already `ready` (all k
    //       primaries decodable) or their deadline has passed.
    //       Stops at the first slot that is neither ready nor
    //       expired. Called from process_packet AND dump_stats so
    //       deadlines fire even when traffic stalls.
    void recompute_hold_off_ms_(void);
    void advance_front_interleaved_(uint64_t now_ms);
    void log_rssi(const sockaddr_in *sockaddr, uint8_t wlan_idx, const uint8_t *ant, const int8_t *rssi,
                  const int8_t *noise, uint16_t freq, uint8_t mcs_index, uint8_t bandwidth);
    int get_block_ring_idx(uint64_t block_idx);
    int rx_ring_push(void);
    // cppcheck-suppress unusedPrivateFunction
    static int get_tag(const void *buf, size_t size, uint8_t tag_id, void *value, size_t value_size);

    fec_t* fec_p;
    int fec_k;  // RS number of primary fragments in block
    int fec_n;  // RS total number of fragments in block
    uint8_t session_fec_type;  // plan §4.1 B1: stock RX would reject anything non-WFB_FEC_VDM_RS
    uint8_t interleave_depth;  // TLV_INTERLEAVE_DEPTH from last SESSION; 1 = no interleaving
    bool session_established;  // true once first valid SESSION has been seen
    // Phase 1 Step D (plan §4.7) hold-off duration for fragment
    // gathering under D > 1. 0 means "no deadline path" (D == 1,
    // master-compatible). Recomputed in recompute_hold_off_ms_
    // after every SESSION parse.
    uint32_t hold_off_ms;
    uint8_t session_hash[crypto_generichash_BYTES];

    uint32_t seq;
    rx_ring_item_t rx_ring[RX_RING_SIZE];
    int rx_ring_front; // current packet
    int rx_ring_alloc; // number of allocated entries
    uint64_t last_known_block;  //id of last known block
    uint64_t epoch; // current epoch
    const uint32_t channel_id; // (link_id << 8) + port_number

    // rx->tx keypair
    uint8_t rx_secretkey[crypto_box_SECRETKEYBYTES];
    uint8_t tx_publickey[crypto_box_PUBLICKEYBYTES];
    uint8_t session_key[crypto_aead_chacha20poly1305_KEYBYTES];

    // Packet loss listener for immediate notifications
    PacketLossListener* packet_loss_listener_ = nullptr;
};


class AggregatorUDPv4 : public Aggregator
{
public:
    AggregatorUDPv4(const std::string &client_addr, int client_port, const std::string &keypair, uint64_t epoch, uint32_t channel_id, int snd_buf_size);
    virtual ~AggregatorUDPv4();

protected:
    virtual void send_to_socket(const uint8_t *payload, uint16_t packet_size);

private:
    AggregatorUDPv4(const AggregatorUDPv4&);
    AggregatorUDPv4& operator=(const AggregatorUDPv4&);

    int sockfd;
    struct sockaddr_in saddr;
};


class AggregatorUNIX : public Aggregator
{
public:
    AggregatorUNIX(const std::string &unix_socket, const std::string &keypair, uint64_t epoch, uint32_t channel_id, int snd_buf_size);
    virtual ~AggregatorUNIX();

protected:
    virtual void send_to_socket(const uint8_t *payload, uint16_t packet_size);

private:
    AggregatorUNIX(const AggregatorUNIX&);
    AggregatorUNIX& operator=(const AggregatorUNIX&);

    int sockfd;
    struct sockaddr_un saddr;
};


class Receiver
{
public:
    Receiver(const char* wlan, int wlan_idx, uint32_t channel_id, BaseAggregator* agg, int rcv_buf_size);
    ~Receiver();
    void loop_iter(void);
    int getfd(void){ return fd; }
private:
    int wlan_idx;
    BaseAggregator *agg;
    int fd;
    pcap_t *ppcap;
};
