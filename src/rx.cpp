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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>
#include <pcap.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <linux/random.h>

#include "zfex.h"

extern "C"
{
#include "ieee80211_radiotap.h"
}

#include <string>
#include <memory>

#include "wifibroadcast.hpp"
#include "rx.hpp"

using namespace std;


Receiver::Receiver(const char *wlan, int wlan_idx, uint32_t channel_id, BaseAggregator *agg, int rcv_buf_size) : wlan_idx(wlan_idx), agg(agg)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    ppcap = pcap_create(wlan, errbuf);

    if (ppcap == NULL){
        throw runtime_error(string_format("Unable to open interface %s in pcap: %s", wlan, errbuf));
    }

    try
    {
        if (rcv_buf_size > 0 && pcap_set_buffer_size(ppcap, rcv_buf_size) != 0) throw runtime_error("set_buffer_size failed");
        if (pcap_set_snaplen(ppcap, MAX_PCAP_PACKET_SIZE) != 0) throw runtime_error("set_snaplen failed");
        if (pcap_set_promisc(ppcap, 1) != 0) throw runtime_error("set_promisc failed");
        if (pcap_set_timeout(ppcap, -1) != 0) throw runtime_error("set_timeout failed");
        if (pcap_set_immediate_mode(ppcap, 1) != 0) throw runtime_error(string_format("pcap_set_immediate_mode failed: %s", pcap_geterr(ppcap)));
        if (pcap_activate(ppcap) !=0) throw runtime_error(string_format("pcap_activate failed: %s", pcap_geterr(ppcap)));
        if (pcap_setnonblock(ppcap, 1, errbuf) != 0) throw runtime_error(string_format("set_nonblock failed: %s", errbuf));

        int link_encap = pcap_datalink(ppcap);
        struct bpf_program bpfprogram;
        string program;

        if (link_encap != DLT_IEEE802_11_RADIO) {
            throw runtime_error(string_format("unknown encapsulation on %s", wlan));
        }

        program = string_format("ether[0x0a:2]==0x5742 && ether[0x0c:4] == 0x%08x", channel_id);

        if (pcap_compile(ppcap, &bpfprogram, program.c_str(), 1, 0) == -1) {
            throw runtime_error(string_format("Unable to compile %s: %s", program.c_str(), pcap_geterr(ppcap)));
        }

        if (pcap_setfilter(ppcap, &bpfprogram) == -1) {
            throw runtime_error(string_format("Unable to set filter %s: %s", program.c_str(), pcap_geterr(ppcap)));
        }

        pcap_freecode(&bpfprogram);
        fd = pcap_get_selectable_fd(ppcap);
    }
    catch(...)
    {
        pcap_close(ppcap);
        throw;
    }
}


Receiver::~Receiver()
{
    close(fd);
    pcap_close(ppcap);
}


void Receiver::loop_iter(void)
{
    for(;;) // loop while incoming queue is not empty
    {
        struct pcap_pkthdr hdr;
        const uint8_t* pkt = pcap_next(ppcap, &hdr);

        if (pkt == NULL) {
            break;
        }

        int pktlen = hdr.caplen;
        // int pkt_rate = 0
        int ant_idx = 0;
        uint32_t freq = 0;
        uint8_t antenna[RX_ANT_MAX];
        int8_t rssi[RX_ANT_MAX];
        int8_t noise[RX_ANT_MAX];
        uint8_t flags = 0;
        bool self_injected = false;
        uint8_t mcs_index = 0;
        uint8_t bandwidth = 20;

        struct ieee80211_radiotap_iterator iterator;
        int ret = ieee80211_radiotap_iterator_init(&iterator, (ieee80211_radiotap_header*)pkt, pktlen, NULL);

        // Fill all antenna slots with 0xff (unused)
        memset(antenna, 0xff, sizeof(antenna));
        // Fill all rssi slots with minimum value
        memset(rssi, SCHAR_MIN, sizeof(rssi));
        // Fill all noise slots with maximum value
        memset(noise, SCHAR_MAX, sizeof(noise));

        while (ret == 0 && ant_idx < RX_ANT_MAX) {
            ret = ieee80211_radiotap_iterator_next(&iterator);

            if (ret)
                continue;

            /* see if this argument is something we can use */

            switch (iterator.this_arg_index)
            {
                /*
                 * You must take care when dereferencing iterator.this_arg
                 * for multibyte types... the pointer is not aligned.  Use
                 * get_unaligned((type *)iterator.this_arg) to dereference
                 * iterator.this_arg for type "type" safely on all arches.
                 */

            case IEEE80211_RADIOTAP_ANTENNA:
                antenna[ant_idx] = *(uint8_t*)(iterator.this_arg);
                ant_idx += 1;
                break;

            case IEEE80211_RADIOTAP_CHANNEL:
                // drop channel flags - they are redundant for freq to chan convertion
                freq = le32toh(*(uint32_t*)(iterator.this_arg)) & 0xffff;
                break;

            case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
                rssi[ant_idx] = *(int8_t*)(iterator.this_arg);
                break;

            case IEEE80211_RADIOTAP_DBM_ANTNOISE:
                noise[ant_idx] = *(int8_t*)(iterator.this_arg);
                break;

            case IEEE80211_RADIOTAP_FLAGS:
                flags = *(uint8_t*)(iterator.this_arg);
                break;

            case IEEE80211_RADIOTAP_TX_FLAGS:
                self_injected = true;
                break;

            case IEEE80211_RADIOTAP_MCS:
            {
                /* u8,u8,u8 */

                uint8_t mcs_have = iterator.this_arg[0];

                if (mcs_have & IEEE80211_RADIOTAP_MCS_HAVE_MCS)
                {
                    mcs_index = iterator.this_arg[2] & 0x7f;
                }

                if ((mcs_have & 1) && (iterator.this_arg[1] & 1))
                {
                    bandwidth = 40;
                }
            }
            break;

            case IEEE80211_RADIOTAP_VHT:
            {
                /* u16 known, u8 flags, u8 bandwidth, u8 mcs_nss[4], u8 coding, u8 group_id, u16 partial_aid */
                u8 known = iterator.this_arg[0];

                if(known & 0x40)
                {
                    int bwidth = iterator.this_arg[3] & 0x1f;
                    if(bwidth >= 1 && bwidth <= 3)
                    {
                        bandwidth = 40;
                    }
                    else if(bwidth >= 4 && bwidth <= 10)
                    {
                        bandwidth = 80;
                    }
                }
                mcs_index = (iterator.this_arg[4] >> 4) & 0x0f;
            }
            break;

            default:
                break;
            }
        }  /* while more rt headers */

        if (ret != -ENOENT && ant_idx < RX_ANT_MAX){
            WFB_ERR("Error parsing radiotap header!\n");
            continue;
        }

        if (self_injected)
        {
            //ignore self injected frames
            continue;
        }

        if (flags & IEEE80211_RADIOTAP_F_FCS)
        {
            pktlen -= 4;
        }

        if (flags & IEEE80211_RADIOTAP_F_BADFCS)
        {
            WFB_ERR("Got packet with bad fsc\n");
            continue;
        }

        /* discard the radiotap header part */
        pkt += iterator._max_length;
        pktlen -= iterator._max_length;

        if (pktlen > (int)sizeof(ieee80211_header))
        {
            agg->process_packet(pkt + sizeof(ieee80211_header), pktlen - sizeof(ieee80211_header),
                                wlan_idx, antenna, rssi, noise, freq, mcs_index, bandwidth, NULL);
        } else {
            WFB_ERR("Short packet (ieee header)\n");
            continue;
        }
    }
}


Aggregator::Aggregator(const string &keypair, uint64_t epoch, uint32_t channel_id) : \
    count_p_all(0), count_b_all(0), count_p_dec_err(0), count_p_session(0), count_p_data(0), count_p_fec_recovered(0),
    count_p_lost(0), count_p_bad(0), count_p_override(0), count_p_outgoing(0), count_b_outgoing(0),
    count_bursts_recovered(0), count_holdoff_fired(0), count_late_after_deadline(0),
    fec_p(NULL), fec_k(-1), fec_n(-1),
    session_fec_type(WFB_FEC_VDM_RS), interleave_depth(1), session_established(false),
    hold_off_ms(0),
    seq(0), rx_ring{}, rx_ring_front(0), rx_ring_alloc(0),
    last_known_block((uint64_t)-1), epoch(epoch), channel_id(channel_id)
{
    memset(session_key, '\0', sizeof(session_key));
    memset(session_hash, '\0', sizeof(session_hash));

    FILE *fp;
    if((fp = fopen(keypair.c_str(), "r")) == NULL)
    {
        throw runtime_error(string_format("Unable to open %s: %s", keypair.c_str(), strerror(errno)));
    }
    if (fread(rx_secretkey, crypto_box_SECRETKEYBYTES, 1, fp) != 1)
    {
        fclose(fp);
        throw runtime_error(string_format("Unable to read rx secret key: %s", strerror(errno)));
    }
    if (fread(tx_publickey, crypto_box_PUBLICKEYBYTES, 1, fp) != 1)
    {
        fclose(fp);
        throw runtime_error(string_format("Unable to read tx public key: %s", strerror(errno)));
    }
    fclose(fp);
}


Aggregator::~Aggregator()
{
    if (fec_p != NULL)
    {
        deinit_fec();
    }
}

void Aggregator::init_fec(int k, int n)
{
    assert(fec_p == NULL);
    assert(k >= 1);
    assert(n >= 1);
    assert(n < 256);
    assert(k <= n);

    fec_k = k;
    fec_n = n;

    zfex_status_code_t rc = fec_new(fec_k, fec_n, &fec_p);
    assert(rc == ZFEX_SC_OK);

    rx_ring_front = 0;
    rx_ring_alloc = 0;
    last_known_block = (uint64_t)-1;
    seq = 0;

    for(int ring_idx = 0; ring_idx < RX_RING_SIZE; ring_idx++)
    {
        rx_ring[ring_idx].block_idx = 0;
        rx_ring[ring_idx].fragment_to_send_idx = 0;
        rx_ring[ring_idx].has_fragments = 0;
        rx_ring[ring_idx].deadline_ms = 0;   // Phase 1 Step D
        rx_ring[ring_idx].ready = false;     // Phase 1 Step D
        rx_ring[ring_idx].fragments = new uint8_t*[fec_n];
        for(int i=0; i < fec_n; i++)
        {
            int _rc = posix_memalign((void**)&rx_ring[ring_idx].fragments[i], ZFEX_SIMD_ALIGNMENT, ZFEX_ROUND_UP_SIMD(MAX_FEC_PAYLOAD));
            assert(_rc == 0);
        }
        rx_ring[ring_idx].fragment_map = new size_t[fec_n];
        memset(rx_ring[ring_idx].fragment_map, '\0', fec_n * sizeof(size_t));
    }
    // interleave_depth may have been captured earlier (during the
    // same SESSION parse); recompute hold_off_ms with the new fec_n.
    recompute_hold_off_ms_();
}

void Aggregator::recompute_hold_off_ms_(void)
{
    // Plan §4.7: hold_off = (fec_n - 1) * depth * IPI_MS + SLACK_MS.
    // At depth == 1 we keep hold_off_ms at 0 so the deadline_ms
    // comparison in advance_front_interleaved_ never trips -- the
    // D=1 path goes through the existing master-compatible flush
    // logic.
    if (interleave_depth <= 1 || fec_n < 1)
    {
        hold_off_ms = 0;
    }
    else
    {
        hold_off_ms = (uint32_t)((fec_n - 1) * interleave_depth * WFB_RX_HOLDOFF_IPI_MS)
                    + (uint32_t)WFB_RX_HOLDOFF_SLACK_MS;
    }
}

void Aggregator::deinit_fec(void)
{
    assert(fec_p != NULL);

    for(int ring_idx = 0; ring_idx < RX_RING_SIZE; ring_idx++)
    {
        delete[] rx_ring[ring_idx].fragment_map;
        rx_ring[ring_idx].fragment_map = NULL;
        for(int i=0; i < fec_n; i++)
        {
            free(rx_ring[ring_idx].fragments[i]);
        }
        delete[] rx_ring[ring_idx].fragments;
        rx_ring[ring_idx].fragments = NULL;
    }

    zfex_status_code_t rc = fec_free(fec_p);
    assert(rc == ZFEX_SC_OK);
    fec_p = NULL;
    fec_k = -1;
    fec_n = -1;
}


Forwarder::Forwarder(const string &client_addr, int client_port, int snd_buf_size)
{
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) throw std::runtime_error(string_format("Error opening socket: %s", strerror(errno)));

    if (snd_buf_size > 0)
    {
        if(setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const void *)&snd_buf_size , sizeof(snd_buf_size)) !=0)
        {
            close(sockfd);
            throw runtime_error(string_format("Unable to set SO_SNDBUF: %s", strerror(errno)));
        }
    }

    memset(&saddr, '\0', sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = inet_addr(client_addr.c_str());
    saddr.sin_port = htons((unsigned short)client_port);
}


void Forwarder::process_packet(const uint8_t *buf, size_t size, uint8_t wlan_idx, const uint8_t *antenna,
                               const int8_t *rssi, const int8_t *noise, uint16_t freq, uint8_t mcs_index,
                               uint8_t bandwidth, sockaddr_in *sockaddr)
{
    wrxfwd_t fwd_hdr = { .wlan_idx = wlan_idx,
                         .freq = htons(freq),
                         .mcs_index = mcs_index,
                         .bandwidth = bandwidth };

    memcpy(fwd_hdr.antenna, antenna, RX_ANT_MAX * sizeof(uint8_t));
    memcpy(fwd_hdr.rssi, rssi, RX_ANT_MAX * sizeof(int8_t));
    memcpy(fwd_hdr.noise, noise, RX_ANT_MAX * sizeof(int8_t));

    struct iovec iov[2] = {{ .iov_base = (void*)&fwd_hdr,
                             .iov_len = sizeof(fwd_hdr)},
                           { .iov_base = (void*)buf,
                             .iov_len = size }};

    struct msghdr msghdr = { .msg_name = &saddr,
                             .msg_namelen = sizeof(saddr),
                             .msg_iov = iov,
                             .msg_iovlen = 2,
                             .msg_control = NULL,
                             .msg_controllen = 0,
                             .msg_flags = 0 };

    sendmsg(sockfd, &msghdr, MSG_DONTWAIT);
}


Forwarder::~Forwarder()
{
    close(sockfd);
}

int Aggregator::rx_ring_push(void)
{
    if(rx_ring_alloc < RX_RING_SIZE)
    {
        int idx = modN(rx_ring_front + rx_ring_alloc, RX_RING_SIZE);
        rx_ring_alloc += 1;
        return idx;
    }

    /*
      Ring overflow. This means that there are more unfinished blocks than ring size
      Possible solutions:
      1. Increase ring size. Do this if you have large variance of packet travel time throught WiFi card or network stack.
         Some cards can do this due to packet reordering inside, diffent chipset and/or firmware or your RX hosts have different CPU power.
      2. Reduce packet injection speed or try to unify RX hardware.
    */

    WFB_DBG("AGG: Override block 0x%" PRIx64 " flush %d fragments\n", rx_ring[rx_ring_front].block_idx, rx_ring[rx_ring_front].has_fragments);

    count_p_override += 1;

    for(int f_idx=rx_ring[rx_ring_front].fragment_to_send_idx; f_idx < fec_k; f_idx++)
    {
        if(rx_ring[rx_ring_front].fragment_map[f_idx])
        {
            send_packet(rx_ring_front, f_idx);
        }
    }

    // override last item in ring
    int ring_idx = rx_ring_front;
    rx_ring_front = modN(rx_ring_front + 1, RX_RING_SIZE);
    return ring_idx;
}


int Aggregator::get_block_ring_idx(uint64_t block_idx)
{
    // check if block is already in the ring
    for(int i = rx_ring_front, c = rx_ring_alloc; c > 0; i = modN(i + 1, RX_RING_SIZE), c--)
    {
        if (rx_ring[i].block_idx == block_idx) return i;
    }

    // check if block is already known and not in the ring then it is already processed
    if (last_known_block != (uint64_t)-1 && block_idx <= last_known_block)
    {
        return -1;
    }

    int new_blocks = (int)min(last_known_block != (uint64_t)-1 ? block_idx - last_known_block : 1, (uint64_t)RX_RING_SIZE);
    assert (new_blocks > 0);

    last_known_block = block_idx;
    int ring_idx = -1;

    const uint64_t now_ms = get_time_ms();
    for(int i = 0; i < new_blocks; i++)
    {
        ring_idx = rx_ring_push();
        rx_ring[ring_idx].block_idx = block_idx + i + 1 - new_blocks;
        rx_ring[ring_idx].fragment_to_send_idx = 0;
        rx_ring[ring_idx].has_fragments = 0;
        rx_ring[ring_idx].ready = false;
        // Phase 1 Step D: set the deadline on creation when
        // interleaving is active. Plan §4.7 says "first fragment
        // arrival" but new_blocks > 1 happens when the RX jumps
        // forward past gaps; those jumped-past slots never see a
        // fragment, so anchoring the deadline at creation gives
        // them a way to age out. At hold_off_ms == 0 (D == 1) the
        // field stays 0 and the master-compatible flush path runs
        // unchanged.
        rx_ring[ring_idx].deadline_ms = (hold_off_ms > 0) ? now_ms + hold_off_ms : 0;
        memset(rx_ring[ring_idx].fragment_map, '\0', fec_n * sizeof(size_t));
    }
    return ring_idx;
}

void Aggregator::dump_stats(void)
{
    //timestamp in ms
    uint64_t ts = get_time_ms();

    // Phase 1 Step D: no-traffic fallback for deadline-driven
    // emission. At D == 1 this is a no-op (hold_off_ms == 0 keeps
    // the deadline check from tripping); at D > 1 it guarantees
    // pending blocks emit within ~log_interval of their deadline
    // even if no new fragments arrive to drive the sweep via
    // process_packet.
    if (interleave_depth > 1)
    {
        advance_front_interleaved_(ts);
    }

    for(auto it = antenna_stat.begin(); it != antenna_stat.end(); it++)
    {
        IPC_MSG("%" PRIu64 "\tRX_ANT\t%u:%u:%u\t%" PRIx64 "\t%d" ":%d:%d:%d" ":%d:%d:%d\n",
                ts, it->first.freq, it->first.mcs_index, it->first.bandwidth, it->first.antenna_id, it->second.count_all,
                it->second.rssi_min, it->second.rssi_sum / it->second.count_all, it->second.rssi_max,
                it->second.snr_min, it->second.snr_sum / it->second.count_all, it->second.snr_max);
    }

    // PKT line schema. Fields #1-#11 are the master layout.
    // #12-#14 (Phase 1 Step A) are always appended; they sit at
    // zero until Step D wires the deadline state machine. Parsers
    // keyed on the first 11 fields remain compatible.
    IPC_MSG("%" PRIu64 "\tPKT\t%u:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u\n", ts,
            count_p_all, count_b_all,                    // incoming         #1-2
            count_p_dec_err,                             // decryption       #3
            count_p_session, count_p_data,               // classification   #4-5
            (uint32_t)count_p_uniq.size(),               // unique check     #6
            count_p_fec_recovered, count_p_lost,         // fec recovering   #7-8
            count_p_bad,                                 // internal errors  #9
            count_p_outgoing, count_b_outgoing,          // outgoing         #10-11
            count_bursts_recovered,                      // Phase 1          #12
            count_holdoff_fired,                         // Phase 1          #13
            count_late_after_deadline);                  // Phase 1          #14

    // Phase 1 Step A (plan §B2 bootstrap): re-emit SESSION once per
    // log_interval so an adaptive daemon joining mid-stream can read
    // (epoch, fec_type, k, n, depth, contract_version) without
    // waiting for a session-key rotation. Master's on-change emit at
    // SESSION_KEY arrival still fires as before; this one is
    // additive.
    if (session_established)
    {
        IPC_MSG("%" PRIu64 "\tSESSION\t%" PRIu64 ":%u:%d:%d:%u:%u\n",
                ts, epoch, session_fec_type, fec_k, fec_n,
                interleave_depth, (unsigned)WFB_IPC_CONTRACT_VERSION);
    }
    IPC_MSG_SEND();

    if(count_p_override)
    {
        WFB_ERR("%u block overrides\n", count_p_override);
    }

    if(count_p_lost)
    {
        WFB_ERR("%u packets lost\n", count_p_lost);
    }

    clear_stats();
}


void Aggregator::log_rssi(const sockaddr_in *sockaddr, uint8_t wlan_idx, const uint8_t *ant, const int8_t *rssi, const int8_t *noise,
                          uint16_t freq, uint8_t mcs_index, uint8_t bandwidth)
{
    for(int i = 0; i < RX_ANT_MAX && ant[i] != 0xff; i++)
    {
        // antenna_id: addr + port + wlan_idx + ant
        rxAntennaKey key = {.freq = freq,
                            .antenna_id = 0,
                            .mcs_index=mcs_index,
                            .bandwidth=bandwidth};

        if (sockaddr != NULL && sockaddr->sin_family == AF_INET)
        {
            // We ignore port here because for the one host (wlan_idx, antenna_id) will be unique key for all forwarder processes.
            key.antenna_id = ((uint64_t)ntohl(sockaddr->sin_addr.s_addr) << 32);
        }

        key.antenna_id |= ((uint64_t)wlan_idx << 8 | (uint64_t)ant[i]);

        antenna_stat[key].log_rssi(rssi[i], noise[i]);
    }
}

// cppcheck-suppress unusedFunction
int Aggregator::get_tag(const void *buf, size_t size, uint8_t tag_id, void *value, size_t value_size)
{
    tlv_hdr_t *p = (tlv_hdr_t*)buf;
    void *end = (uint8_t*)buf + size;

    while((void*)(p + 1) <= end)
    {
        if(p->id != tag_id)
        {
            p = (tlv_hdr_t*)((uint8_t*)(p + 1) + p->len);
            continue;
        }
        if(p->len > value_size) return -1;
        if(p->value + p->len > end) return -1;
        memcpy(value, p->value, p->len);
        return p->len;
    }

    return -1;
}

void Aggregator::process_packet(const uint8_t *buf, size_t size, uint8_t wlan_idx, const uint8_t *antenna,
                                const int8_t *rssi, const int8_t *noise, uint16_t freq, uint8_t mcs_index,
                                uint8_t bandwidth, sockaddr_in *sockaddr)
{
    uint8_t session_tmp[MAX_SESSION_PACKET_SIZE - crypto_box_MACBYTES - sizeof(wsession_hdr_t)];
    uint8_t new_session_hash[sizeof(session_hash)];

    wsession_data_t* new_session_data = NULL;
    //size_t new_session_tags_size = 0;

    count_p_all += 1;
    count_b_all += size;

    if(size == 0) return;

    if (size > MAX_FORWARDER_PACKET_SIZE)
    {
        WFB_ERR("Long packet (fec payload)\n");
        count_p_bad += 1;
        return;
    }

    switch(buf[0])
    {
    case WFB_PACKET_DATA:
        if(size < sizeof(wblock_hdr_t) + crypto_aead_chacha20poly1305_ABYTES + sizeof(wpacket_hdr_t))
        {
            WFB_ERR("Short packet (fec header)\n");
            count_p_bad += 1;
            return;
        }
        break;

    case WFB_PACKET_SESSION:
        new_session_data = (wsession_data_t*)session_tmp;

        if(size < sizeof(wsession_hdr_t) + sizeof(wsession_data_t) + crypto_box_MACBYTES || \
           size > MAX_SESSION_PACKET_SIZE)
        {
            WFB_ERR("Invalid session key packet\n");
            count_p_bad += 1;
            return;
        }

        if(crypto_generichash(new_session_hash,
                              sizeof(new_session_hash),
                              buf + sizeof(wsession_hdr_t),
                              size - sizeof(wsession_hdr_t),
                              ((wsession_hdr_t*)buf)->session_nonce,
                              sizeof(((wsession_hdr_t*)buf)->session_nonce)) != 0)
        {
            // Should newer happened
            assert(0);
        }

        if (memcmp(session_hash, new_session_hash, sizeof(session_hash)) == 0)
        {
            // Session is equal to current so we can ignore it
            count_p_session += 1;
            return;
        }

        if(crypto_box_open_easy((uint8_t*)session_tmp,
                                buf + sizeof(wsession_hdr_t),
                                size - sizeof(wsession_hdr_t),
                                ((wsession_hdr_t*)buf)->session_nonce,
                                tx_publickey, rx_secretkey) != 0)
        {
            WFB_ERR("Unable to decrypt session key\n");
            count_p_dec_err += 1;
            return;
        }

        //new_session_tags_size = size - (sizeof(wsession_hdr_t) + sizeof(wsession_data_t) + crypto_box_MACBYTES);

        if (be64toh(new_session_data->epoch) < epoch)
        {
            WFB_ERR("Session epoch doesn't match: %" PRIu64 " < %" PRIu64 "\n", be64toh(new_session_data->epoch), epoch);
            count_p_dec_err += 1;
            return;
        }

        if (be32toh(new_session_data->channel_id) != channel_id)
        {
            WFB_ERR("Session channel_id doesn't match: %u != %u\n", be32toh(new_session_data->channel_id), channel_id);
            count_p_dec_err += 1;
            return;
        }

        // Phase 1 Step D: accept the interleaved variant (plan §4.1
        // B1 / v2.1 R3). Fully supported on this RX because the
        // deadline state machine below handles D > 1.
        if (new_session_data->fec_type != WFB_FEC_VDM_RS &&
            new_session_data->fec_type != WFB_FEC_VDM_RS_INTERLEAVED)
        {
            WFB_ERR("Unsupported FEC codec type: %d\n", new_session_data->fec_type);
            count_p_dec_err += 1;
            return;
        }

        if (new_session_data->n < 1)
        {
            WFB_ERR("Invalid FEC N: %d\n", new_session_data->n);
            count_p_dec_err += 1;
            return;
        }

        if (new_session_data->k < 1 || new_session_data->k > new_session_data->n)
        {
            WFB_ERR("Invalid FEC K: %d\n", new_session_data->k);
            count_p_dec_err += 1;
            return;
        }

        count_p_session += 1;

        // Ignore RSSI (and per-card rx counters) for session packets to simplify calculation
        // of lost packets because session packets doesn't have any serial number and it is
        // too hard to calculate number of unique session packets

        // Phase 1 Step A: record the fec_type the peer advertised and
        // parse TLV_INTERLEAVE_DEPTH from the SESSION tags (if any).
        // Step A does NOT accept WFB_FEC_VDM_RS_INTERLEAVED for data
        // packet processing (the deadline state machine arrives in
        // Step D); the check above at "Unsupported FEC codec type"
        // still rejects 0x2. These fields are captured for the
        // SESSION IPC line only.
        session_fec_type = new_session_data->fec_type;
        {
            // The decrypted buffer starts at `session_tmp`, with
            // total length `size - sizeof(wsession_hdr_t) -
            // crypto_box_MACBYTES`. The fixed wsession_data_t header
            // sits at the start; anything trailing is a TLV stream.
            const size_t decrypted_len =
                size - sizeof(wsession_hdr_t) - crypto_box_MACBYTES;
            const uint8_t* tags_buf = (const uint8_t*)new_session_data + sizeof(wsession_data_t);
            const size_t tags_size = (decrypted_len > sizeof(wsession_data_t))
                ? decrypted_len - sizeof(wsession_data_t) : 0;
            uint8_t advertised_depth = 1;
            if (tags_size >= sizeof(tlv_hdr_t)) {
                // get_tag() returns the TLV's len on match, -1 otherwise.
                // At depth=1 no TLV is emitted by our TX, so this
                // stays at the default of 1.
                int rc = get_tag(tags_buf, tags_size,
                                 TLV_INTERLEAVE_DEPTH,
                                 &advertised_depth, sizeof(advertised_depth));
                if (rc < 0) advertised_depth = 1;
            }
            interleave_depth = advertised_depth;
        }
        // Phase 1 Step D: depth may have changed (either initial
        // session or a 1C refresh). Recompute hold_off_ms so
        // advance_front_interleaved_ uses the new deadline window.
        // If fec_n isn't yet set (very first session), init_fec
        // will call recompute_hold_off_ms_ again with the actual
        // fec_n.
        recompute_hold_off_ms_();

        if (memcmp(session_key, new_session_data->session_key, sizeof(session_key)) != 0)
        {
            // Full rekey path (unchanged from master): new
            // session_key means a fresh Transmitter process or a
            // (pre-1C-era) init_session. Reset FEC and epoch.
            epoch = be64toh(new_session_data->epoch);
            memcpy(session_key, new_session_data->session_key, sizeof(session_key));

            if (fec_p != NULL)
            {
                deinit_fec();
            }

            init_fec(new_session_data->k, new_session_data->n);

            // Trailing fields #5 (interleave_depth) and #6
            // (contract_version) are Phase 1 additions. Parsers
            // that only read the first 4 (epoch, fec_type, k, n)
            // stay compatible.
            IPC_MSG("%" PRIu64 "\tSESSION\t%" PRIu64 ":%u:%d:%d:%u:%u\n",
                    get_time_ms(), epoch, session_fec_type, fec_k, fec_n,
                    interleave_depth, (unsigned)WFB_IPC_CONTRACT_VERSION);
            IPC_MSG_SEND();
            session_established = true;
        }
        else if (fec_p != NULL &&
                 (fec_k != (int)new_session_data->k ||
                  fec_n != (int)new_session_data->n))
        {
            // Plan v2.1 R1 (1C) refresh: same session_key, but the
            // peer advertised a new (k, n). Reinitialize our FEC
            // state to the new parameters. block_idx keeps going
            // (the TX preserves it too for nonce uniqueness), so
            // old in-flight blocks in the rx ring may be
            // unrecoverable if they had the old codec mid-way --
            // RX's deadline sweep in Step D will age them out; at
            // Step C they're discarded implicitly when init_fec
            // wipes rx_ring state via deinit_fec().
            deinit_fec();
            init_fec(new_session_data->k, new_session_data->n);

            IPC_MSG("%" PRIu64 "\tSESSION\t%" PRIu64 ":%u:%d:%d:%u:%u\n",
                    get_time_ms(), epoch, session_fec_type, fec_k, fec_n,
                    interleave_depth, (unsigned)WFB_IPC_CONTRACT_VERSION);
            IPC_MSG_SEND();
        }

        // Cache already processed session
        memcpy(session_hash, new_session_hash, sizeof(session_hash));

        return;

    default:
        WFB_ERR("Unknown packet type 0x%x\n", buf[0]);
        count_p_bad += 1;
        return;
    }

    uint8_t decrypted[MAX_FEC_PAYLOAD];
    unsigned long long decrypted_len;
    wblock_hdr_t *block_hdr = (wblock_hdr_t*)buf;

    if (crypto_aead_chacha20poly1305_decrypt(decrypted, &decrypted_len,
                                             NULL,
                                             buf + sizeof(wblock_hdr_t), size - sizeof(wblock_hdr_t),
                                             buf,
                                             sizeof(wblock_hdr_t),
                                             (uint8_t*)(&(block_hdr->data_nonce)), session_key) != 0)
    {
        WFB_ERR("Unable to decrypt packet #0x%" PRIx64 "\n", be64toh(block_hdr->data_nonce));
        count_p_dec_err += 1;
        return;
    }

    count_p_data += 1;
    log_rssi(sockaddr, wlan_idx, antenna, rssi, noise, freq, mcs_index, bandwidth);

    assert(decrypted_len >= sizeof(wpacket_hdr_t));
    assert(decrypted_len <= MAX_FEC_PAYLOAD);

    uint64_t block_idx = be64toh(block_hdr->data_nonce) >> 8;
    uint8_t fragment_idx = (uint8_t)(be64toh(block_hdr->data_nonce) & 0xff);

    count_p_uniq.insert(be64toh(block_hdr->data_nonce));

    // Should never happend due to generating new session key on tx side
    if (block_idx > MAX_BLOCK_IDX)
    {
        WFB_ERR("block_idx overflow\n");
        count_p_bad += 1;
        return;
    }

    if (fragment_idx >= fec_n)
    {
        WFB_ERR("Invalid fragment_idx: %d\n", fragment_idx);
        count_p_bad += 1;
        return;
    }

    int ring_idx = get_block_ring_idx(block_idx);

    //ignore already processed blocks
    if (ring_idx < 0)
    {
        // Phase 1 Step D: a fragment arriving for a block that has
        // already been retired from the ring. Under D == 1 the
        // master behaviour is "already flushed via force-flush";
        // under D > 1 it is "arrived after our deadline expired."
        // The counter captures the latter; at D == 1 we keep it at
        // 0 to not change the visible IPC numbers.
        if (interleave_depth > 1)
        {
            count_late_after_deadline += 1;
        }
        return;
    }

    rx_ring_item_t *p = &rx_ring[ring_idx];

    //ignore already processed fragments
    if (p->fragment_map[fragment_idx]) return;

    memset(p->fragments[fragment_idx], '\0', MAX_FEC_PAYLOAD);
    memcpy(p->fragments[fragment_idx], decrypted, decrypted_len);

    p->fragment_map[fragment_idx] = decrypted_len;
    p->has_fragments += 1;

    // =================================================================
    // Phase 1 Step D branch point (plan §4.7).
    //
    // At interleave_depth == 1 the master block-emit logic runs
    // unchanged: early-emit fast path when ring_idx == front; force-
    // flush older blocks when a later block reaches k fragments.
    // This is Invariant A from plan §1.1 and the critical "wire-
    // identical to master" property for the default configuration.
    //
    // At interleave_depth > 1 the early-emit fast path is disabled
    // (fragments of earlier blocks are in-flight out of their
    // natural order -- emitting fragment f of the front block does
    // NOT mean the block is complete). Instead:
    //   - on k-fragment completion, FEC-recover any missing
    //     primaries and mark the slot `ready`;
    //   - call advance_front_interleaved_ to drain any consecutive
    //     run of ready slots from the front, AND any slots whose
    //     deadline has expired.
    // This preserves in-order delivery (blocks emitted in
    // block_idx order) while the block interleaver shuffles
    // fragments on the wire.
    // =================================================================
    if (interleave_depth == 1)
    {
        // ----- MASTER PATH (unchanged from rx.cpp:891-942 prior) -----
        // Check if we use current (oldest) block
        // then we can optimize and don't wait for all K fragments
        // and send packets if there are no gaps in fragments from the beginning of this block
        if(ring_idx == rx_ring_front)
        {
            // check if there are any packets without gaps
            // and send them immediately
            while(p->fragment_to_send_idx < fec_k && p->fragment_map[p->fragment_to_send_idx])
            {
                send_packet(ring_idx, p->fragment_to_send_idx);
                p->fragment_to_send_idx += 1;
            }

            // remove block if all K elements (without gaps) were sent
            if(p->fragment_to_send_idx == fec_k)
            {
                rx_ring_front = modN(rx_ring_front + 1, RX_RING_SIZE);
                rx_ring_alloc -= 1;
                assert(rx_ring_alloc >= 0);
                return;
            }
        }

        // Check that this block has K elements (with gaps) and can be recovered via FEC
        if(p->fragment_to_send_idx < fec_k && p->has_fragments == fec_k)
        {
            // send all queued packets in all unfinished blocks before current
            // and then remove that blocks
            int nrm = modN(ring_idx - rx_ring_front, RX_RING_SIZE);

            while(nrm > 0)
            {
                for(int f_idx=rx_ring[rx_ring_front].fragment_to_send_idx; f_idx < fec_k; f_idx++)
                {
                    if(rx_ring[rx_ring_front].fragment_map[f_idx])
                    {
                        send_packet(rx_ring_front, f_idx);
                    }
                }
                rx_ring_front = modN(rx_ring_front + 1, RX_RING_SIZE);
                rx_ring_alloc -= 1;
                nrm -= 1;
            }

            assert(rx_ring_alloc > 0);
            assert(ring_idx == rx_ring_front);

            // Search for missed data fragments and apply FEC only if needed
            for(int f_idx=p->fragment_to_send_idx; f_idx < fec_k; f_idx++)
            {
                if(! p->fragment_map[f_idx])
                {
                    uint32_t fec_count = 0;

                    //Recover missed fragments using FEC
                    apply_fec(ring_idx);

                    // Count total number of recovered fragments
                    for(; f_idx < fec_k; f_idx++)
                    {
                        if(! p->fragment_map[f_idx])
                        {
                            fec_count += 1;
                        }
                    }

                    if(fec_count)
                    {
                        count_p_fec_recovered += fec_count;
                        WFB_DBG("FEC recovered %u packets\n", fec_count);
                    }
                    break;
                }
            }

            while(p->fragment_to_send_idx < fec_k)
            {
                send_packet(ring_idx, p->fragment_to_send_idx);
                p->fragment_to_send_idx += 1;
            }

            // remove block
            rx_ring_front = modN(rx_ring_front + 1, RX_RING_SIZE);
            rx_ring_alloc -= 1;
            assert(rx_ring_alloc >= 0);
        }
        return;
    }

    // ----- INTERLEAVED PATH (plan §4.7 state machine) -----
    //
    // Block-complete detection: the first time this block reaches
    // has_fragments == fec_k, recover any missing primaries and
    // mark the slot ready. Subsequent fragment arrivals (extra
    // parity beyond k) do not re-trigger this branch because ready
    // latches once set. Re-processing would be wasted work AND
    // could double-count fec_recovered metrics.
    if (!p->ready && p->has_fragments == (uint8_t)fec_k)
    {
        // Check which primaries are missing; if any, apply_fec.
        int missing_primaries = 0;
        for (int f = 0; f < fec_k; f++)
        {
            if (!p->fragment_map[f]) missing_primaries += 1;
        }
        if (missing_primaries > 0)
        {
            apply_fec(ring_idx);
            count_p_fec_recovered += missing_primaries;
            // Plan §3.7 non-blocking #3: count a block as a
            // "burst recovery" when FEC recovered at least half of
            // the parity budget worth of primaries in one block --
            // a proxy for "recovered a burst hit." Threshold
            // matches the plan's ceil((n-k)/2) definition.
            if (missing_primaries >= (fec_n - fec_k + 1) / 2)
            {
                count_bursts_recovered += 1;
            }
            WFB_DBG("FEC recovered %d packets (D>1)\n", missing_primaries);
        }
        p->ready = true;
    }

    // Try to drain any consecutive ready-or-expired slots from the
    // front. Called here so a block completing mid-ring can emit
    // itself as soon as the front catches up. Called again on
    // dump_stats and at process_packet entry for the no-traffic /
    // mid-gap cases.
    advance_front_interleaved_(get_time_ms());
}

void Aggregator::advance_front_interleaved_(uint64_t now_ms)
{
    // Plan §4.7 periodic sweep + in-order emit. Walks the ring from
    // rx_ring_front forward. For each slot:
    //   - READY: FEC recovery already ran (or block had all
    //     primaries natively). Emit remaining primaries, advance
    //     front.
    //   - DEADLINE EXPIRED: emit whatever primaries we have (no
    //     FEC; we're past the reasonable wait window), bump
    //     count_holdoff_fired, advance front.
    //   - OTHERWISE: stop -- the slot is still accumulating and
    //     hasn't aged out yet.
    // Emissions remain in block_idx order even though the TX has
    // interleaved their fragment emissions.
    while (rx_ring_alloc > 0)
    {
        rx_ring_item_t& fp = rx_ring[rx_ring_front];

        if (fp.ready)
        {
            // Block is complete and ready to emit.
            while (fp.fragment_to_send_idx < fec_k)
            {
                send_packet(rx_ring_front, fp.fragment_to_send_idx);
                fp.fragment_to_send_idx += 1;
            }
        }
        else if (fp.deadline_ms != 0 && now_ms >= fp.deadline_ms)
        {
            // Holdoff expired before block completion. Emit what
            // primaries we have; rest are lost.
            for (int f = fp.fragment_to_send_idx; f < fec_k; f++)
            {
                if (fp.fragment_map[f])
                {
                    send_packet(rx_ring_front, f);
                }
            }
            count_holdoff_fired += 1;
        }
        else
        {
            // Neither ready nor expired. Stop.
            break;
        }

        // Advance front.
        rx_ring_front = modN(rx_ring_front + 1, RX_RING_SIZE);
        rx_ring_alloc -= 1;
    }
}

void Aggregator::send_packet(int ring_idx, int fragment_idx)
{
    wpacket_hdr_t* packet_hdr = (wpacket_hdr_t*)(rx_ring[ring_idx].fragments[fragment_idx]);
    uint8_t *payload = (rx_ring[ring_idx].fragments[fragment_idx]) + sizeof(wpacket_hdr_t);
    uint8_t flags = packet_hdr->flags;
    uint16_t packet_size = be16toh(packet_hdr->packet_size);
    uint32_t packet_seq = rx_ring[ring_idx].block_idx * fec_k + fragment_idx;

    if (packet_seq > seq + 1 && seq > 0)
    {
        uint32_t lost_count = packet_seq - seq - 1;
        ANDROID_IPC_MSG("PKT_LOST\t%d", lost_count);
        count_p_lost += lost_count;

        // Immediate packet loss notification
        if (packet_loss_listener_ != NULL)
        {
            packet_loss_listener_->on_packet_loss(lost_count, seq, packet_seq);
        }
    }

    seq = packet_seq;

    if(packet_size > MAX_PAYLOAD_SIZE)
    {
        WFB_ERR("Corrupted packet %u\n", seq);
        count_p_bad += 1;
    }
    else if(!(flags & WFB_PACKET_FEC_ONLY))
    {
        send_to_socket(payload, packet_size);
        count_p_outgoing += 1;
        count_b_outgoing += packet_size;
    }
}

void Aggregator::apply_fec(int ring_idx)
{
    assert(fec_k >= 1);
    assert(fec_n >= 1);
    assert(fec_k <= fec_n);
    assert(fec_p != NULL);

    unsigned index[fec_k];
    uint8_t *in_blocks[fec_k];
    uint8_t *out_blocks[fec_n - fec_k];
    int j = fec_k;
    int ob_idx = 0;
    size_t max_packet_size = 0;

    for(int i=0; i < fec_k; i++)
    {
        if(rx_ring[ring_idx].fragment_map[i])
        {
            in_blocks[i] = rx_ring[ring_idx].fragments[i];
            index[i] = i;
        }
        else
        {
            while(j < fec_n && ! rx_ring[ring_idx].fragment_map[j])
            {
                j++;
            }

            assert(j < fec_n);
            // FEC packets always have max size between packets in block
            max_packet_size = max(max_packet_size, rx_ring[ring_idx].fragment_map[j]);
            in_blocks[i] = rx_ring[ring_idx].fragments[j];
            out_blocks[ob_idx++] = rx_ring[ring_idx].fragments[i];
            index[i] = j++;
        }
    }

    assert(max_packet_size > 0);
    assert(max_packet_size <= MAX_FEC_PAYLOAD);

    zfex_status_code_t rc = fec_decode_simd(fec_p, (const uint8_t**)in_blocks, out_blocks, index, ZFEX_ROUND_UP_SIMD(max_packet_size));
    assert(rc == ZFEX_SC_OK);
}

AggregatorUDPv4::AggregatorUDPv4(const std::string &client_addr, int client_port, const std::string &keypair, uint64_t epoch, uint32_t channel_id, int snd_buf_size) : \
    Aggregator(keypair, epoch, channel_id)
{
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) throw std::runtime_error(string_format("Error opening socket: %s", strerror(errno)));

    if (snd_buf_size > 0)
    {
        if(setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const void *)&snd_buf_size , sizeof(snd_buf_size)) !=0)
        {
            close(sockfd);
            throw runtime_error(string_format("Unable to set SO_SNDBUF: %s", strerror(errno)));
        }
    }

    memset(&saddr, '\0', sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = inet_addr(client_addr.c_str());
    saddr.sin_port = htons((unsigned short)client_port);
}

AggregatorUDPv4::~AggregatorUDPv4()
{
    close(sockfd);
}

void AggregatorUDPv4::send_to_socket(const uint8_t *payload, uint16_t packet_size)
{
    sendto(sockfd, payload, packet_size, MSG_DONTWAIT, (sockaddr*)&saddr, sizeof(saddr));
}

AggregatorUNIX::AggregatorUNIX(const std::string &socket_path, const std::string &keypair, uint64_t epoch, uint32_t channel_id, int snd_buf_size) : \
    Aggregator(keypair, epoch, channel_id)
{
    sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sockfd < 0) throw std::runtime_error(string_format("Error opening socket: %s", strerror(errno)));

    if (snd_buf_size > 0)
    {
        if(setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const void *)&snd_buf_size , sizeof(snd_buf_size)) !=0)
        {
            close(sockfd);
            throw runtime_error(string_format("Unable to set SO_SNDBUF: %s", strerror(errno)));
        }
    }

    memset(&saddr, '\0', sizeof(saddr));
    saddr.sun_family = AF_UNIX;
    strncpy(saddr.sun_path + 1, socket_path.c_str(), sizeof(saddr.sun_path) - 2);
}

AggregatorUNIX::~AggregatorUNIX()
{
    close(sockfd);
}

void AggregatorUNIX::send_to_socket(const uint8_t *payload, uint16_t packet_size)
{
    sendto(sockfd, payload, packet_size, MSG_DONTWAIT, (sockaddr*)&saddr, sizeof(sa_family_t) + strlen(saddr.sun_path + 1) + 1);
}

void radio_loop(int argc, char* const *argv, int optind, uint32_t channel_id, unique_ptr<BaseAggregator> &agg, int log_interval, int rcv_buf_size)
{
    int nfds = argc - optind;
    uint64_t log_send_ts = get_time_ms();
    struct pollfd fds[MAX_RX_INTERFACES];
    unique_ptr<Receiver> rx[MAX_RX_INTERFACES];

    if (nfds > MAX_RX_INTERFACES)
    {
        throw runtime_error(string_format("Too many WiFi adapters, increase MAX_RX_INTERFACES"));
    }

    memset(fds, '\0', sizeof(fds));

    for(int i = 0; i < nfds; i++)
    {
        rx[i].reset(new Receiver(argv[optind + i], i, channel_id, agg.get(), rcv_buf_size));
        fds[i].fd = rx[i]->getfd();
        fds[i].events = POLLIN;
    }

    for(;;)
    {
        uint64_t cur_ts = get_time_ms();
        int rc = poll(fds, nfds, log_send_ts > cur_ts ? log_send_ts - cur_ts : 0);

        if (rc < 0){
            if (errno == EINTR || errno == EAGAIN) continue;
            throw runtime_error(string_format("Poll error: %s", strerror(errno)));
        }

        cur_ts = get_time_ms();
        if (cur_ts >= log_send_ts)
        {
            agg->dump_stats();
            log_send_ts = cur_ts + log_interval - ((cur_ts - log_send_ts) % log_interval);
        }

        if (rc == 0) continue; // timeout expired

        for(int i = 0; rc > 0 && i < nfds; i++)
        {
            if (fds[i].revents & (POLLERR|POLLNVAL))
            {
                throw runtime_error("socket error!");
            }
            if (fds[i].revents & POLLIN){
                rx[i]->loop_iter();
                rc -= 1;
            }
        }
    }
}

void network_loop(int srv_port, unique_ptr<BaseAggregator> &agg, int log_interval, int rcv_buf_size)
{
    wrxfwd_t fwd_hdr;
    struct sockaddr_in sockaddr;
    uint8_t buf[MAX_FORWARDER_PACKET_SIZE];

    uint64_t log_send_ts = get_time_ms();
    struct pollfd fds[1];
    int fd = open_udp_socket_for_rx(srv_port, rcv_buf_size);

    memset(fds, '\0', sizeof(fds));
    fds[0].fd = fd;
    fds[0].events = POLLIN;

    for(;;)
    {
        uint64_t cur_ts = get_time_ms();
        int rc = poll(fds, 1, log_send_ts > cur_ts ? log_send_ts - cur_ts : 0);

        if (rc < 0){
            if (errno == EINTR || errno == EAGAIN) continue;
            throw runtime_error(string_format("poll error: %s", strerror(errno)));
        }

        cur_ts = get_time_ms();
        if (cur_ts >= log_send_ts)
        {
            agg->dump_stats();
            log_send_ts = cur_ts + log_interval - ((cur_ts - log_send_ts) % log_interval);
        }

        if (rc == 0) continue; // timeout expired

        // some events detected
        if (fds[0].revents & (POLLERR | POLLNVAL))
        {
            throw runtime_error(string_format("socket error: %s", strerror(errno)));
        }

        if (fds[0].revents & POLLIN)
        {
            for(;;) // process pending rx
            {
                memset((void*)&sockaddr, '\0', sizeof(sockaddr));

                struct iovec iov[2] = {{ .iov_base = (void*)&fwd_hdr,
                                         .iov_len = sizeof(fwd_hdr)},
                                       { .iov_base = (void*)buf,
                                         .iov_len = sizeof(buf) }};

                struct msghdr msghdr = { .msg_name = (void*)&sockaddr,
                                         .msg_namelen = sizeof(sockaddr),
                                         .msg_iov = iov,
                                         .msg_iovlen = 2,
                                         .msg_control = NULL,
                                         .msg_controllen = 0,
                                         .msg_flags = 0};

                ssize_t rsize = recvmsg(fd, &msghdr, MSG_DONTWAIT);
                if (rsize < 0)
                {
                    break;
                }

                if (rsize < (ssize_t)sizeof(wrxfwd_t))
                {
                    continue;
                }
                agg->process_packet(buf, rsize - sizeof(wrxfwd_t),
                                    fwd_hdr.wlan_idx, fwd_hdr.antenna,
                                    fwd_hdr.rssi, fwd_hdr.noise, ntohs(fwd_hdr.freq),
                                    fwd_hdr.mcs_index, fwd_hdr.bandwidth, &sockaddr);
            }
            if(errno != EWOULDBLOCK) throw runtime_error(string_format("Error receiving packet: %s", strerror(errno)));
        }
    }
}

#ifndef __WFB_RX_SHARED_LIBRARY__

int main(int argc, char* const *argv)
{
    int opt;
    uint8_t radio_port = 0;
    uint32_t link_id = 0;
    uint64_t epoch = 0;
    int log_interval = 1000;
    int client_port = 5600;
    int srv_port = 0;
    string client_addr = "127.0.0.1";
    rx_mode_t rx_mode = LOCAL;
    int rcv_buf = 0;
    int snd_buf = 0;

    string keypair = "rx.key";
    string unix_socket = "";

    while ((opt = getopt(argc, argv, "K:fa:c:u:U:p:l:i:e:R:s:")) != -1) {
        switch (opt) {
        case 'K':
            keypair = optarg;
            break;
        case 'f':
            rx_mode = FORWARDER;
            break;
        case 'a':
            rx_mode = AGGREGATOR;
            srv_port = atoi(optarg);
            break;
        case 'c':
            client_addr = string(optarg);
            break;
        case 'u':
            client_port = atoi(optarg);
            break;
        case 'U':
            unix_socket = string(optarg);
            break;
        case 'p':
            radio_port = atoi(optarg);
            break;
        case 'R':
            rcv_buf = atoi(optarg);
            break;
        case 's':
            snd_buf = atoi(optarg);
            break;
        case 'l':
            log_interval = atoi(optarg);
            break;
        case 'i':
            link_id = ((uint32_t)atoi(optarg)) & 0xffffff;
            break;
        case 'e':
            epoch = atoll(optarg);
            break;
        default: /* '?' */
        show_usage:
            WFB_INFO("Local RX: %s [-K rx_key] { [-c client_addr] [-u client_port] | [-U unix_socket] } [-p radio_port]\n"
                     "             [-R rcv_buf] [-s snd_buf] [-l log_interval] [-e epoch] [-i link_id] interface1 [interface2] ...\n", argv[0]);
            WFB_INFO("RX forwarder: %s -f [-c client_addr] [-u client_port] [-p radio_port]  [-R rcv_buf] [-s snd_buf]\n"
                     "                    [-i link_id] interface1 [interface2] ...\n", argv[0]);
            WFB_INFO("RX aggregator: %s -a server_port [-K rx_key] { [-c client_addr] [-u client_port] | [-U unix_socket] } [-R rcv_buf]\n"
                     "                                 [-s snd_buf] [-l log_interval] [-p radio_port] [-e epoch] [-i link_id]\n", argv[0]);
            WFB_INFO("Default: K='%s', connect=%s:%d, link_id=0x%06x, radio_port=%u, epoch=%" PRIu64 ", log_interval=%d, rcv_buf=system_default, snd_buf=system_default\n", keypair.c_str(), client_addr.c_str(), client_port, link_id, radio_port, epoch, log_interval);
            WFB_INFO("WFB-ng version %s, FEC: %s\n", WFB_VERSION, zfex_opt);
            WFB_INFO("WFB-ng home page: <http://wfb-ng.org>\n");
            exit(1);
        }
    }

    {
        int fd;
        int c;

        if ((fd = open("/dev/random", O_RDONLY)) != -1) {
            if (ioctl(fd, RNDGETENTCNT, &c) == 0 && c < 160) {
                WFB_ERR("This system doesn't provide enough entropy to quickly generate high-quality random numbers.\n"
                        "Installing the rng-utils/rng-tools, jitterentropy or haveged packages may help.\n"
                        "On virtualized Linux environments, also consider using virtio-rng.\n"
                        "The service will not start until enough entropy has been collected.\n");
            }
            (void) close(fd);
        }
    }

    if (sodium_init() < 0)
    {
        WFB_ERR("Libsodium init failed\n");
        return 1;
    }

    try
    {
        uint32_t channel_id = (link_id << 8) + radio_port;

        // WiFi interface(s) are required for all modes except aggregator
        if(rx_mode == AGGREGATOR)
        {
            if (optind > argc) goto show_usage;
        }
        else
        {
            if (optind >= argc) goto show_usage;
        }

        unique_ptr<BaseAggregator> agg;

        switch(rx_mode)
        {
        case LOCAL:
        case AGGREGATOR:
            if(unix_socket.length() > 0)
            {
                agg = unique_ptr<AggregatorUNIX>(new AggregatorUNIX(unix_socket, keypair, epoch, channel_id, snd_buf));
            }
            else
            {
                agg = unique_ptr<AggregatorUDPv4>(new AggregatorUDPv4(client_addr, client_port, keypair, epoch, channel_id, snd_buf));
            }
            break;

        case FORWARDER:
            agg = unique_ptr<Forwarder>(new Forwarder(client_addr, client_port, snd_buf));
            break;

        default:
            throw runtime_error(string_format("Unknown rx_mode=%d", rx_mode));
        }

        if(rx_mode == AGGREGATOR)
        {
            network_loop(srv_port, agg, log_interval, rcv_buf);
        }
        else
        {
            radio_loop(argc, argv, optind, channel_id, agg, log_interval, rcv_buf);
        }
    }
    catch(runtime_error &e)
    {
        WFB_ERR("Error: %s\n", e.what());
        exit(1);
    }
    return 0;
}

#endif
