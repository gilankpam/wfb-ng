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
#include <getopt.h>
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
#include "fec_block.hpp"

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


Aggregator::Aggregator(const string &keypair, uint64_t epoch, uint32_t channel_id,
                       uint8_t configured_codec, uint64_t T_flush_ms) : \
    count_p_all(0), count_b_all(0), count_p_dec_err(0), count_p_session(0), count_p_data(0), count_p_fec_recovered(0),
    count_p_lost(0), count_p_bad(0), count_p_override(0), count_p_outgoing(0), count_b_outgoing(0),
    decoder(), pop_scratch(nullptr),
    mirror_baseline_fec_recovered(0), mirror_baseline_override(0),
    current_params{},
    configured_codec(configured_codec),
    T_flush_ms(T_flush_ms),
    seq(0),
    epoch(epoch), channel_id(channel_id)
{
    if (configured_codec != WFB_FEC_VDM_RS && configured_codec != WFB_FEC_SWIN_RS)
    {
        throw runtime_error(string_format("Aggregator: unknown configured_codec 0x%x", configured_codec));
    }
    memset(session_key, '\0', sizeof(session_key));
    memset(session_hash, '\0', sizeof(session_hash));

    // Aligned scratch buffer that pop_ready copies recovered/received
    // source fragments into on every drain call. Symmetric with the
    // Transmitter's scratch (tx.cpp).
    int rc_align = posix_memalign((void**)&pop_scratch, ZFEX_SIMD_ALIGNMENT,
                                  ZFEX_ROUND_UP_SIMD(MAX_FEC_PAYLOAD));
    if (rc_align != 0) {
        throw runtime_error(string_format("Aggregator: posix_memalign failed: %s",
                                          strerror(rc_align)));
    }

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
    free(pop_scratch);
    pop_scratch = nullptr;
    // decoder unique_ptr destroys BlockFecDecoder, which frees
    // rx_ring fragments and the zfex handle.
}

void Aggregator::init_fec(const fec_params_t &params)
{
    // B4: both codecs are wired. Param validation mirrors the codec-
    // side ctors (fec_block.cpp / fec_swin.cpp).
    if (params.fec_type == WFB_FEC_VDM_RS)
    {
        assert(params.k >= 1);
        assert(params.n >= 1);
        assert(params.n < 256);
        assert(params.k <= params.n);
    }
    else if (params.fec_type == WFB_FEC_SWIN_RS)
    {
        assert(params.k == 0 && params.n == 0);
        assert(params.swin_w >= 1);
        assert(params.swin_r_num >= 1 && params.swin_r_den >= 1);
    }
    else
    {
        throw runtime_error(string_format("init_fec: unknown fec_type 0x%x", params.fec_type));
    }

    current_params = params;
    seq = 0;

    // B0: factory dispatches on fec_type. B4: T_flush_ms flows to the
    // SWIN decoder here (block decoder ignores it).
    decoder = make_fec_decoder(current_params, packet_loss_listener_, T_flush_ms);

    // Fresh decoder: cumulative counters are 0, so baseline is 0.
    mirror_baseline_fec_recovered = 0;
    mirror_baseline_override = 0;
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

void Aggregator::dump_stats(void)
{
    //timestamp in ms
    uint64_t ts = get_time_ms();

    for(auto it = antenna_stat.begin(); it != antenna_stat.end(); it++)
    {
        IPC_MSG("%" PRIu64 "\tRX_ANT\t%u:%u:%u\t%" PRIx64 "\t%d" ":%d:%d:%d" ":%d:%d:%d\n",
                ts, it->first.freq, it->first.mcs_index, it->first.bandwidth, it->first.antenna_id, it->second.count_all,
                it->second.rssi_min, it->second.rssi_sum / it->second.count_all, it->second.rssi_max,
                it->second.snr_min, it->second.snr_sum / it->second.count_all, it->second.snr_max);
    }

    IPC_MSG("%" PRIu64 "\tPKT\t%u:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u\n", ts,
            count_p_all, count_b_all,                    // incoming
            count_p_dec_err,                             // decryption
            count_p_session, count_p_data,               // classification
            (uint32_t)count_p_uniq.size(),               // unique check
            count_p_fec_recovered, count_p_lost,         // fec recovering
            count_p_bad,                                 // internal errors
            count_p_outgoing, count_b_outgoing);         // outgoing
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

    case WFB_PACKET_SESSION: {
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

        // B4: §9.2 step 3 — fail closed if the TX used a different
        // codec than this RX was configured for. This catches
        // symmetric mismatches (new TX + old RX; block TX + SWIN RX;
        // SWIN TX + block RX) at the session packet before any
        // data packet reaches the decoder.
        if (new_session_data->fec_type != configured_codec)
        {
            WFB_ERR("Unsupported FEC codec type 0x%x (RX configured for 0x%x)\n",
                    new_session_data->fec_type, configured_codec);
            count_p_dec_err += 1;
            return;
        }

        // Codec-specific param validation. fec_params_t carries both
        // block (k, n) and sliding (swin_w, swin_r_num, swin_r_den)
        // fields; only the fields for the active codec are populated,
        // the rest stay 0.
        fec_params_t session_params{};
        session_params.fec_type = new_session_data->fec_type;

        if (new_session_data->fec_type == WFB_FEC_VDM_RS)
        {
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

            session_params.k = new_session_data->k;
            session_params.n = new_session_data->n;
        }
        else
        {
            // WFB_FEC_SWIN_RS — §5.5 reserves k/n = 0; §5.5 carries
            // W and R in optional TLVs.
            if (new_session_data->k != 0 || new_session_data->n != 0)
            {
                WFB_ERR("SWIN session has non-zero k/n (0x%x/0x%x)\n",
                        new_session_data->k, new_session_data->n);
                count_p_dec_err += 1;
                return;
            }

            const size_t fixed_prefix =
                sizeof(wsession_hdr_t) + sizeof(wsession_data_t) + crypto_box_MACBYTES;
            const size_t tlv_size = size - fixed_prefix;
            const void*  tlv_start = new_session_data->tags;

            uint16_t w_be = 0;
            int rc_w = get_tag(tlv_start, tlv_size, TLV_SWIN_WINDOW,
                               &w_be, sizeof(w_be));
            if (rc_w != (int)sizeof(w_be))
            {
                WFB_ERR("SWIN session missing/malformed TLV_SWIN_WINDOW (rc=%d)\n", rc_w);
                count_p_dec_err += 1;
                return;
            }

            uint8_t r_bytes[2] = {0, 0};
            int rc_r = get_tag(tlv_start, tlv_size, TLV_SWIN_REPAIR_RATIO,
                               r_bytes, sizeof(r_bytes));
            if (rc_r != (int)sizeof(r_bytes))
            {
                WFB_ERR("SWIN session missing/malformed TLV_SWIN_REPAIR_RATIO (rc=%d)\n", rc_r);
                count_p_dec_err += 1;
                return;
            }

            const uint16_t w = be16toh(w_be);
            const uint8_t  r_num = r_bytes[0];
            const uint8_t  r_den = r_bytes[1];

            if (w < 1 || r_num < 1 || r_den < 1)
            {
                WFB_ERR("Invalid SWIN params W=%u R=%u/%u\n", w, r_num, r_den);
                count_p_dec_err += 1;
                return;
            }

            // §5.3: repair_idx is 7 bits, so ⌈R·W⌉ ≤ 128.
            const uint32_t repairs_per_window =
                ((uint32_t)w * (uint32_t)r_num + (uint32_t)r_den - 1) / (uint32_t)r_den;
            if (repairs_per_window < 1 || repairs_per_window > 128)
            {
                WFB_ERR("SWIN ⌈R·W⌉=%u out of range [1,128]\n", repairs_per_window);
                count_p_dec_err += 1;
                return;
            }

            session_params.swin_w = w;
            session_params.swin_r_num = r_num;
            session_params.swin_r_den = r_den;
        }

        count_p_session += 1;

        // Ignore RSSI (and per-card rx counters) for session packets to simplify calculation
        // of lost packets because session packets doesn't have any serial number and it is
        // too hard to calculate number of unique session packets

        if (memcmp(session_key, new_session_data->session_key, sizeof(session_key)) != 0)
        {
            epoch = be64toh(new_session_data->epoch);
            memcpy(session_key, new_session_data->session_key, sizeof(session_key));

            // B4: session_params is built above from the codec-specific
            // fields. init_fec dispatches to block or SWIN via the
            // factory. init_fec resets the decoder unique_ptr, which
            // frees the previous ring / zfex handle.
            init_fec(session_params);

            // B6 log format (§10.3.1):
            //   ts <TAB> SESSION <TAB> epoch:fec_type:k:n:swin_w:r_num/r_den
            // Block sessions carry W=0, r_num/r_den=0/0 (SWIN fields
            // unused). SWIN sessions carry k=n=0 (block fields unused).
            // Both flavors are always 6 colon-separated fields so the
            // Python parser can disambiguate on token count.
            IPC_MSG("%" PRIu64 "\tSESSION\t%" PRIu64 ":%u:%d:%d:%u:%u/%u\n",
                    get_time_ms(), epoch,
                    (unsigned)current_params.fec_type,
                    current_params.k, current_params.n,
                    (unsigned)current_params.swin_w,
                    (unsigned)current_params.swin_r_num,
                    (unsigned)current_params.swin_r_den);
            IPC_MSG_SEND();
        }

        // Cache already processed session
        memcpy(session_hash, new_session_hash, sizeof(session_hash));

        return;
    }

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

    const uint64_t data_nonce = be64toh(block_hdr->data_nonce);

    count_p_uniq.insert(data_nonce);

    // Block-FEC nonce validation lives here so the block path can
    // trust (block_idx, fragment_idx) downstream. Under SWIN the
    // nonce is (is_repair | repair_idx | seq_num) and these checks
    // don't apply (block_idx = nonce>>8 is always > MAX_BLOCK_IDX
    // for a SWIN repair where bit 63 = 1).
    if (current_params.fec_type == WFB_FEC_VDM_RS)
    {
        uint64_t block_idx = data_nonce >> 8;
        uint8_t fragment_idx_ = (uint8_t)(data_nonce & 0xff);

        if (block_idx > MAX_BLOCK_IDX)
        {
            WFB_ERR("block_idx overflow\n");
            count_p_bad += 1;
            return;
        }

        if (fragment_idx_ >= current_params.n)
        {
            WFB_ERR("Invalid fragment_idx: %d\n", fragment_idx_);
            count_p_bad += 1;
            return;
        }
    }

    // B0: unified dispatch via decoder->is_repair_fragment(data_nonce).
    // Block returns (nonce & 0xff) >= fec_k_; sliding returns bit 63.
    // Aggregator stays codec-agnostic; the codec-specific rule is
    // inside the decoder.
    if (!decoder->is_repair_fragment(data_nonce))
    {
        decoder->on_source_packet(data_nonce, decrypted, decrypted_len);
    }
    else if (current_params.fec_type == WFB_FEC_VDM_RS)
    {
        // Block repair: synthesize (window_tail, repair_idx) from the
        // wire nonce. window_tail = (block_idx << 8) | (fec_k - 1) —
        // a synthetic value per IFecDecoder doc (§9.3) meaning "last
        // source of this block".
        const uint64_t block_idx     = data_nonce >> 8;
        const uint8_t  fragment_idx_ = (uint8_t)(data_nonce & 0xff);
        const uint64_t window_tail = ((block_idx & BLOCK_IDX_MASK) << 8) | (uint8_t)(current_params.k - 1);
        const uint8_t  repair_idx  = fragment_idx_ - (uint8_t)current_params.k;
        decoder->on_repair_packet(data_nonce, window_tail, repair_idx,
                                  decrypted, decrypted_len);
    }
    else
    {
        // SWIN repair: the inner header (wpacket_hdr_repair_t, §5.4)
        // carries the window tail. The wire nonce carries repair_idx
        // in bits 62..56 (§5.2); we pass both to the decoder —
        // repair_idx from the nonce is the authoritative value, the
        // inner header has been integrity-protected by AEAD so we
        // trust its window_tail_seq.
        if (decrypted_len < sizeof(wpacket_hdr_repair_t))
        {
            WFB_ERR("SWIN repair packet too short (%llu < %zu)\n",
                    decrypted_len, sizeof(wpacket_hdr_repair_t));
            count_p_bad += 1;
            return;
        }
        const wpacket_hdr_repair_t* rhdr = (const wpacket_hdr_repair_t*)decrypted;
        if (rhdr->flags != WFB_PACKET_REPAIR_SWIN)
        {
            WFB_ERR("SWIN repair inner flags mismatch 0x%x (want 0x%x)\n",
                    rhdr->flags, WFB_PACKET_REPAIR_SWIN);
            count_p_bad += 1;
            return;
        }

        const size_t   parity_len     = be16toh(rhdr->payload_size);
        const uint64_t window_tail    = be64toh(rhdr->window_tail_seq);
        const uint8_t  repair_idx     = (uint8_t)((data_nonce >> 56) & 0x7f);

        if (sizeof(wpacket_hdr_repair_t) + parity_len > decrypted_len)
        {
            WFB_ERR("SWIN repair payload_size %zu exceeds decrypted len %llu\n",
                    parity_len, decrypted_len);
            count_p_bad += 1;
            return;
        }

        decoder->on_repair_packet(data_nonce, window_tail, repair_idx,
                                  decrypted + sizeof(wpacket_hdr_repair_t),
                                  parity_len);
    }

    // Drain every source packet the decoder is ready to emit. pop_ready
    // returns in increasing seq order (now flat packet_seq per B0);
    // emit_source tracks losses and writes to the socket.
    uint64_t out_seq = 0;
    size_t out_sz = 0;
    while (decoder->pop_ready(&out_seq, pop_scratch, &out_sz))
    {
        emit_source(out_seq, pop_scratch, out_sz);
    }

    // Mirror decoder-owned counters into Aggregator's public members,
    // delta-since-last-clear (see rx.hpp mirror_baseline_* doc).
    // Cheap virtual-call pulls; cost is per-packet but well under
    // memcpy overhead.
    count_p_fec_recovered = decoder->count_p_fec_recovered() - mirror_baseline_fec_recovered;
    count_p_override      = decoder->count_p_override()      - mirror_baseline_override;
}

void Aggregator::emit_source(uint64_t seq_from_decoder, const uint8_t* buf, size_t sz)
{
    // pop_ready hands back the full ZFEX-padded fragment; the inner
    // wpacket_hdr_t's packet_size field tells us the logical payload
    // length.
    //
    // B0: seq_from_decoder IS the flat packet_seq suitable for
    // loss-listener tracking. Block returned block_idx * fec_k +
    // fragment_idx; sliding returns seq_num. No conversion here.
    assert(sz >= sizeof(wpacket_hdr_t));
    (void)sz;

    const wpacket_hdr_t* packet_hdr = (const wpacket_hdr_t*)buf;
    const uint8_t*       payload    = buf + sizeof(wpacket_hdr_t);
    const uint8_t        flags      = packet_hdr->flags;
    const uint16_t       packet_size = be16toh(packet_hdr->packet_size);

    const uint64_t packet_seq = seq_from_decoder;

    if (packet_seq > seq + 1 && seq > 0)
    {
        // Gap size truncates to 32 bits for count_p_lost and the
        // listener's lost_count parameter. A single gap > 2^32
        // packets is unreachable in practice (billions of packets)
        // so saturation here would only hide a bug elsewhere.
        const uint64_t gap64 = packet_seq - seq - 1;
        const uint32_t lost_count = (uint32_t)gap64;
        ANDROID_IPC_MSG("PKT_LOST\t%d", lost_count);
        count_p_lost += lost_count;

        if (packet_loss_listener_ != NULL)
        {
            packet_loss_listener_->on_packet_loss(lost_count, seq, packet_seq);
        }
    }

    seq = packet_seq;

    if (packet_size > MAX_PAYLOAD_SIZE)
    {
        WFB_ERR("Corrupted packet %" PRIu64 "\n", seq);
        count_p_bad += 1;
    }
    else if (!(flags & WFB_PACKET_FEC_ONLY))
    {
        send_to_socket(payload, packet_size);
        count_p_outgoing += 1;
        count_b_outgoing += packet_size;
    }
}

AggregatorUDPv4::AggregatorUDPv4(const std::string &client_addr, int client_port, const std::string &keypair, uint64_t epoch, uint32_t channel_id, int snd_buf_size,
                                 uint8_t configured_codec, uint64_t T_flush_ms) : \
    Aggregator(keypair, epoch, channel_id, configured_codec, T_flush_ms)
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

AggregatorUNIX::AggregatorUNIX(const std::string &socket_path, const std::string &keypair, uint64_t epoch, uint32_t channel_id, int snd_buf_size,
                               uint8_t configured_codec, uint64_t T_flush_ms) : \
    Aggregator(keypair, epoch, channel_id, configured_codec, T_flush_ms)
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

    // B5: codec selector + T_flush override. Default stays block so
    // existing deployments behave identically. SWIN's W and R come from
    // the session TLV at runtime; no RX CLI flags for those.
    uint8_t  configured_codec = WFB_FEC_VDM_RS;
    uint64_t t_flush_ms = 100;

    enum {
        OPT_CODEC   = 256,
        OPT_TFLUSH  = 257,
    };

    static const struct option long_options[] = {
        { "codec",       required_argument, nullptr, OPT_CODEC  },
        { "t-flush-ms",  required_argument, nullptr, OPT_TFLUSH },
        { nullptr, 0, nullptr, 0 }
    };

    while ((opt = getopt_long(argc, argv, "K:fa:c:u:U:p:l:i:e:R:s:",
                              long_options, nullptr)) != -1) {
        switch (opt) {
        case OPT_CODEC:
            if (strcmp(optarg, "block") == 0) {
                configured_codec = WFB_FEC_VDM_RS;
            } else if (strcmp(optarg, "sliding") == 0) {
                configured_codec = WFB_FEC_SWIN_RS;
            } else {
                WFB_ERR("Invalid --codec: %s (expected block|sliding)\n", optarg);
                exit(1);
            }
            break;
        case OPT_TFLUSH: {
            long v = atol(optarg);
            if (v < 0) {
                WFB_ERR("Invalid --t-flush-ms: %s\n", optarg);
                exit(1);
            }
            t_flush_ms = (uint64_t)v;
            break;
        }
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
            WFB_INFO("Local RX: %s [-K rx_key] [--codec block|sliding] [--t-flush-ms MS] { [-c client_addr] [-u client_port] | [-U unix_socket] } [-p radio_port]\n"
                     "             [-R rcv_buf] [-s snd_buf] [-l log_interval] [-e epoch] [-i link_id] interface1 [interface2] ...\n", argv[0]);
            WFB_INFO("RX forwarder: %s -f [-c client_addr] [-u client_port] [-p radio_port]  [-R rcv_buf] [-s snd_buf]\n"
                     "                    [-i link_id] interface1 [interface2] ...\n", argv[0]);
            WFB_INFO("RX aggregator: %s -a server_port [-K rx_key] [--codec block|sliding] [--t-flush-ms MS] { [-c client_addr] [-u client_port] | [-U unix_socket] } [-R rcv_buf]\n"
                     "                                 [-s snd_buf] [-l log_interval] [-p radio_port] [-e epoch] [-i link_id]\n", argv[0]);
            WFB_INFO("Default: K='%s', codec=block, t_flush_ms=%" PRIu64 ", connect=%s:%d, link_id=0x%06x, radio_port=%u, epoch=%" PRIu64 ", log_interval=%d, rcv_buf=system_default, snd_buf=system_default\n",
                     keypair.c_str(), t_flush_ms, client_addr.c_str(), client_port, link_id, radio_port, epoch, log_interval);
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
                agg = unique_ptr<AggregatorUNIX>(new AggregatorUNIX(unix_socket, keypair, epoch, channel_id, snd_buf,
                                                                   configured_codec, t_flush_ms));
            }
            else
            {
                agg = unique_ptr<AggregatorUDPv4>(new AggregatorUDPv4(client_addr, client_port, keypair, epoch, channel_id, snd_buf,
                                                                     configured_codec, t_flush_ms));
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
