#pragma once
#include <stdint.h>

#define CMD_SET_FEC   1
#define CMD_SET_RADIO 2
#define CMD_GET_FEC   3
#define CMD_GET_RADIO 4
#define CMD_GET_STATS 5

typedef struct {
    uint32_t req_id;
    uint8_t cmd_id;
    union {
        struct
        {
            uint8_t k;
            uint8_t n;
        } __attribute__ ((packed)) cmd_set_fec;

        struct
        {
            uint8_t stbc;
            bool ldpc;
            bool short_gi;
            uint8_t bandwidth;
            uint8_t mcs_index;
            bool vht_mode;
            uint8_t vht_nss;
        } __attribute__ ((packed)) cmd_set_radio;
    } __attribute__ ((packed)) u;
} __attribute__ ((packed)) cmd_req_t;


typedef struct {
    uint32_t req_id;
    uint32_t rc;
    union {
        struct
        {
            uint8_t k;
            uint8_t n;
        } __attribute__ ((packed)) cmd_get_fec;

        struct
        {
            uint8_t stbc;
            bool ldpc;
            bool short_gi;
            uint8_t bandwidth;
            uint8_t mcs_index;
            bool vht_mode;
            uint8_t vht_nss;
        } __attribute__ ((packed)) cmd_get_radio;

        /* Cumulative counters since wfb_tx startup. Host byte order —
         * control socket is loopback-only (127.0.0.1), both ends are on
         * the same machine, so no htonll/ntohll conversion. */
        struct
        {
            uint64_t p_fec_timeouts;  /* FEC-only pad packets sent (only nonzero when -T > 0) */
            uint64_t p_incoming;      /* UDP packets received from encoder (inc. RXQ-dropped) */
            uint64_t p_injected;      /* Packets successfully injected (includes parity) */
            uint64_t b_injected;      /* Bytes successfully injected */
            uint64_t p_dropped;       /* Dropped due to RXQ overflow or injection timeout */
            uint64_t p_truncated;     /* Packets truncated because payload exceeds MAX_FEC_PAYLOAD */
        } __attribute__ ((packed)) cmd_get_stats;
    } __attribute__ ((packed)) u;
} __attribute__ ((packed)) cmd_resp_t;
