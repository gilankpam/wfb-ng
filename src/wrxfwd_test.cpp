#include <catch2/catch_test_macros.hpp>
#include <cstring>
#include "wifibroadcast.hpp"

TEST_CASE("wrxfwd v2 round-trip preserves evm and payload") {
    uint8_t buf[sizeof(wrxfwd_t) + 3];
    std::memset(buf, 0, sizeof(buf));
    wrxfwd_t *h = reinterpret_cast<wrxfwd_t*>(buf);
    h->version = WFB_FWD_VERSION;
    h->wlan_idx = 1;
    h->evm[0] = 84; h->evm[1] = 0xff; h->evm[2] = 0xff; h->evm[3] = 0xff;
    buf[sizeof(wrxfwd_t) + 0] = 0xAA;
    buf[sizeof(wrxfwd_t) + 1] = 0xBB;
    buf[sizeof(wrxfwd_t) + 2] = 0xCC;

    const wrxfwd_t *ph = nullptr; const uint8_t *pl = nullptr; size_t pll = 0;
    REQUIRE(wrxfwd_parse(buf, sizeof(buf), &ph, &pl, &pll));
    REQUIRE(ph->evm[0] == 84);
    REQUIRE(pll == 3);
    REQUIRE(pl[0] == 0xAA);
    REQUIRE(pl[2] == 0xCC);
}

TEST_CASE("wrxfwd version guard drops stale/unknown packets") {
    uint8_t buf[sizeof(wrxfwd_t) + 3];
    std::memset(buf, 0, sizeof(buf));
    reinterpret_cast<wrxfwd_t*>(buf)->version = 0x01;   // v1 / stale node
    const wrxfwd_t *ph = nullptr; const uint8_t *pl = nullptr; size_t pll = 0;
    REQUIRE_FALSE(wrxfwd_parse(buf, sizeof(buf), &ph, &pl, &pll));
}

TEST_CASE("wrxfwd drops short packets") {
    uint8_t buf[sizeof(wrxfwd_t)];
    std::memset(buf, 0, sizeof(buf));
    reinterpret_cast<wrxfwd_t*>(buf)->version = WFB_FWD_VERSION;
    const wrxfwd_t *ph = nullptr; const uint8_t *pl = nullptr; size_t pll = 0;
    REQUIRE_FALSE(wrxfwd_parse(buf, sizeof(wrxfwd_t) - 1, &ph, &pl, &pll));
}
