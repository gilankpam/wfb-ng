// src/fec_iface.hpp
// Abstract encoder/decoder interfaces for wfb-ng FEC codecs.
// Two implementations: src/fec_block.{cpp,hpp} (WFB_FEC_VDM_RS,
// the existing RS-over-block codec) and src/fec_swin.{cpp,hpp}
// (WFB_FEC_SWIN_RS, the new sliding-window RS codec, Phase 2b).
//
// Alignment: all buffers passed across these interfaces must be
// ZFEX_SIMD_ALIGNMENT-aligned and ZFEX_ROUND_UP_SIMD-padded, per
// zfex.c:794-809. The existing block path already does this at
// tx.cpp:135 / rx.cpp:326; the new path must do the same.

#ifndef FEC_IFACE_HPP
#define FEC_IFACE_HPP

#include <cstdint>
#include <cstddef>
#include <memory>

#include "zfex.h"   // transitively includes zfex_macros.h
                    // (ZFEX_SIMD_ALIGNMENT, ZFEX_ROUND_UP_SIMD)

// ----- Wire constants -----------------------------------------------------
// WFB_FEC_VDM_RS is already defined in wifibroadcast.hpp.
// SWIN constants are defined here for Phase 2a (referenced by the
// fail-closed compat check); the sliding impl in Phase 2b wires them
// into the TX path.
#ifndef WFB_FEC_SWIN_RS
#define WFB_FEC_SWIN_RS          0x2
#endif

#ifndef WFB_PACKET_REPAIR_SWIN
#define WFB_PACKET_REPAIR_SWIN   0x2   // inner flag, repair-only
#endif

#ifndef TLV_SWIN_WINDOW
#define TLV_SWIN_WINDOW          0x10  // uint16_be W
#endif

#ifndef TLV_SWIN_REPAIR_RATIO
#define TLV_SWIN_REPAIR_RATIO    0x11  // uint8 num, uint8 den
#endif

// ----- Parameter carrier --------------------------------------------------
// Passed into init_session / init_fec and into the factory functions.
// Populated from -k/-n (block) or --swin-w/--swin-r (sliding); the
// session-parse path in rx.cpp:645-700 builds one from the decrypted
// wsession_data_t + TLVs.

struct fec_params_t {
    uint8_t  fec_type;      // WFB_FEC_VDM_RS or WFB_FEC_SWIN_RS

    // WFB_FEC_VDM_RS only (must be 0 under SWIN):
    int      k;
    int      n;

    // WFB_FEC_SWIN_RS only (must be 0 under VDM):
    uint16_t swin_w;        // W, from TLV_SWIN_WINDOW
    uint8_t  swin_r_num;    // R numerator, from TLV_SWIN_REPAIR_RATIO
    uint8_t  swin_r_den;    // R denominator
};

// ----- Listener for packet-loss events (widened per §9.4) -----------------
// Existing definition at src/rx.hpp:38-43 is widened in commit A4; the
// forward-decl here lets fec_iface.hpp be included without pulling rx.hpp.
class PacketLossListener;

// ----- Encoder interface --------------------------------------------------
// All public methods are single-threaded per-instance. Each instance is
// owned by exactly one Transmitter (via unique_ptr) and accessed only
// from the TX event loop. Concurrent calls are UB; no internal locking.
//
// On programmer error (bad alignment, mis-sized buffer, seq out of
// range) methods assert. On unexpected internal error (e.g. a zfex
// failure that indicates corruption) they throw std::runtime_error.
// Expected "not yet" states use bool return, not exceptions.

class IFecEncoder {
public:
    virtual ~IFecEncoder() = default;

    // Called for every source packet the app wants transmitted.
    // Updates codec state (window ring, repair schedule, block buffer).
    // The encoder does NOT emit the source packet itself — Transmitter
    // sends the source on the wire; this call is the encoder's
    // notification that a new source exists.
    //
    //   seq     : 64-bit view of the source packet's data_nonce. For
    //             block FEC, this is (block_idx << 8) | fragment_idx,
    //             matching the current wire nonce at tx.cpp:631. For
    //             sliding FEC, this is a flat 56-bit source seq_num
    //             (bits 55..0 per §5.2).
    //   payload : ZFEX_SIMD_ALIGNMENT-aligned, ZFEX_ROUND_UP_SIMD(sz)-
    //             padded buffer holding the already-framed inner
    //             packet (wpacket_hdr_t + user data + zero pad).
    //   sz      : logical size (≤ MAX_FEC_PAYLOAD). The padded buffer
    //             may be larger; the codec reads only [0, sz).
    //
    // Ownership: payload is caller-owned. The encoder MAY retain a
    // copy internally (block FEC copies into its k-slot buffer;
    // sliding FEC copies into the window ring). The caller may
    // free/reuse payload as soon as this call returns.
    virtual void on_source_packet(uint64_t seq,
                                  const uint8_t* payload,
                                  size_t sz) = 0;

    // Try to emit the next repair packet.
    //
    // Returns true and fills (*sz_out, *nonce_out) with the repair
    // payload and the wire-format 64-bit big-endian data_nonce (§5.2)
    // if a repair is ready to send. Returns false if no repair is
    // ready.
    //
    // Caller contract: Transmitter MUST drain next_repair in a loop
    // until it returns false, after every on_source_packet and on
    // every call to tick() (for sliding). For block FEC, this
    // produces zero repairs for the first k-1 source packets, then
    // exactly (n - k) repairs in sequence after the k-th, then zero
    // until the next block completes. For sliding, it produces
    // repairs on the schedule defined by §7.3.
    //
    //   out       : caller-provided, ZFEX_SIMD_ALIGNMENT-aligned,
    //               ZFEX_ROUND_UP_SIMD(MAX_FEC_PAYLOAD)-sized buffer.
    //   sz_out    : on return, the logical size of the repair payload
    //               (≤ MAX_FEC_PAYLOAD).
    //   nonce_out : on return, the 64-bit big-endian data_nonce for
    //               this repair. For block FEC, this is
    //               (block_idx << 8) | fragment_idx with
    //               fragment_idx ∈ [k, n). For sliding FEC, this is
    //               the is_repair|repair_idx|seq_num layout of §5.2.
    //
    // On repair, the encoder has already written the inner header
    // (wpacket_hdr_t for block, wpacket_hdr_repair_t for sliding) at
    // the start of out; Transmitter appends nothing.
    virtual bool next_repair(uint8_t* out,
                             size_t* sz_out,
                             uint64_t* nonce_out) = 0;

    // Advance wall-clock state. Called every ~10 ms from the TX event
    // loop. Block FEC ignores it (returns immediately); sliding FEC
    // uses it to implement fec_delay-style pacing in Phase 2b.
    virtual void tick(uint64_t now_ms) = 0;
};

// ----- Decoder interface --------------------------------------------------
// Single-threaded per-instance, owned by exactly one Aggregator (via
// unique_ptr), same threading / error contract as IFecEncoder.

class IFecDecoder {
public:
    virtual ~IFecDecoder() = default;

    // A source packet arrived from the wire. Aggregator has already
    // decrypted + authenticated it and parsed the data_nonce; it
    // dispatches to on_source_packet or on_repair_packet based on
    // decoder->is_repair_fragment(data_nonce) — a unified, codec-
    // agnostic signal (see below).
    //
    //   seq     : 64-bit "full data_nonce" view. Block: encodes
    //             (block_idx, fragment_idx); sliding: 56-bit
    //             seq_num.
    //   payload : ZFEX_SIMD_ALIGNMENT-aligned buffer, length sz.
    //   sz      : logical size (≤ MAX_FEC_PAYLOAD).
    //
    // Ownership: payload is caller-owned; decoder copies what it
    // needs into its internal storage (block: rx_ring fragment
    // slot; sliding: window ring).
    virtual void on_source_packet(uint64_t seq,
                                  const uint8_t* payload,
                                  size_t sz) = 0;

    // A repair packet arrived from the wire.
    //
    //   repair_nonce    : full 64-bit big-endian data_nonce as
    //                     received on the wire (§5.2 for sliding;
    //                     (block_idx << 8) | fragment_idx for
    //                     block). Under sliding this encodes
    //                     is_repair=1 | repair_idx | seq_num;
    //                     under block it encodes
    //                     (block_idx, fragment_idx) with
    //                     fragment_idx ∈ [k, n).
    //   window_tail_seq : for sliding, the value from
    //                     wpacket_hdr_repair_t.window_tail_seq
    //                     (§5.4). For block, the Aggregator passes
    //                     (block_idx << 8) | (fec_k - 1) — a
    //                     synthetic value representing "the last
    //                     source of this block".
    //   repair_idx      : for sliding, the 7-bit field extracted
    //                     from repair_nonce (redundant with that
    //                     nonce; passed explicitly for clarity and
    //                     so the decoder can assert consistency).
    //                     For block, the Aggregator passes
    //                     fragment_idx - fec_k.
    //   payload, sz     : aligned buffer with the repair's parity
    //                     bytes; same ownership contract as
    //                     on_source_packet.
    virtual void on_repair_packet(uint64_t repair_nonce,
                                  uint64_t window_tail_seq,
                                  uint8_t  repair_idx,
                                  const uint8_t* payload,
                                  size_t sz) = 0;

    // Drain one ready source packet (received or FEC-recovered) in
    // increasing seq order.
    //
    // Returns true and fills (*seq_out, writes into out, *sz_out)
    // if a packet is ready. Returns false when the decoder has
    // nothing more to emit right now.
    //
    // Caller contract: Aggregator drains pop_ready in a loop after
    // every on_source_packet / on_repair_packet / tick() call. For
    // block FEC, packets pop out in fragment order once a block is
    // complete (k received, or k recovered via apply_fec). For
    // sliding FEC, each source packet pops immediately on arrival;
    // recovered packets pop as the decoder solves their window.
    //
    //   seq_out : the FLAT packet_seq for loss-listener tracking.
    //             Block returns block_idx * fec_k + fragment_idx.
    //             Sliding returns the 56-bit seq_num (low bits of
    //             data_nonce). Aggregator uses this directly for
    //             its `packet_seq > seq + 1` gap-detection check;
    //             it does NOT need to reparse data_nonce.
    //   out     : caller-provided, ZFEX_SIMD_ALIGNMENT-aligned,
    //             ZFEX_ROUND_UP_SIMD(MAX_FEC_PAYLOAD)-sized
    //             buffer. Decoder copies the recovered/received
    //             source payload into it.
    //   sz_out  : logical size written.
    virtual bool pop_ready(uint64_t* seq_out,
                           uint8_t* out,
                           size_t* sz_out) = 0;

    // Advance wall-clock state. Called every ~10 ms from the RX
    // event loop. Block FEC ignores it; sliding FEC uses it to
    // fire T_flush (§7.3) on stalled windows.
    virtual void tick(uint64_t now_ms) = 0;

    // ----- Codec-aware query accessors ---------------------------
    // These three methods let Aggregator stay codec-agnostic. Added
    // in B0 to resolve the Gate G2 findings: before B0, rx.cpp used
    // fragment_idx < fec_k (block-only rule) to dispatch, and read
    // counter values via out-of-band pointers. Now the decoder
    // owns both pieces of codec-specific knowledge and exposes them
    // via virtual accessors.

    // True if data_nonce names a repair fragment. Block returns
    // (data_nonce & 0xff) >= fec_k_; sliding returns the high bit
    // of data_nonce (is_repair per §5.2).
    virtual bool is_repair_fragment(uint64_t data_nonce) const = 0;

    // Running count of source fragments recovered via FEC, since
    // construction. Aggregator mirrors into its public
    // count_p_fec_recovered member after every drain.
    virtual uint32_t count_p_fec_recovered() const = 0;

    // Running count of ring override-evictions (block-specific).
    // SWIN has no ring; SWIN implementations always return 0.
    virtual uint32_t count_p_override() const = 0;

    // Running count of windows retired at T_flush with at least one
    // unrecovered gap (SWIN-specific, §10.3). Block has no T_flush;
    // block implementations always return 0.
    virtual uint32_t count_w_flush() const = 0;
};

// ----- Factory ------------------------------------------------------------
// Each call returns a new encoder/decoder instance configured from
// params. params.fec_type selects the implementation; malformed
// params (bad k, bad n, bad W, bad R) assert.
//
// The decoder's loss_listener may be nullptr; in that case the
// decoder still recovers / drops packets but reports no loss
// events.

std::unique_ptr<IFecEncoder> make_fec_encoder(const fec_params_t& params);

std::unique_ptr<IFecDecoder> make_fec_decoder(const fec_params_t& params,
                                              PacketLossListener* loss_listener);

#endif // FEC_IFACE_HPP
