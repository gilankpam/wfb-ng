// -*- mode: c++; -*-
// Channel loss models for the fec_bench harness.
//
// Three models, all stateful objects exposing a single method:
//     bool drop(size_t packet_index)
//
// Each returns true iff the packet at packet_index is lost in transit.
// Each is deterministic given the seed passed at construction -- two
// instances with the same seed produce the same loss sequence for the
// same sequence of indices.
//
// Models:
//   UniformLoss  -- Bernoulli(p). Independent per packet.
//   GilbertElliottLoss -- Two-state Markov chain. Good state delivers,
//                         Bad state drops. Transition rates tuned so
//                         that mean burst length and mean gap length
//                         match the supplied parameters.
//   PeriodicLoss -- Deterministic. Drops burst_len packets every
//                   period packets. Simulates a beacon-aligned
//                   interferer worst-case for short interleavers.
//
// Header-only by design; the harness is a single translation unit and
// these classes are cheap to include.

#ifndef FEC_BENCH_CHANNEL_MODEL_HPP
#define FEC_BENCH_CHANNEL_MODEL_HPP

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <random>

namespace fec_bench {

// ---------------------------------------------------------------------------
// Uniform random loss: every packet dropped with probability p, independently.
// ---------------------------------------------------------------------------
class UniformLoss {
public:
    UniformLoss(double p, uint64_t seed)
        : p_(p), rng_(seed), dist_(0.0, 1.0) {
        assert(p >= 0.0 && p <= 1.0);
    }

    bool drop(size_t /*packet_index*/) {
        return dist_(rng_) < p_;
    }

    const char* name() const { return "uniform"; }

private:
    double p_;
    std::mt19937_64 rng_;
    std::uniform_real_distribution<double> dist_;
};

// ---------------------------------------------------------------------------
// Gilbert-Elliott two-state burst loss.
//
// Two states: GOOD (delivers every packet) and BAD (drops every packet).
// This is the "simplified" GE with p_good = 0, p_bad = 1, matching the
// plan (§3.2). The transition probabilities are chosen so that the
// expected time spent in BAD is `burst_mean` packets and in GOOD is
// `gap_mean` packets.
//
// For a two-state Markov chain, if the probability of leaving a state
// on each step is q, the geometric dwell time has mean 1/q. So:
//     P(GOOD -> BAD) = 1 / gap_mean
//     P(BAD  -> GOOD) = 1 / burst_mean
// ---------------------------------------------------------------------------
class GilbertElliottLoss {
public:
    GilbertElliottLoss(double burst_mean, double gap_mean, uint64_t seed)
        : p_good_to_bad_(1.0 / gap_mean),
          p_bad_to_good_(1.0 / burst_mean),
          rng_(seed),
          dist_(0.0, 1.0),
          in_bad_state_(false) {
        assert(burst_mean >= 1.0);
        assert(gap_mean >= 1.0);
    }

    bool drop(size_t /*packet_index*/) {
        // Step the chain *before* emitting, so the very first packet
        // can be either good or bad depending on the RNG. This gives
        // a slightly cleaner distribution than sticking in GOOD for
        // the first sample.
        const double u = dist_(rng_);
        if (in_bad_state_) {
            if (u < p_bad_to_good_) in_bad_state_ = false;
        } else {
            if (u < p_good_to_bad_) in_bad_state_ = true;
        }
        return in_bad_state_;
    }

    const char* name() const { return "ge"; }

private:
    double p_good_to_bad_;
    double p_bad_to_good_;
    std::mt19937_64 rng_;
    std::uniform_real_distribution<double> dist_;
    bool in_bad_state_;
};

// ---------------------------------------------------------------------------
// Periodic burst loss: deterministic. Drop `burst_len` consecutive
// packets out of every `period` packets. The seed is accepted for
// interface uniformity but is unused.
// ---------------------------------------------------------------------------
class PeriodicLoss {
public:
    PeriodicLoss(size_t period, size_t burst_len, uint64_t /*seed*/)
        : period_(period), burst_len_(burst_len) {
        assert(period >= 1);
        assert(burst_len <= period);
    }

    bool drop(size_t packet_index) {
        return (packet_index % period_) < burst_len_;
    }

    const char* name() const { return "periodic"; }

private:
    size_t period_;
    size_t burst_len_;
};

} // namespace fec_bench

#endif // FEC_BENCH_CHANNEL_MODEL_HPP
