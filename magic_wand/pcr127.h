#pragma once
/*
 * PCR (Pollard Chained Recursion) sliding window for 127-bit y-parity FPs.
 *
 * Incremental FP computation: given FP(k) = 127 y-parity bits of the walk
 *   k*G, (k+1)*G, ..., (k+126)*G
 * the next FP(k+1) shares 126 bits with FP(k) -- shift and add one new bit
 * from the tail point (k+127)*G.
 *
 * Speedup vs cold FP recomputation: ~127x (one EC add instead of 127).
 *
 * Forward and backward variants share state. Both require maintaining a
 * tail point; forward tail advances, backward tail regresses.
 *
 * All EC operations delegated to keyhunt's Secp256K1 class.
 */

#include "oracle_schema.h"
#include "../secp256k1/SECP256k1.h"
#include "../secp256k1/Int.h"
#include <cstdint>

namespace magicwand {

class PCR127Forward {
public:
    explicit PCR127Forward(Secp256K1 *secp);

    /* Initialize window at position k. Computes FP(k) from scratch
     * (127 EC additions). */
    FP127 init_at(uint64_t k);

    /* Advance window to k+1. O(1): one EC add on head and tail points
     * plus FP shift. Returns FP(k+1). */
    FP127 step_forward();

    /* Return current scalar and FP without stepping. */
    uint64_t current_k() const { return k_; }
    const FP127 &current_fp() const { return fp_; }
    const Point &current_point() const { return head_; }

private:
    Secp256K1 *secp_;
    uint64_t   k_;
    Point      head_;   /* k * G */
    Point      tail_;   /* (k + 127) * G */
    FP127      fp_;

    /* P_HALF constant for y-parity test.
     * secp256k1 prime P, P_HALF = P / 2 (integer division). */
    Int p_half_;

    bool y_is_low_(const Point &p) const;
};

class PCR127Backward {
public:
    explicit PCR127Backward(Secp256K1 *secp);

    /* Initialize window at position k. Computes FP_b(k) = 127 y-parity
     * bits of the walk (k-1)*G, (k-2)*G, ..., (k-127)*G from scratch. */
    FP127 init_at(uint64_t k);

    /* Step window to k-1. Returns FP_b(k-1). */
    FP127 step_backward();

    uint64_t current_k() const { return k_; }
    const FP127 &current_fp() const { return fp_; }
    const Point &current_point() const { return head_; }

private:
    Secp256K1 *secp_;
    uint64_t   k_;
    Point      head_;   /* k * G */
    Point      tail_;   /* (k - 127) * G */
    FP127      fp_;
    Int        p_half_;

    bool y_is_low_(const Point &p) const;
};

} /* namespace magicwand */
