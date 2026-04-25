#pragma once
/*
 * Legacy 64-bit FP computation (matches magic_wand_sieve.py compute_fp64).
 *
 * 64 forward y-parity bits starting at k*G:
 *   bit i = (y((k+i)*G) <= P_HALF) ? 1 : 0
 *
 * Used for back-compat with the deck Redis (1.96B existing entries) and
 * as an L0 prior cache in the new triple-index oracle.
 */

#include "../secp256k1/SECP256k1.h"
#include "../secp256k1/Int.h"
#include <cstdint>

namespace magicwand {

/* Compute fp64 for scalar k. */
uint64_t compute_fp64(Secp256K1 *secp, uint64_t k);

/* Compute fp64 from a precomputed point Q = k*G (skips one ComputePublicKey). */
uint64_t compute_fp64_from_point(Secp256K1 *secp, Point Q);

} /* namespace magicwand */
