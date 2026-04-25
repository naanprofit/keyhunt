#pragma once
/*
 * Y-sign rainbow merge.
 *
 * Bridges the magic_wand FP oracle (which maps FP -> scalar k for known
 * scalars) with the Y-sign rainbow technique from
 *   YSIGN_RAINBOW_TECHNIQUE.md (Apr 2026)
 * which builds a single relative-offset table and reuses it across
 * arbitrary ranges via Q = P - R*G translation.
 *
 * KEY IDEA
 * ========
 *   fingerprint(P) depends only on the relative offset r when
 *   P = R*G + r*G, because translating both sides by -R*G gives
 *   Q = r*G whose fingerprint is determined entirely by r.
 *
 *   So if we have a table of (fp, r) for r in [0, 2^N), we can attack
 *   ANY range [R, R+2^N) by:
 *       1. Compute Q = P - R*G                (one EC subtraction)
 *       2. Compute fp = compute_fp64(Q.x, Q.y) (64 EC adds)
 *       3. Look up fp in the rainbow table -> r
 *       4. k = R + r
 *
 * This module reuses the existing magic_wand oracle's fp / fp127f /
 * fp127b / xset indexes, but in a different *interpretation* of the
 * stored value: instead of "absolute scalar k for which we computed
 * this FP", we store "relative offset r such that fp(r*G) = this FP".
 *
 * To distinguish, rainbow tables use a different Redis namespace:
 *   rfp:<16hex>          -> 8-byte LE relative offset r
 *   rfp127f:<32hex>      -> 8-byte LE relative offset r
 *   rxset:<16hex>        -> 8-byte LE relative offset r
 *
 * Because the rainbow table is a SHARED resource across all attacks,
 * we don't store fp127b (which would be shifted differently for each
 * range and isn't translation-invariant in the same way).
 */

#include "oracle_schema.h"
#include "oracle_client.h"
#include "../secp256k1/SECP256k1.h"
#include "../secp256k1/Point.h"
#include "../secp256k1/Int.h"
#include <cstdint>
#include <string>
#include <vector>

namespace magicwand {

/* Rainbow-namespaced key generators. */
std::string rfp_key(uint64_t fp64);                      /* "rfp:<16hex>" */
std::string rfp127f_key(const FP127 &fp);                /* "rfp127f:<32hex>" */
std::string rxset_key(XSet64 x);                         /* "rxset:<16hex>" */

/* Attack ANY range [R_base, R_base + 2^bits) using a precomputed
 * rainbow table that covers [0, 2^bits).
 *
 * Returns true and sets *k_out if a hit is recovered (then verified by
 * recomputing pubkey and matching against target). Returns false if no
 * hit was found in the rainbow table for this offset.
 *
 * Internally:
 *   - subtracts R_base*G from target to obtain Q = r*G
 *   - computes fp64(Q), fp127f(Q), xset(Q)
 *   - probes all three rainbow indexes and uses 2-of-3 voting like
 *     triple_lookup
 *   - on positive match recomputes (R_base + r)*G and compares to
 *     target Q to reject false positives
 */
bool attack_range(OracleClient &cli,
                  Secp256K1 &secp,
                  const Point &target,        /* P = k*G */
                  const Int &R_base,          /* range start */
                  uint64_t *k_out);

/* Build a rainbow-table entry batch for relative offsets [r_lo, r_hi).
 * Computes fp64, fp127f, xset for each r and inserts into the rainbow
 * namespace via batch_insert_*-style MSET pipelines.
 *
 * NOTE: the relative table never includes the absolute scalar; only
 * the relative offset r is stored as the value.
 */
bool build_rainbow_range(OracleClient &cli,
                         Secp256K1 &secp,
                         uint64_t r_lo,
                         uint64_t r_hi,
                         size_t batch);

/* Diagnostic: count rainbow-namespace keys (uses SCAN for safety
 * but is O(N) on large datasets). */
uint64_t rainbow_table_size(OracleClient &cli);

} /* namespace magicwand */
