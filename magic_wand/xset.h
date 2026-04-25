#pragma once
/*
 * X-set: extract first 64 bits of X(k*G) as the third independent oracle
 * signal. This is a COMPUTED value (not stored alongside k in Redis); the
 * Redis index xset:<hex> maps that 64-bit X fragment back to k.
 *
 * Encoding: Int.Get32Bytes produces a big-endian 32-byte serialization
 * of X (high byte first). We take the FIRST 8 bytes (the high 8 bytes
 * of X, i.e., the most significant 64 bits of the 256-bit X coordinate).
 *
 * Rationale: taking the HIGH bits means the X-fragment is roughly
 * uniformly distributed even when scalars cluster (the low bits of X(k*G)
 * have less pseudo-random structure in small-k regimes than the high).
 */

#include "oracle_schema.h"
#include "../secp256k1/Point.h"
#include <cstdint>

namespace magicwand {

inline XSet64 extract_xset64(const Point &p) {
    Point tmp = p;
    unsigned char buf[32];
    tmp.x.Get32Bytes(buf);
    /* Get32Bytes returns little-endian per keyhunt convention.
     * For the "high 64 bits of X" we want the big-endian high bytes,
     * which are at offsets 24..31 of the LE buffer (since LE reverses
     * byte order from BE). Read them as a BE uint64.
     */
    uint64_t x = 0;
    for (int i = 0; i < 8; i++) {
        x = (x << 8) | (uint64_t)buf[31 - i];
    }
    return x;
}

} /* namespace magicwand */
