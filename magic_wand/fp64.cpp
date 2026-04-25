#include "fp64.h"

namespace magicwand {

static const char *P_HALF_HEX =
    "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFE17";

uint64_t compute_fp64_from_point(Secp256K1 *secp, Point Q) {
    Int p_half;
    p_half.SetBase16((char *)P_HALF_HEX);

    uint64_t fp = 0;
    Point q = Q;
    for (int i = 0; i < 64; i++) {
        if (q.y.IsLowerOrEqual(&p_half)) {
            fp |= ((uint64_t)1 << i);
        }
        q = secp->AddDirect(q, secp->G);
    }
    return fp;
}

uint64_t compute_fp64(Secp256K1 *secp, uint64_t k) {
    Int k_int(k);
    Point Q = secp->ComputePublicKey(&k_int);
    return compute_fp64_from_point(secp, Q);
}

} /* namespace magicwand */
