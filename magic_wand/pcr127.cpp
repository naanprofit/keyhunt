#include "pcr127.h"

namespace magicwand {

/*
 * P_HALF constant: (P - 1) / 2 where P is the secp256k1 prime.
 * P = 2^256 - 2^32 - 977 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
 * P_HALF = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFE17
 *
 * A point (x, y) has "low y" (y <= P_HALF) or "high y" (y > P_HALF). For the
 * y-parity FP this gives a deterministic 1-bit signal per point, matching the
 * Python compute_fp64 semantics (qy <= P_HALF => bit set).
 */
static const char *P_HALF_HEX =
    "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFE17";

/* ------------------------------------------------------------------ */
/* Forward PCR127                                                      */
/* ------------------------------------------------------------------ */

PCR127Forward::PCR127Forward(Secp256K1 *secp) : secp_(secp), k_(0) {
    p_half_.SetBase16((char *)P_HALF_HEX);
}

bool PCR127Forward::y_is_low_(const Point &p) const {
    Point tmp = p;
    return tmp.y.IsLowerOrEqual(const_cast<Int *>(&p_half_));
}

FP127 PCR127Forward::init_at(uint64_t k) {
    k_ = k;
    Int k_int((uint64_t)k);
    head_ = secp_->ComputePublicKey(&k_int);
    Int k_tail((uint64_t)(k + 127));
    tail_ = secp_->ComputePublicKey(&k_tail);

    fp_.hi = 0;
    fp_.lo = 0;

    /* Walk 127 forward points from k*G, collect y-parity bits into a
     * 127-bit FP. Bit i corresponds to y-parity of (k + i)*G. */
    Point q = head_;
    for (int i = 0; i < 127; i++) {
        bool low = y_is_low_(q);
        if (low) {
            if (i < 64) fp_.lo |= ((uint64_t)1 << i);
            else         fp_.hi |= ((uint64_t)1 << (i - 64));
        }
        if (i < 126) q = secp_->AddDirect(q, secp_->G);
    }
    return fp_;
}

FP127 PCR127Forward::step_forward() {
    /* Shift FP left by 1, dropping MSB (bit 126); add new LSB from head
     * of NEXT window (i.e., the point that WAS at position 1 and will
     * become position 0). But since y-parity of bit 0 in the old window
     * was y-parity of k*G, and bit 0 in the new window is y-parity of
     * (k+1)*G, we actually shift RIGHT by 1 and fill MSB with the NEW
     * tail bit.
     *
     * Reasoning: FP_k bit i = parity((k+i)*G). FP_{k+1} bit i =
     * parity((k+1+i)*G) = FP_k bit (i+1). So FP_{k+1} = FP_k >> 1, with
     * the new MSB (bit 126) coming from parity((k+1+126)*G) =
     * parity((k+127)*G) = parity(tail_).
     */
    bool tail_low = y_is_low_(tail_);

    /* shift 127-bit fp right by 1 */
    uint64_t new_lo = (fp_.lo >> 1) | ((fp_.hi & 1ULL) << 63);
    uint64_t new_hi = fp_.hi >> 1;
    if (tail_low) new_hi |= ((uint64_t)1 << 62); /* bit 126 of full FP = bit 62 of hi */

    fp_.lo = new_lo;
    fp_.hi = new_hi;

    /* Advance head and tail by one G each. */
    head_ = secp_->AddDirect(head_, secp_->G);
    tail_ = secp_->AddDirect(tail_, secp_->G);
    k_++;
    return fp_;
}

/* ------------------------------------------------------------------ */
/* Backward PCR127                                                     */
/* ------------------------------------------------------------------ */

PCR127Backward::PCR127Backward(Secp256K1 *secp) : secp_(secp), k_(0) {
    p_half_.SetBase16((char *)P_HALF_HEX);
}

bool PCR127Backward::y_is_low_(const Point &p) const {
    Point tmp = p;
    return tmp.y.IsLowerOrEqual(const_cast<Int *>(&p_half_));
}

FP127 PCR127Backward::init_at(uint64_t k) {
    k_ = k;
    Int k_int((uint64_t)k);
    head_ = secp_->ComputePublicKey(&k_int);

    /* tail = (k - 127) * G. If k < 127 the window underflows; clamp at 1.
     * For k < 127 the backward FP has fewer than 127 valid bits; the
     * remaining high bits are zero. */
    uint64_t k_tail = (k > 127) ? (k - 127) : 1;
    Int k_tail_int((uint64_t)k_tail);
    tail_ = secp_->ComputePublicKey(&k_tail_int);

    fp_.hi = 0;
    fp_.lo = 0;

    /* Walk 127 points backward from (k-1)*G to (k-127)*G.
     * Bit i = parity of (k - 1 - i)*G. */
    Point negG = secp_->Negation(secp_->G);
    Point q = head_;
    q = secp_->AddDirect(q, negG);  /* q = (k-1)*G */
    for (int i = 0; i < 127; i++) {
        if (k <= (uint64_t)(i + 1)) break;  /* underflow guard */
        bool low = y_is_low_(q);
        if (low) {
            if (i < 64) fp_.lo |= ((uint64_t)1 << i);
            else         fp_.hi |= ((uint64_t)1 << (i - 64));
        }
        if (i < 126) q = secp_->AddDirect(q, negG);
    }
    return fp_;
}

FP127 PCR127Backward::step_backward() {
    /* Moving from k to k-1: FP_b bit i at k = parity((k-1-i)*G).
     * FP_b bit i at k-1 = parity((k-2-i)*G) = FP_b bit (i+1) at k.
     * So FP_{k-1} = FP_k >> 1, new MSB (bit 126) = parity((k-1-127)*G)
     * = parity(tail_ regressed by 1) = parity of the NEW tail.
     *
     * Before the shift we need to move head and tail backward by one G.
     */
    Point negG = secp_->Negation(secp_->G);
    head_ = secp_->AddDirect(head_, negG);
    tail_ = secp_->AddDirect(tail_, negG);
    k_--;

    bool tail_low = y_is_low_(tail_);
    uint64_t new_lo = (fp_.lo >> 1) | ((fp_.hi & 1ULL) << 63);
    uint64_t new_hi = fp_.hi >> 1;
    if (tail_low) new_hi |= ((uint64_t)1 << 62);
    fp_.lo = new_lo;
    fp_.hi = new_hi;
    return fp_;
}

} /* namespace magicwand */
