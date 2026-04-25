#include "ysign_rainbow.h"
#include "fp64.h"
#include "pcr127.h"
#include "xset.h"
#include <chrono>
#include <cstdio>

namespace magicwand {

/* ------------------------------------------------------------------ */
/* key helpers                                                         */
/* ------------------------------------------------------------------ */

std::string rfp_key(uint64_t fp64) {
    char buf[17];
    snprintf(buf, sizeof(buf), "%016lx", (unsigned long)fp64);
    return "rfp:" + std::string(buf);
}

std::string rfp127f_key(const FP127 &fp) {
    return "rfp127f:" + fp127_hex(fp);
}

std::string rxset_key(XSet64 x) {
    char buf[17];
    snprintf(buf, sizeof(buf), "%016lx", (unsigned long)x);
    return "rxset:" + std::string(buf);
}

/* ------------------------------------------------------------------ */
/* fp127f from arbitrary point (no scalar known)                       */
/* ------------------------------------------------------------------ */

static FP127 fp127f_from_point(Secp256K1 &secp, const Point &P) {
    static const char *P_HALF_HEX =
        "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFE17";
    Int p_half;
    p_half.SetBase16((char *)P_HALF_HEX);

    FP127 fp{0, 0};
    Point q = P;
    for (int i = 0; i < 127; i++) {
        if (q.y.IsLowerOrEqual(&p_half)) {
            if (i < 64) fp.lo |= ((uint64_t)1 << i);
            else        fp.hi |= ((uint64_t)1 << (i - 64));
        }
        if (i < 126) q = secp.AddDirect(q, secp.G);
    }
    return fp;
}

/* ------------------------------------------------------------------ */
/* range attack                                                        */
/* ------------------------------------------------------------------ */

bool attack_range(OracleClient &cli,
                  Secp256K1 &secp,
                  const Point &target,
                  const Int &R_base,
                  uint64_t *k_out) {
    /* Q = target - R_base * G */
    Int R_copy = const_cast<Int &>(R_base);
    Point R_pub = secp.ComputePublicKey(&R_copy);

    /* Special case r=0 (target == R*G).  Q would be the identity which
     * has no FP; just check direct equality. */
    if (R_pub.equals(const_cast<Point &>(target))) {
        if (k_out) *k_out = 0;
        return true;
    }

    Point neg_R = secp.Negation(R_pub);
    Point Q     = secp.AddDirect(const_cast<Point &>(target), neg_R);

    /* Compute three FPs of Q. */
    uint64_t fp64 = compute_fp64_from_point(&secp, Q);
    XSet64   x    = extract_xset64(Q);
    FP127    fp127f = fp127f_from_point(secp, Q);

    /* Probe rainbow namespace. */
    auto p1 = cli.lookup_raw(rfp_key(fp64));
    auto p2 = cli.lookup_raw(rfp127f_key(fp127f));
    auto p3 = cli.lookup_raw(rxset_key(x));

    bool     have[3] = {p1.status == ProbeStatus::HIT,
                        p2.status == ProbeStatus::HIT,
                        p3.status == ProbeStatus::HIT};
    uint64_t cands[3] = {p1.k, p2.k, p3.k};

    /* 2-of-3 voting; fp127f single-hit is also acceptable since 127
     * bits has very low collision probability. */
    int      matches = 0;
    uint64_t consensus_r = 0;
    for (int i = 0; i < 3; i++) {
        if (!have[i]) continue;
        for (int j = i + 1; j < 3; j++) {
            if (!have[j]) continue;
            if (cands[i] == cands[j]) {
                matches++;
                consensus_r = cands[i];
            }
        }
    }
    bool good = (matches >= 1) || (have[1] && !have[0] && !have[2]);
    if (!good) return false;
    uint64_t r = (matches >= 1) ? consensus_r : cands[1];

    /* Verify by recomputing (R + r) * G and comparing to target. */
    Int R_plus_r = const_cast<Int &>(R_base);
    Int r_int((uint64_t)r);
    R_plus_r.Add(&r_int);
    Point check = secp.ComputePublicKey(&R_plus_r);
    if (!check.equals(const_cast<Point &>(target))) {
        return false;  /* honest rejection of false positive. */
    }
    if (k_out) *k_out = r;
    return true;
}

/* ------------------------------------------------------------------ */
/* table builder                                                       */
/* ------------------------------------------------------------------ */

bool build_rainbow_range(OracleClient &cli,
                         Secp256K1 &secp,
                         uint64_t r_lo,
                         uint64_t r_hi,
                         size_t batch) {
    using namespace std::chrono;
    auto t0 = steady_clock::now();

    std::vector<std::pair<std::string, uint64_t>> buf_rfp;
    std::vector<std::pair<std::string, uint64_t>> buf_rfp127f;
    std::vector<std::pair<std::string, uint64_t>> buf_rxset;
    buf_rfp.reserve(batch);
    buf_rfp127f.reserve(batch);
    buf_rxset.reserve(batch);

    PCR127Forward pcr_f(&secp);

    uint64_t total = r_hi - r_lo;
    uint64_t processed = 0;

    for (uint64_t r = r_lo; r < r_hi; r++) {
        Int rr((uint64_t)r);
        Point Q = secp.ComputePublicKey(&rr);

        uint64_t fp64 = compute_fp64_from_point(&secp, Q);
        XSet64   x    = extract_xset64(Q);
        FP127    fpf  = pcr_f.init_at(r);

        buf_rfp.emplace_back(rfp_key(fp64), r);
        buf_rxset.emplace_back(rxset_key(x), r);
        buf_rfp127f.emplace_back(rfp127f_key(fpf), r);

        bool flush_now = (buf_rfp.size() >= batch || (r + 1 == r_hi));
        if (flush_now) {
            if (!buf_rfp.empty()     && !cli.batch_insert_raw(buf_rfp))     return false;
            if (!buf_rxset.empty()   && !cli.batch_insert_raw(buf_rxset))   return false;
            if (!buf_rfp127f.empty() && !cli.batch_insert_raw(buf_rfp127f)) return false;
            buf_rfp.clear(); buf_rfp127f.clear(); buf_rxset.clear();
        }

        processed++;
        if (processed % 10000 == 0 || processed == total) {
            auto el = duration_cast<duration<double>>(steady_clock::now() - t0).count();
            double rate = el > 0 ? processed / el : 0;
            fprintf(stderr, "\r[rainbow] %llu/%llu %.0f r/s elapsed=%.1fs",
                    (unsigned long long)processed, (unsigned long long)total,
                    rate, el);
            fflush(stderr);
        }
    }
    fprintf(stderr, "\n");
    return true;
}

uint64_t rainbow_table_size(OracleClient &cli) {
    return cli.db_size();
}

} /* namespace magicwand */
