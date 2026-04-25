/*
 * Full oracle round-trip test: fill -> probe all 4 indexes for the
 * same scalar k and verify each returns k.
 *
 * Assumes fill_worker has populated db=15 with [k_lo, k_hi).
 */

#include "oracle_client.h"
#include "fp64.h"
#include "pcr127.h"
#include "xset.h"
#include "../secp256k1/SECP256k1.h"
#include "../secp256k1/Int.h"
#include <cstdio>
#include <cstdlib>

using namespace magicwand;

int main(int argc, char **argv) {
    uint64_t k = (argc > 1) ? strtoull(argv[1], nullptr, 0) : 1000500ULL;
    int      db = (argc > 2) ? atoi(argv[2]) : 15;

    Secp256K1 secp;
    secp.Init();

    OracleConfig cfg;
    cfg.db_index = db;
    OracleClient cli(cfg);
    if (!cli.connect()) { printf("connect FAIL\n"); return 1; }

    Int kk((uint64_t)k);
    Point Q = secp.ComputePublicKey(&kk);
    uint64_t fp64 = compute_fp64_from_point(&secp, Q);
    XSet64   x    = extract_xset64(Q);

    PCR127Forward  pcr_f(&secp);
    PCR127Backward pcr_b(&secp);
    FP127 fpf = pcr_f.init_at(k);
    FP127 fpb = pcr_b.init_at(k);

    int fails = 0;

    auto check = [&](const char *name, ProbeResult r, uint64_t expected) {
        bool ok = (r.status == ProbeStatus::HIT && r.k == expected);
        printf("  %-12s status=%-5s k_recovered=%llu %s\n",
               name,
               r.status == ProbeStatus::HIT ? "HIT" :
               r.status == ProbeStatus::MISS ? "MISS" : "ERR",
               (unsigned long long)r.k,
               ok ? "OK" : "FAIL");
        if (!ok) fails++;
    };

    printf("Probing k=%llu (Q.x_high64=0x%016llx fp64=0x%016llx)\n",
           (unsigned long long)k,
           (unsigned long long)x,
           (unsigned long long)fp64);
    check("fp64",        cli.lookup_fp64(fp64), k);
    check("fp127f",      cli.lookup_fp127f(fpf), k);
    check("fp127b",      cli.lookup_fp127b(fpb), k);
    check("xset",        cli.lookup_xset(x), k);

    /* Triple lookup with full triple agrees. */
    auto rt = cli.triple_lookup(fpf, fpb, x);
    bool ok = (rt.status == ProbeStatus::HIT && rt.k == k);
    printf("  triple_lookup status=%s k=%llu %s\n",
           rt.status == ProbeStatus::HIT ? "HIT" :
           rt.status == ProbeStatus::MISS ? "MISS" : "ERR",
           (unsigned long long)rt.k,
           ok ? "OK" : "FAIL");
    if (!ok) fails++;

    return fails ? 1 : 0;
}
