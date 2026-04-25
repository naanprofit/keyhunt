/*
 * Y-sign rainbow round-trip test.
 *
 * 1. Build a 1024-entry rainbow table covering relative offsets [0, 1024).
 * 2. For an arbitrary range start R (e.g., 2^49 = puzzle 50 base),
 *    pick a target k = R + r  (r < 1024).
 * 3. Compute target public key P = k*G.
 * 4. Run attack_range(P, R) and verify it recovers r.
 *
 * If this works, the y-sign rainbow technique is proven end-to-end:
 * a small relative-offset table can attack arbitrary ranges by EC
 * translation.
 */

#include "ysign_rainbow.h"
#include "fp64.h"
#include "../secp256k1/SECP256k1.h"
#include "../secp256k1/Int.h"
#include <cstdio>
#include <cstdlib>

using namespace magicwand;

static void hex_to_int(const char *hex, Int &out) {
    out.SetBase16((char *)hex);
}

int main(int argc, char **argv) {
    /* Args: [host port db r_lo r_hi range_hex test_offsets...] */
    int        argi = 1;
    const char *host = (argc > argi) ? argv[argi++] : "127.0.0.1";
    int         port = (argc > argi) ? atoi(argv[argi++]) : 6379;
    int         db   = (argc > argi) ? atoi(argv[argi++]) : 14;
    uint64_t    r_lo = (argc > argi) ? strtoull(argv[argi++], nullptr, 0) : 0ULL;
    uint64_t    r_hi = (argc > argi) ? strtoull(argv[argi++], nullptr, 0) : 1024ULL;
    /* Range start hex; default = 2^49 (puzzle 50 lower bound). */
    const char *R_hex = (argc > argi) ? argv[argi++] : "2000000000000";

    Secp256K1 secp;
    secp.Init();

    OracleConfig cfg;
    cfg.host = host;
    cfg.port = port;
    cfg.db_index = db;
    OracleClient cli(cfg);
    if (!cli.connect()) { printf("connect FAIL\n"); return 1; }

    printf("=== Y-sign rainbow build [%llu, %llu) ===\n",
           (unsigned long long)r_lo, (unsigned long long)r_hi);

    /* Wipe rainbow namespace in this db (use FLUSHDB on dedicated db). */
    {
        /* No FLUSHDB exposed via public API; user runs it before. */
    }

    if (!build_rainbow_range(cli, secp, r_lo, r_hi, 256)) {
        printf("build FAIL\n");
        return 1;
    }
    printf("dbsize = %llu (expected ~%llu)\n",
           (unsigned long long)cli.db_size(),
           (unsigned long long)(3 * (r_hi - r_lo)));

    /* Now attack range [R, R+r_hi). */
    Int R_base;
    hex_to_int(R_hex, R_base);
    printf("\n=== attacking range starting at hex %s ===\n", R_hex);

    /* Pick a few targets within the range. */
    int fails = 0;
    uint64_t test_offsets[] = {0, 1, 7, 100, 511, 1000, r_hi - 1};
    for (uint64_t r_test : test_offsets) {
        if (r_test >= r_hi) continue;

        /* k = R + r_test */
        Int k_target = R_base;
        Int r_int((uint64_t)r_test);
        k_target.Add(&r_int);

        Point P = secp.ComputePublicKey(&k_target);

        uint64_t r_recovered = 0;
        bool ok = attack_range(cli, secp, P, R_base, &r_recovered);
        if (ok && r_recovered == r_test) {
            printf("  r=%llu  recovered=%llu  OK\n",
                   (unsigned long long)r_test,
                   (unsigned long long)r_recovered);
        } else {
            printf("  r=%llu  recovered=%llu  ok=%d  FAIL\n",
                   (unsigned long long)r_test,
                   (unsigned long long)r_recovered, (int)ok);
            fails++;
        }
    }

    /* Negative test: target NOT in the rainbow table range. */
    {
        Int k_outside = R_base;
        Int huge((uint64_t)(r_hi + 1000000));
        k_outside.Add(&huge);
        Point P = secp.ComputePublicKey(&k_outside);
        uint64_t r_out = 0;
        bool ok = attack_range(cli, secp, P, R_base, &r_out);
        printf("  negative test (k outside r table): ok=%d r=%llu  %s\n",
               (int)ok, (unsigned long long)r_out,
               !ok ? "OK (correct miss)" : "FAIL (false positive)");
        if (ok) fails++;
    }

    return fails == 0 ? 0 : 1;
}
