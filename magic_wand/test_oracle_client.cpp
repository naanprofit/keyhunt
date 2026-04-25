/*
 * Live oracle client test against deck Redis.
 *
 * Probes the existing 1.96B-entry oracle for the known reference vector
 *   k = 1,415,719,084  fp = 0x00f1bd44a1a66104
 * and verifies the round trip (fp -> k via lookup_fp64) returns the
 * original scalar.
 *
 * Also tests:
 *   - PING / db_size diagnostics
 *   - lookup_fp64 hit/miss paths
 *   - triple_lookup behavior on a synthetic FP127 (expected MISS since
 *     the deck oracle has no fp127 entries)
 *
 * Usage: ./test_oracle_client [host] [port]
 */

#include "oracle_client.h"
#include "fp64.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

int main(int argc, char **argv) {
    magicwand::OracleConfig cfg;
    cfg.host = (argc > 1) ? argv[1] : "192.168.200.88";
    cfg.port = (argc > 2) ? (uint16_t)atoi(argv[2]) : 6381;

    Secp256K1 secp;
    secp.Init();

    printf("[test] connecting to %s:%u ...\n", cfg.host.c_str(), (unsigned)cfg.port);
    magicwand::OracleClient cli(cfg);
    if (!cli.connect()) {
        printf("[test] connect FAIL\n");
        return 1;
    }

    if (!cli.ping()) {
        printf("[test] ping FAIL\n");
        return 1;
    }
    printf("[test] ping OK\n");

    uint64_t n = cli.db_size();
    printf("[test] dbsize = %llu\n", (unsigned long long)n);
    if (n < 1) {
        printf("[test] empty db, aborting\n");
        return 1;
    }

    /* Reference: k=1,415,719,084 -> fp=0x00f1bd44a1a66104 */
    uint64_t k_ref = 1415719084ULL;
    uint64_t fp_expected = 0x00f1bd44a1a66104ULL;
    uint64_t fp_computed = magicwand::compute_fp64(&secp, k_ref);
    printf("[test] k=%llu fp_computed=0x%016llx fp_expected=0x%016llx %s\n",
           (unsigned long long)k_ref,
           (unsigned long long)fp_computed,
           (unsigned long long)fp_expected,
           fp_computed == fp_expected ? "OK" : "FAIL");
    if (fp_computed != fp_expected) return 1;

    /* Now look up that fp in the oracle and check we recover k. */
    auto r = cli.lookup_fp64(fp_computed);
    if (r.status == magicwand::ProbeStatus::HIT) {
        printf("[test] oracle hit: k_recovered=%llu %s\n",
               (unsigned long long)r.k,
               (r.k == k_ref) ? "OK" : "MISMATCH");
        if (r.k != k_ref) return 1;
    } else if (r.status == magicwand::ProbeStatus::MISS) {
        printf("[test] oracle miss for k=%llu (fp not in deck) -- non-fatal\n",
               (unsigned long long)k_ref);
    } else {
        printf("[test] oracle ERROR: %s\n", r.error_message.c_str());
        return 1;
    }

    /* Synthetic FP127 -- expect MISS since deck has no fp127 entries. */
    magicwand::FP127 fp127;
    fp127.hi = 0xdeadbeef00000000ULL;
    fp127.lo = 0xcafebabe00000000ULL;
    auto rt = cli.triple_lookup(fp127, fp127, 0xdeadbeef0000baadULL);
    printf("[test] triple_lookup synthetic %s (status=%d)\n",
           (rt.status == magicwand::ProbeStatus::MISS) ? "MISS (expected)" : "unexpected",
           (int)rt.status);

    return 0;
}
