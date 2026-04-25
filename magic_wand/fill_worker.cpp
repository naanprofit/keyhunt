/*
 * Magic Wand fill worker (single-threaded, in-process).
 *
 * For a [k_lo, k_hi) range, computes:
 *   fp:<fp64>           legacy 64-bit FP
 *   fp127f:<fp127>      127 forward bits
 *   fp127b:<fp127>      127 backward bits
 *   xset:<x_high_64>    high 64 bits of X(k*G)
 * and inserts them into the configured Redis instance via batched MSET.
 *
 * Used both standalone (./fill_worker host port k_lo k_hi) and as the
 * core of the BLPOP fill-queue daemon (TODO: separate cmdline mode).
 *
 * Performance: single-threaded ~5-10k k/sec on fozzie. Multi-thread
 * variant queued for next iteration.
 *
 * Build: linked against the same .o files as test_oracle_client.
 */

#include "oracle_client.h"
#include "fp64.h"
#include "pcr127.h"
#include "xset.h"
#include "../secp256k1/SECP256k1.h"
#include "../secp256k1/Int.h"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>

using namespace std::chrono;
using namespace magicwand;

static void usage() {
    fprintf(stderr, "Usage: fill_worker [--host H] [--port P] [--db D]\n");
    fprintf(stderr, "                   [--fields fp,fp127f,fp127b,xset]\n");
    fprintf(stderr, "                   [--batch N] --range k_lo k_hi\n");
    fprintf(stderr, "       fill_worker --queue [--worker-id ID] [...]\n");
    fprintf(stderr, "          (consume jobs from fill:queue indefinitely)\n");
    exit(1);
}

struct Args {
    std::string host = "127.0.0.1";
    uint16_t    port = 6379;
    int         db   = 0;
    std::string fields = "fp,fp127f,fp127b,xset";
    size_t      batch = 1024;
    uint64_t    k_lo = 0;
    uint64_t    k_hi = 0;
    bool        queue_mode = false;
    std::string worker_id = "";
};

static uint64_t parse_u64(const char *s) {
    return strtoull(s, nullptr, 0);
}

static Args parse(int argc, char **argv) {
    Args a;
    for (int i = 1; i < argc; i++) {
        std::string opt = argv[i];
        auto next = [&](const char *name) -> const char * {
            if (i + 1 >= argc) { fprintf(stderr, "missing arg for %s\n", name); usage(); }
            return argv[++i];
        };
        if (opt == "--host")        a.host = next("--host");
        else if (opt == "--port")   a.port = (uint16_t)atoi(next("--port"));
        else if (opt == "--db")     a.db = atoi(next("--db"));
        else if (opt == "--fields") a.fields = next("--fields");
        else if (opt == "--batch")  a.batch = (size_t)parse_u64(next("--batch"));
        else if (opt == "--range") {
            a.k_lo = parse_u64(next("--range[lo]"));
            a.k_hi = parse_u64(next("--range[hi]"));
        }
        else if (opt == "--queue")  a.queue_mode = true;
        else if (opt == "--worker-id") a.worker_id = next("--worker-id");
        else if (opt == "-h" || opt == "--help") usage();
        else { fprintf(stderr, "unknown arg %s\n", opt.c_str()); usage(); }
    }
    if (!a.queue_mode && a.k_hi <= a.k_lo) usage();
    return a;
}

/* Match a comma-separated field list against a needle without false-positive
 * substrings (so "fp" doesn't match "fp127f"). */
static bool wants_field(const std::string &fields, const std::string &name) {
    std::string padded = "," + fields + ",";
    std::string needle = "," + name + ",";
    return padded.find(needle) != std::string::npos;
}

/*
 * Process [k_lo, k_hi) into Redis. Returns true on success.
 *
 * Algorithm:
 *  - For each k, compute Q = k*G via ComputePublicKey (slow, but
 *    PCR127 needs 127-step init anyway and we don't yet have the
 *    cross-step optimization wired through to all four indexes).
 *  - For fp64 we walk forward 64 steps.
 *  - For fp127f we walk forward 127 steps.
 *  - For fp127b we walk backward 127 steps.
 *  - For xset we just take the high 64 bits of Q.x.
 *
 * Future: PCR sliding for fp64 / fp127f gives 64x / 127x speedup but
 * requires pre-staging the head/tail points, which we're skipping here
 * to keep this initial port simple and obviously-correct.
 */
static bool process_range(OracleClient &cli, Secp256K1 &secp,
                          uint64_t k_lo, uint64_t k_hi,
                          const std::string &fields, size_t batch) {
    bool do_fp     = wants_field(fields, "fp");
    bool do_fp127f = wants_field(fields, "fp127f");
    bool do_fp127b = wants_field(fields, "fp127b");
    bool do_xset   = wants_field(fields, "xset");

    std::vector<std::pair<uint64_t, uint64_t>> buf_fp;
    std::vector<std::pair<FP127, uint64_t>>    buf_fp127f;
    std::vector<std::pair<FP127, uint64_t>>    buf_fp127b;
    std::vector<std::pair<XSet64, uint64_t>>   buf_xset;
    buf_fp.reserve(batch);
    buf_fp127f.reserve(batch);
    buf_fp127b.reserve(batch);
    buf_xset.reserve(batch);

    PCR127Forward  pcr_f(&secp);
    PCR127Backward pcr_b(&secp);

    auto t0 = steady_clock::now();
    uint64_t processed = 0;
    uint64_t total = k_hi - k_lo;

    for (uint64_t k = k_lo; k < k_hi; k++) {
        Int kk((uint64_t)k);
        Point Q = secp.ComputePublicKey(&kk);

        if (do_fp) {
            uint64_t fp = compute_fp64_from_point(&secp, Q);
            buf_fp.emplace_back(fp, k);
        }
        if (do_xset) {
            buf_xset.emplace_back(extract_xset64(Q), k);
        }
        if (do_fp127f) {
            FP127 fp = pcr_f.init_at(k);
            buf_fp127f.emplace_back(fp, k);
        }
        if (do_fp127b) {
            FP127 fp = pcr_b.init_at(k);
            buf_fp127b.emplace_back(fp, k);
        }

        bool flush_now = (buf_fp.size() >= batch || buf_fp127f.size() >= batch ||
                          buf_fp127b.size() >= batch || buf_xset.size() >= batch ||
                          (k + 1 == k_hi));
        if (flush_now) {
            if (!buf_fp.empty()    && !cli.batch_insert_fp64(buf_fp))    return false;
            if (!buf_fp127f.empty() && !cli.batch_insert_fp127f(buf_fp127f)) return false;
            if (!buf_fp127b.empty() && !cli.batch_insert_fp127b(buf_fp127b)) return false;
            if (!buf_xset.empty()   && !cli.batch_insert_xset(buf_xset))     return false;
            buf_fp.clear(); buf_fp127f.clear(); buf_fp127b.clear(); buf_xset.clear();
        }

        processed++;
        if (processed % 10000 == 0 || processed == total) {
            auto elapsed = duration_cast<duration<double>>(steady_clock::now() - t0).count();
            double rate = elapsed > 0 ? processed / elapsed : 0;
            double pct = 100.0 * processed / total;
            fprintf(stderr, "\r[fill] %llu/%llu (%.1f%%) %.0f k/s elapsed=%.1fs",
                    (unsigned long long)processed, (unsigned long long)total,
                    pct, rate, elapsed);
            fflush(stderr);
        }
    }
    fprintf(stderr, "\n");
    return true;
}

int main(int argc, char **argv) {
    Args a = parse(argc, argv);

    Secp256K1 secp;
    secp.Init();

    OracleConfig cfg;
    cfg.host = a.host;
    cfg.port = a.port;
    cfg.db_index = a.db;
    OracleClient cli(cfg);
    if (!cli.connect()) {
        fprintf(stderr, "[fill] connect failed\n");
        return 1;
    }
    fprintf(stderr, "[fill] connected to %s:%u db=%d (dbsize=%llu)\n",
            cfg.host.c_str(), (unsigned)cfg.port, cfg.db_index,
            (unsigned long long)cli.db_size());

    if (a.queue_mode) {
        std::string wid = a.worker_id;
        if (wid.empty()) wid = "worker_default";
        fprintf(stderr, "[fill] queue mode worker_id=%s\n", wid.c_str());
        for (;;) {
            auto job = cli.blpop_fill(60.0, wid);
            if (job.k_hi <= job.k_lo) continue;
            fprintf(stderr, "[fill] job [%llx..%llx) fields=%s\n",
                    (unsigned long long)job.k_lo, (unsigned long long)job.k_hi,
                    job.fields.c_str());
            if (!process_range(cli, secp, job.k_lo, job.k_hi, job.fields, a.batch)) {
                fprintf(stderr, "[fill] job FAILED\n");
                continue;
            }
            cli.publish_fill_done(job.k_lo, job.k_hi);
            fprintf(stderr, "[fill] job complete\n");
        }
    } else {
        if (!process_range(cli, secp, a.k_lo, a.k_hi, a.fields, a.batch)) {
            fprintf(stderr, "[fill] process_range FAILED\n");
            return 1;
        }
        fprintf(stderr, "[fill] dbsize after fill = %llu\n",
                (unsigned long long)cli.db_size());
    }
    return 0;
}
