#pragma once
/*
 * Magic Wand oracle client.
 *
 * Thin wrapper around hiredis (synchronous mode) for lookup, batch insert,
 * and fill-queue dispatch against the magic_wand schema.
 *
 * Designed for both:
 *   - In-process embedded use from keyhunt / bsgsd / future tools
 *   - Out-of-process workers reading the fill queue (BLPOP) and
 *     writing computed FPs back via batch HMSET
 *
 * Connection model: one OracleClient per thread. Internal hiredis context
 * is non-thread-safe; callers should use OraclePool for multi-thread.
 */

#include "oracle_schema.h"
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

struct redisContext;

namespace magicwand {

struct OracleConfig {
    std::string host;       /* default: 127.0.0.1 */
    uint16_t    port;       /* default: 6379 */
    std::string password;   /* empty for no AUTH */
    int         db_index;   /* default: 0 */
    int         timeout_ms; /* default: 5000 */

    OracleConfig() : host("127.0.0.1"), port(6379), db_index(0), timeout_ms(5000) {}
};

/* Probe result tag for any of the four lookup channels. */
enum class ProbeStatus {
    HIT,            /* exact key found, k recovered */
    MISS,           /* key not in oracle, no fill enqueued */
    PENDING_FILL,   /* miss, fill job dispatched, retry later */
    ERROR           /* network or schema error */
};

struct ProbeResult {
    ProbeStatus status;
    uint64_t    k;          /* valid only on HIT */
    std::string error_message;
    std::string fill_id;    /* valid only on PENDING_FILL */
};

class OracleClient {
public:
    explicit OracleClient(const OracleConfig &cfg = OracleConfig());
    ~OracleClient();
    OracleClient(const OracleClient &) = delete;
    OracleClient &operator=(const OracleClient &) = delete;

    bool connect();
    bool is_connected() const;

    /* Single-channel exact lookups. All return HIT on success. */
    ProbeResult lookup_fp64(uint64_t fp);
    ProbeResult lookup_fp127f(const FP127 &fp);
    ProbeResult lookup_fp127b(const FP127 &fp);
    ProbeResult lookup_fpcombo127(const FP127 &fp);
    ProbeResult lookup_xset(XSet64 x);

    /* Triple-signal lookup. Probes fp127f, fp127b, and xset; returns HIT
     * only if at least 2 of the 3 channels return the same scalar (third
     * signal acts as anti-collision veto). On a single-channel hit returns
     * MISS so callers can decide whether to flood-fill. */
    ProbeResult triple_lookup(const FP127 &fp_fwd, const FP127 &fp_bwd, XSet64 x);

    /* Batch insert. Pipelines N MSETs in one round-trip. Used by fill workers. */
    bool batch_insert_fp64(const std::vector<std::pair<uint64_t, uint64_t>> &fp_to_k);
    bool batch_insert_fp127f(const std::vector<std::pair<FP127, uint64_t>> &fp_to_k);
    bool batch_insert_fp127b(const std::vector<std::pair<FP127, uint64_t>> &fp_to_k);
    bool batch_insert_xset(const std::vector<std::pair<XSet64, uint64_t>> &x_to_k);

    /* Fill-queue ops. */
    struct FillJob {
        uint64_t k_lo;       /* inclusive */
        uint64_t k_hi;       /* exclusive */
        std::string fields;  /* comma-separated subset of fp,fp127f,fp127b,xset */
        int      priority;   /* higher = sooner */
        std::string requested_by;
    };

    bool        enqueue_fill(const FillJob &job, std::string *fill_id_out = nullptr);
    /* Block until a job is available or timeout_seconds elapses. Returns
     * empty FillJob on timeout. */
    FillJob     blpop_fill(double timeout_seconds, const std::string &worker_id);
    bool        ack_fill(const std::string &worker_id, const std::string &fill_id);
    bool        publish_fill_done(uint64_t k_lo, uint64_t k_hi);

    /* Generic raw access for rainbow / non-fp namespaces. */
    ProbeResult lookup_raw(const std::string &key);
    bool        batch_insert_raw(
        const std::vector<std::pair<std::string, uint64_t>> &kv_to_value);

    /* Diagnostics. */
    uint64_t db_size();      /* DBSIZE */
    bool     ping();

private:
    OracleConfig cfg_;
    redisContext *ctx_;      /* opaque hiredis handle */
};

} /* namespace magicwand */
