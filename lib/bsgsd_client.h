/*
 * libbsgsd_client -- shared TCP/HTTP client for the BSGSD daemon.
 *
 * Used by:
 *   - keyhunt (when it wants to dispatch BSGS work to a remote daemon)
 *   - magic_wand (when oracle fill jobs need bulk BSGS compute against
 *     a remote scalar range)
 *   - any future tool that wants pool-aware BSGSD access
 *
 * Two transports are supported:
 *   * TCP single-line (the original AlbertoBSD protocol):
 *       <pubkey_hex> <from_hex>:<to_hex>\n
 *       reply: hex_priv_key | "404 Not Found" | "400 Bad Request"
 *   * HTTP POST JSON (added in this branch):
 *       Content-Type: application/json
 *       {"pubkey":"...","from":"...","to":"..."}
 *       reply: 200 OK with hex priv key + X-* diagnostic headers,
 *              or 404 / 400 on miss / error.
 *
 * Pool support:
 *   bsgsd_pool_t holds an array of hosts; bsgsd_pool_search round-robins
 *   work across them, with per-host health tracking and retry-on-failure.
 */

#ifndef BSGSD_CLIENT_H
#define BSGSD_CLIENT_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace bsgsd_client {

enum class Transport {
    TCP_SINGLE_LINE,   /* original protocol */
    HTTP_POST_JSON     /* HTTP, supports X-* diagnostics */
};

enum class Status {
    FOUND,             /* private key recovered */
    NOT_FOUND,         /* daemon completed scan, no key in range */
    BAD_REQUEST,       /* daemon rejected the request */
    NETWORK_ERROR,     /* socket / DNS / timeout / EOF */
    TIMEOUT            /* request exceeded max_wait_seconds */
};

struct LaneStats {
    uint64_t probes;
    uint64_t hits;
    uint64_t recovers;
};

struct SearchResult {
    Status status;
    std::string private_key_hex;   /* populated when status==FOUND */
    double elapsed_seconds;        /* server-reported wall time */

    /* Honest-counter diagnostics, populated only when daemon was started
     * with --honest-counter and the HTTP transport was used.  Zero
     * otherwise. */
    uint64_t total_steps;
    LaneStats lanes[3];
    std::string bsgs_endo_mode;    /* "off" | "keyhunt" | "glv12" | "" */
    int gpu_bloom;                 /* 0 or 1; -1 if unknown */

    /* Last error message from the network / parsing layer.  Useful for
     * debugging pool failover. */
    std::string error_message;
};

struct HostSpec {
    std::string host;              /* hostname or IPv4 literal */
    uint16_t    port;
    Transport   transport;

    HostSpec(const std::string &h, uint16_t p,
             Transport t = Transport::HTTP_POST_JSON)
        : host(h), port(p), transport(t) {}
};

/* Single-host search.  Blocks until the daemon replies or max_wait
 * elapses.  Returns a populated SearchResult.  Thread-safe. */
SearchResult search_one(const HostSpec &host,
                        const std::string &pubkey_hex,
                        const std::string &from_hex,
                        const std::string &to_hex,
                        double max_wait_seconds = 0.0 /* 0 = no timeout */);

/* Multi-host pool.  Holds a list of hosts and per-host health state.
 * Caller can drive policy (round-robin, fastest-first, etc.) by
 * choosing which dispatch entrypoint to invoke.
 *
 * NOTE: BSGSD is single-client-at-a-time per host; sending two
 * simultaneous searches to the same host will queue server-side via
 * the single_search_mutex added in the bug-fix commit.  The pool
 * still benefits from spreading work across distinct hosts. */
class Pool {
public:
    explicit Pool(std::vector<HostSpec> hosts);

    /* Round-robin dispatch.  Tries hosts in turn until one succeeds or
     * all fail.  On NETWORK_ERROR, marks the host unhealthy for
     * unhealthy_seconds and retries the next host. */
    SearchResult search_round_robin(const std::string &pubkey_hex,
                                    const std::string &from_hex,
                                    const std::string &to_hex,
                                    double max_wait_seconds = 0.0);

    /* Fan-out dispatch.  Splits [from,to] into N equal-size sub-ranges
     * (one per healthy host), launches them in parallel, returns the
     * first FOUND or NOT_FOUND-after-all-complete.  Useful when the
     * caller has a known [from,to] that fits the BSGS table size and
     * wants horizontal speedup.
     *
     * NOTE: each sub-range still goes against a separate BSGSD with its
     * own (identical) bloom files; coordination is purely client-side. */
    SearchResult search_fanout(const std::string &pubkey_hex,
                               const std::string &from_hex,
                               const std::string &to_hex,
                               double max_wait_seconds = 0.0);

    /* Diagnostic accessors. */
    size_t healthy_host_count() const;
    std::vector<bool> healthy_mask() const;

    /* Health policy (defaults: 30s unhealthy after a NETWORK_ERROR). */
    void set_unhealthy_window(double seconds) { unhealthy_window_ = seconds; }

private:
    struct HostState {
        HostSpec spec;
        double   unhealthy_until;  /* steady_clock seconds since epoch; 0=healthy */
    };
    std::vector<HostState> hosts_;
    size_t                 next_rr_;
    double                 unhealthy_window_;
    /* mutex omitted from header to avoid pulling pthread.h into headers;
     * the .cpp pulls in <mutex> and uses std::mutex internally. */
};

} /* namespace bsgsd_client */

#endif /* BSGSD_CLIENT_H */
