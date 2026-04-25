#include "oracle_client.h"
#include <hiredis/hiredis.h>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <random>
#include <sstream>

namespace magicwand {

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

static ProbeResult make_error(const std::string &msg) {
    ProbeResult r;
    r.status = ProbeStatus::ERROR;
    r.k = 0;
    r.error_message = msg;
    return r;
}

static ProbeResult make_hit(uint64_t k) {
    ProbeResult r;
    r.status = ProbeStatus::HIT;
    r.k = k;
    return r;
}

static ProbeResult make_miss() {
    ProbeResult r;
    r.status = ProbeStatus::MISS;
    r.k = 0;
    return r;
}

static std::string random_id(size_t bytes = 16) {
    static thread_local std::random_device rd;
    static thread_local std::mt19937_64 rng(rd());
    char buf[64];
    char *p = buf;
    for (size_t i = 0; i < bytes; i += 8) {
        uint64_t v = rng();
        for (int j = 0; j < 8 && (i + j) < bytes; j++) {
            p += snprintf(p, 4, "%02x", (unsigned)((v >> (j * 8)) & 0xff));
        }
    }
    return std::string(buf);
}

/* ------------------------------------------------------------------ */
/* construction / connection                                           */
/* ------------------------------------------------------------------ */

OracleClient::OracleClient(const OracleConfig &cfg) : cfg_(cfg), ctx_(nullptr) {}

OracleClient::~OracleClient() {
    if (ctx_) {
        redisFree(ctx_);
        ctx_ = nullptr;
    }
}

bool OracleClient::connect() {
    if (ctx_) {
        redisFree(ctx_);
        ctx_ = nullptr;
    }
    struct timeval tv;
    tv.tv_sec  = cfg_.timeout_ms / 1000;
    tv.tv_usec = (cfg_.timeout_ms % 1000) * 1000;
    ctx_ = redisConnectWithTimeout(cfg_.host.c_str(), cfg_.port, tv);
    if (!ctx_ || ctx_->err) {
        if (ctx_) {
            fprintf(stderr, "[oracle] connect %s:%u failed: %s\n",
                    cfg_.host.c_str(), (unsigned)cfg_.port, ctx_->errstr);
            redisFree(ctx_);
            ctx_ = nullptr;
        }
        return false;
    }
    redisSetTimeout(ctx_, tv);

    if (!cfg_.password.empty()) {
        redisReply *r = (redisReply *)redisCommand(ctx_, "AUTH %s", cfg_.password.c_str());
        if (!r || r->type == REDIS_REPLY_ERROR) {
            fprintf(stderr, "[oracle] AUTH failed\n");
            if (r) freeReplyObject(r);
            redisFree(ctx_);
            ctx_ = nullptr;
            return false;
        }
        freeReplyObject(r);
    }

    if (cfg_.db_index != 0) {
        redisReply *r = (redisReply *)redisCommand(ctx_, "SELECT %d", cfg_.db_index);
        if (!r || r->type == REDIS_REPLY_ERROR) {
            fprintf(stderr, "[oracle] SELECT %d failed\n", cfg_.db_index);
            if (r) freeReplyObject(r);
            redisFree(ctx_);
            ctx_ = nullptr;
            return false;
        }
        freeReplyObject(r);
    }
    return true;
}

bool OracleClient::is_connected() const { return ctx_ != nullptr && !ctx_->err; }

bool OracleClient::ping() {
    if (!ctx_) return false;
    redisReply *r = (redisReply *)redisCommand(ctx_, "PING");
    if (!r) return false;
    bool ok = (r->type == REDIS_REPLY_STATUS && strcmp(r->str, "PONG") == 0);
    freeReplyObject(r);
    return ok;
}

uint64_t OracleClient::db_size() {
    if (!ctx_) return 0;
    redisReply *r = (redisReply *)redisCommand(ctx_, "DBSIZE");
    if (!r) return 0;
    uint64_t n = 0;
    if (r->type == REDIS_REPLY_INTEGER) n = (uint64_t)r->integer;
    freeReplyObject(r);
    return n;
}

/* ------------------------------------------------------------------ */
/* lookups                                                             */
/* ------------------------------------------------------------------ */

static ProbeResult get_one(redisContext *ctx, const std::string &key) {
    if (!ctx) return make_error("not connected");
    redisReply *r = (redisReply *)redisCommand(ctx, "GET %s", key.c_str());
    if (!r) return make_error("GET failed");
    ProbeResult result;
    if (r->type == REDIS_REPLY_NIL) {
        result = make_miss();
    } else if (r->type == REDIS_REPLY_STRING) {
        std::string v(r->str, r->len);
        uint64_t k;
        if (decode_k_le(v, &k)) {
            result = make_hit(k);
        } else {
            result = make_error("malformed value (size != 8)");
        }
    } else {
        result = make_error("unexpected reply type");
    }
    freeReplyObject(r);
    return result;
}

ProbeResult OracleClient::lookup_fp64(uint64_t fp) { return get_one(ctx_, fp_key(fp)); }
ProbeResult OracleClient::lookup_fp127f(const FP127 &fp) { return get_one(ctx_, fp127f_key(fp)); }
ProbeResult OracleClient::lookup_fp127b(const FP127 &fp) { return get_one(ctx_, fp127b_key(fp)); }
ProbeResult OracleClient::lookup_fpcombo127(const FP127 &fp) { return get_one(ctx_, fpcombo127_key(fp)); }
ProbeResult OracleClient::lookup_xset(XSet64 x) { return get_one(ctx_, xset_key(x)); }
ProbeResult OracleClient::lookup_raw(const std::string &key) { return get_one(ctx_, key); }

bool OracleClient::batch_insert_raw(
    const std::vector<std::pair<std::string, uint64_t>> &kv_to_value) {
    if (!ctx_) return false;
    if (kv_to_value.empty()) return true;

    const size_t CHUNK = 1024;
    for (size_t off = 0; off < kv_to_value.size(); off += CHUNK) {
        size_t n = std::min(CHUNK, kv_to_value.size() - off);
        std::vector<std::string> args;
        std::vector<const char *> argv;
        std::vector<size_t> argvlen;
        args.reserve(n * 2 + 1);
        argv.reserve(n * 2 + 1);
        argvlen.reserve(n * 2 + 1);

        args.emplace_back("MSET");
        argv.push_back(args.back().c_str());
        argvlen.push_back(args.back().size());

        for (size_t i = 0; i < n; i++) {
            const auto &p = kv_to_value[off + i];
            args.emplace_back(p.first);
            argv.push_back(args.back().c_str());
            argvlen.push_back(args.back().size());
            args.emplace_back(encode_k_le(p.second));
            argv.push_back(args.back().c_str());
            argvlen.push_back(args.back().size());
        }
        redisReply *r = (redisReply *)redisCommandArgv(
            ctx_, (int)argv.size(), argv.data(), argvlen.data());
        if (!r || r->type == REDIS_REPLY_ERROR) {
            if (r) freeReplyObject(r);
            return false;
        }
        freeReplyObject(r);
    }
    return true;
}

ProbeResult OracleClient::triple_lookup(const FP127 &fp_fwd, const FP127 &fp_bwd, XSet64 x) {
    /* Pipeline three GETs in one round trip. */
    if (!ctx_) return make_error("not connected");
    if (redisAppendCommand(ctx_, "GET %s", fp127f_key(fp_fwd).c_str()) != REDIS_OK ||
        redisAppendCommand(ctx_, "GET %s", fp127b_key(fp_bwd).c_str()) != REDIS_OK ||
        redisAppendCommand(ctx_, "GET %s", xset_key(x).c_str()) != REDIS_OK) {
        return make_error("pipeline append failed");
    }

    uint64_t hits[3] = {0, 0, 0};
    bool     have[3] = {false, false, false};
    for (int i = 0; i < 3; i++) {
        redisReply *r = nullptr;
        if (redisGetReply(ctx_, (void **)&r) != REDIS_OK || !r) {
            return make_error("pipeline reply failed");
        }
        if (r->type == REDIS_REPLY_STRING) {
            std::string v(r->str, r->len);
            uint64_t k;
            if (decode_k_le(v, &k)) {
                hits[i] = k;
                have[i] = true;
            }
        }
        freeReplyObject(r);
    }

    /* 2-of-3 voting: any two channels agreeing -> HIT. */
    int matches = 0;
    uint64_t consensus = 0;
    for (int i = 0; i < 3; i++) {
        if (!have[i]) continue;
        for (int j = i + 1; j < 3; j++) {
            if (!have[j]) continue;
            if (hits[i] == hits[j]) {
                matches++;
                consensus = hits[i];
            }
        }
    }
    if (matches >= 1) return make_hit(consensus);
    return make_miss();
}

/* ------------------------------------------------------------------ */
/* batch insert                                                        */
/* ------------------------------------------------------------------ */

template <typename Pair, typename KeyFn>
static bool batch_insert_impl(redisContext *ctx,
                              const std::vector<Pair> &items,
                              KeyFn key_fn) {
    if (!ctx) return false;
    if (items.empty()) return true;

    /* MSET key1 val1 key2 val2 ... in chunks of 1024 to bound memory. */
    const size_t CHUNK = 1024;
    for (size_t off = 0; off < items.size(); off += CHUNK) {
        size_t n = std::min(CHUNK, items.size() - off);
        std::vector<std::string> args;
        std::vector<const char *> argv;
        std::vector<size_t> argvlen;
        args.reserve(n * 2 + 1);
        argv.reserve(n * 2 + 1);
        argvlen.reserve(n * 2 + 1);

        args.emplace_back("MSET");
        argv.push_back(args.back().c_str());
        argvlen.push_back(args.back().size());

        for (size_t i = 0; i < n; i++) {
            const auto &p = items[off + i];
            args.emplace_back(key_fn(p.first));
            argv.push_back(args.back().c_str());
            argvlen.push_back(args.back().size());

            args.emplace_back(encode_k_le(p.second));
            argv.push_back(args.back().c_str());
            argvlen.push_back(args.back().size());
        }

        redisReply *r = (redisReply *)redisCommandArgv(
            ctx, (int)argv.size(), argv.data(), argvlen.data());
        if (!r || r->type == REDIS_REPLY_ERROR) {
            if (r) freeReplyObject(r);
            return false;
        }
        freeReplyObject(r);
    }
    return true;
}

bool OracleClient::batch_insert_fp64(const std::vector<std::pair<uint64_t, uint64_t>> &fp_to_k) {
    return batch_insert_impl(ctx_, fp_to_k, fp_key);
}
bool OracleClient::batch_insert_fp127f(const std::vector<std::pair<FP127, uint64_t>> &fp_to_k) {
    return batch_insert_impl(ctx_, fp_to_k, fp127f_key);
}
bool OracleClient::batch_insert_fp127b(const std::vector<std::pair<FP127, uint64_t>> &fp_to_k) {
    return batch_insert_impl(ctx_, fp_to_k, fp127b_key);
}
bool OracleClient::batch_insert_xset(const std::vector<std::pair<XSet64, uint64_t>> &x_to_k) {
    return batch_insert_impl(ctx_, x_to_k, xset_key);
}

/* ------------------------------------------------------------------ */
/* fill queue                                                          */
/* ------------------------------------------------------------------ */

bool OracleClient::enqueue_fill(const FillJob &job, std::string *fill_id_out) {
    if (!ctx_) return false;
    std::string fid = random_id(16);

    char body[1024];
    snprintf(body, sizeof(body),
             "{\"id\":\"%s\",\"k_lo\":\"%lx\",\"k_hi\":\"%lx\","
             "\"fields\":\"%s\",\"priority\":%d,\"requested_by\":\"%s\"}",
             fid.c_str(), (unsigned long)job.k_lo, (unsigned long)job.k_hi,
             job.fields.c_str(), job.priority, job.requested_by.c_str());

    redisReply *r = (redisReply *)redisCommand(ctx_, "RPUSH fill:queue %s", body);
    if (!r) return false;
    bool ok = (r->type == REDIS_REPLY_INTEGER);
    freeReplyObject(r);
    if (ok && fill_id_out) *fill_id_out = fid;
    return ok;
}

OracleClient::FillJob OracleClient::blpop_fill(double timeout_seconds,
                                               const std::string &worker_id) {
    FillJob empty{};
    if (!ctx_) return empty;

    int t = (int)timeout_seconds;
    if (t < 0) t = 0;
    redisReply *r = (redisReply *)redisCommand(ctx_, "BLPOP fill:queue %d", t);
    if (!r) return empty;

    FillJob job{};
    if (r->type == REDIS_REPLY_ARRAY && r->elements == 2 &&
        r->element[1]->type == REDIS_REPLY_STRING) {
        std::string body(r->element[1]->str, r->element[1]->len);
        /* Extremely thin JSON parser -- enough for our schema. */
        auto extract = [&](const std::string &k) -> std::string {
            std::string needle = "\"" + k + "\":";
            size_t p = body.find(needle);
            if (p == std::string::npos) return "";
            p += needle.size();
            while (p < body.size() && body[p] == ' ') p++;
            if (p < body.size() && body[p] == '"') {
                size_t end = body.find('"', p + 1);
                if (end == std::string::npos) return "";
                return body.substr(p + 1, end - p - 1);
            } else {
                size_t end = body.find_first_of(",}", p);
                if (end == std::string::npos) return "";
                return body.substr(p, end - p);
            }
        };
        job.k_lo = strtoull(extract("k_lo").c_str(), nullptr, 16);
        job.k_hi = strtoull(extract("k_hi").c_str(), nullptr, 16);
        job.fields = extract("fields");
        job.priority = atoi(extract("priority").c_str());
        job.requested_by = extract("requested_by");

        std::string fid = extract("id");
        /* Track inflight for crash recovery. */
        if (!worker_id.empty() && !fid.empty()) {
            redisReply *r2 = (redisReply *)redisCommand(
                ctx_, "SADD fill:inflight:%s %s", worker_id.c_str(), fid.c_str());
            if (r2) freeReplyObject(r2);
        }
    }
    freeReplyObject(r);
    return job;
}

bool OracleClient::ack_fill(const std::string &worker_id, const std::string &fill_id) {
    if (!ctx_) return false;
    redisReply *r = (redisReply *)redisCommand(
        ctx_, "SREM fill:inflight:%s %s", worker_id.c_str(), fill_id.c_str());
    if (!r) return false;
    bool ok = (r->type == REDIS_REPLY_INTEGER);
    freeReplyObject(r);
    return ok;
}

bool OracleClient::publish_fill_done(uint64_t k_lo, uint64_t k_hi) {
    if (!ctx_) return false;
    redisReply *r = (redisReply *)redisCommand(
        ctx_, "PUBLISH fill:done %lx-%lx", (unsigned long)k_lo, (unsigned long)k_hi);
    if (!r) return false;
    bool ok = (r->type == REDIS_REPLY_INTEGER);
    freeReplyObject(r);
    return ok;
}

} /* namespace magicwand */
