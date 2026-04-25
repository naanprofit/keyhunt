#pragma once
/*
 * Magic Wand oracle schema.
 *
 * Three independent lookups per scalar k, all in the same Redis instance
 * (primary on fozzie; optionally replicated to deck). All keys are bytestrings,
 * values are the 8-byte little-endian scalar k.
 *
 * Schema choice rationale: see research/MAGIC_WAND_FP127_WIRING.md
 *   - FP127f and FP127b both use y-parity bits only because Hamming distance
 *     must be meaningful for flood-fill elimination to work. Mixing in
 *     X-coord bits destroys that locality property.
 *   - X-set is a separate index (exact lookup, no flood-fill) used purely
 *     as a third independent signal to confirm oracle hits and reject
 *     false positives in the FP indexes.
 *
 * FIELD LAYOUT
 * ============
 *   fp:<16-hex>       -> 8-byte LE scalar k
 *       Legacy 64-bit y-parity FP from magic_wand_sieve.py compute_fp64.
 *       64 forward y-parity bits starting at k*G. The deck Redis instance
 *       has ~1.96 B entries in this format; we preserve it for back-compat
 *       and use it as an L0 prior cache.
 *
 *   fp127f:<32-hex>   -> 8-byte LE scalar k
 *       127 forward y-parity bits of the walk k*G, (k+1)*G, ..., (k+126)*G.
 *       Stored as two uint64: hi = bits 126..64, lo = bits 63..0.
 *       Hex encoding: 16 hex chars for hi, 16 for lo (total 32 hex chars).
 *       MSB of hi is always 0 (127 bits into 128-bit field).
 *
 *   fp127b:<32-hex>   -> 8-byte LE scalar k
 *       127 backward y-parity bits of the walk (k-1)*G, (k-2)*G, ..., (k-127)*G.
 *       Same encoding as fp127f.
 *
 *   fpcombo127:<32-hex> -> 8-byte LE scalar k
 *       Layout matching fp127_solver_fast.py compute_fp127_batch:
 *           bits 0..63   = fp64_bwd(k) = parity(T[k-63..k])  (64 bits)
 *           bits 64..126 = fp64_fwd(k) >> 1 = parity(T[k+1..k+63])  (63 bits)
 *       Encoded as two uint64: hi = bits 126..64, lo = bits 63..0.
 *       Provided for direct interop with the existing Python solver
 *       toolchain on deck. New tooling should prefer the separate
 *       fp127f / fp127b indexes which give richer 2D Hamming locality.
 *
 *   xset:<16-hex>     -> 8-byte LE scalar k
 *       First 64 bits of X(k*G) (big-endian low 8 bytes of X as a Bitcoin
 *       scalar serialization). Exact lookup, no flood-fill.
 *
 * FILL QUEUE
 * ==========
 *   fill:queue        -> Redis LIST of JSON job descriptors:
 *                        {"k_lo": <LE-hex>, "k_hi": <LE-hex>,
 *                         "fields": ["fp127f","fp127b","xset"],
 *                         "priority": <int>, "requested_by": "<host>"}
 *                        Workers BLPOP from this list.
 *
 *   fill:inflight:<worker_id> -> Redis SET of jobs claimed but not yet completed.
 *                                Used for worker-crash recovery (orphan jobs
 *                                return to queue after TTL expires).
 *
 *   fill:done         -> Redis PUB/SUB channel; workers PUBLISH the k_lo..k_hi
 *                        range on completion so any waiting queries can
 *                        re-probe.
 *
 * MISS-HANDLING
 * =============
 *   On oracle miss for scalar k:
 *     1. Check L2 disk store (LMDB). If hit, promote to Redis, return hit.
 *     2. If double-miss, compute a small "fill cell" covering k and enqueue
 *        a fill job. Respond to caller with STATUS=PENDING and a unique
 *        fill_id. Caller chooses to wait (blocking) or mark probe as
 *        inconclusive (advisory).
 */

#include <cstdint>
#include <string>

namespace magicwand {

/* 127-bit fingerprint, packed into two 64-bit words.
 * hi occupies bit positions 126..64, lo occupies 63..0. Bit 127 is always 0.
 */
struct FP127 {
    uint64_t hi;
    uint64_t lo;

    bool operator==(const FP127 &o) const { return hi == o.hi && lo == o.lo; }
    bool operator!=(const FP127 &o) const { return !(*this == o); }

    /* Hamming distance between two 127-bit FPs. */
    int hamming(const FP127 &o) const {
        return __builtin_popcountll(hi ^ o.hi) + __builtin_popcountll(lo ^ o.lo);
    }
};

/* X-set index value: first 64 bits of the X coord. */
using XSet64 = uint64_t;

/* Key format helpers (hex-encoded Redis keys). */
std::string fp127_hex(const FP127 &fp);             /* 32 hex chars */
std::string fp_key(uint64_t fp64);                  /* "fp:<16hex>" -- legacy 64-bit */
std::string fp127f_key(const FP127 &fp);            /* "fp127f:<hex>" */
std::string fp127b_key(const FP127 &fp);            /* "fp127b:<hex>" */
std::string fpcombo127_key(const FP127 &fp);        /* "fpcombo127:<hex>" -- Python interop */
std::string xset_key(XSet64 x);                     /* "xset:<16hex>" */

/* Value encoding: 8-byte LE scalar k. */
std::string encode_k_le(uint64_t k);                /* 8 raw bytes */
bool        decode_k_le(const std::string &v, uint64_t *k_out);

/* Pack 64 fwd + 63 fwd-shifted-right bits into FP127 in the layout used by
 * fp127_solver_fast.py compute_fp127_batch. fp64_bwd is parities of
 * T[k-63..k] (64 bits, bit 0 = T[k-63]). fp64_fwd is parities of T[k..k+63]
 * (64 bits, bit 0 = T[k]). The Python combo drops fp64_fwd's bit 0 (which
 * equals fp64_bwd's bit 63, since both name T[k]). */
FP127 pack_fpcombo127(uint64_t fp64_bwd, uint64_t fp64_fwd);

} /* namespace magicwand */
