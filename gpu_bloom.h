// GPU bloom check stub / real impl depending on ENABLE_GPU_BLOOM define.
//
// API contract:
//   gpu_bloom_init(bloom_bP[], 256)       -- upload all 256 shards to VRAM
//   gpu_bloom_batch_check(xpoints, n,
//                         bucket_idx,     -- which of 256 shards per xpoint
//                         hits_out)       -- 0/1 output
//   gpu_bloom_shutdown()
//
// When ENABLE_GPU_BLOOM is NOT defined, all entry points return false/do
// nothing so keyhunt is buildable without CUDA.
//
// PERFORMANCE STATUS (2026-04-24):
// Prototype is byte-exact-correct vs CPU bloom_check (validated on 1M
// queries against a 10M-entry bloom: 0 mismatches). Per-thread persistent
// device buffers + per-thread CUDA streams added.
//
// HOWEVER, the per-CPU-thread synchronous-call design is bottlenecked by
// GPU launch latency: 32 CPU threads firing 1024-point batches each pays
// 2 ms round-trip and serializes on the device driver. Real-world rate
// observed: ~500 lookups/s vs ~10000 lookups/s on pure CPU.
//
// Production path requires a single GPU-coordinator thread that batches
// candidates across all 32 CPU producers via lock-free queue, fires fat
// 32K-point batches, and notifies producers via condvars. Implemented here:
// no. Sketched in TODO.md.
//
// Therefore --gpu-bloom is OFF by default and should NOT be turned on for
// production runs until the coordinator-thread design ships.

#ifndef KEYHUNT_GPU_BLOOM_H
#define KEYHUNT_GPU_BLOOM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct bloom;  /* forward */

/*
 * Upload the 256 bloom shards to the GPU. Returns 1 on success, 0 on failure
 * (CUDA error, out-of-memory, or not compiled in).
 */
int gpu_bloom_init(const struct bloom *blooms_256);

/*
 * Query `n` x-points against their respective bloom shards. Each xpoints[i]
 * is 32 bytes. The byte bucket is encoded as bucket_idx[i] (0..255).
 * hits_out[i] is set to 1 if all k hash bits are present, else 0.
 *
 * Returns 1 on success, 0 on failure (caller should fall back to CPU).
 */
int gpu_bloom_batch_check(const uint8_t *xpoints, const uint8_t *bucket_idx,
                          int n, int *hits_out);

/*
 * Release GPU resources.
 */
void gpu_bloom_shutdown(void);

/*
 * Query whether GPU bloom is available at runtime.
 */
int gpu_bloom_available(void);

#ifdef __cplusplus
}
#endif

#endif /* KEYHUNT_GPU_BLOOM_H */
