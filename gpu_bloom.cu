/*
 * GPU bloom check, multi-GPU coordinator-thread design.
 *
 * Architecture:
 *   - One worker thread per CUDA device. Each worker owns a stream + buffers
 *     and a full replica of all 256 bloom shards on its device.
 *   - Each producer (CPU thread doing thread_process_bsgs) submits a 1024-
 *     point batch to a global lock-free MPSC queue with seqnum.
 *   - Workers pop from the queue, fire 32K-point batched kernels (combining
 *     up to 32 producer submissions), and signal completion via per-submit
 *     futures.
 *
 * Producers BLOCK on their submission's future. This is identical wire
 * semantics to the previous synchronous version, but the GPU sees fat
 * batches instead of 32 thin ones, amortising launch latency.
 *
 * Hash recipe matches keyhunt CPU bloom_check byte-for-byte:
 *   a = XXH64(buf, 32, 0x59f2815b16f81798)
 *   b = XXH64(buf, 32, a)
 *   for i in 0..k:  bit = (a + b*i) % bloom->bits
 */
#include "gpu_bloom.h"
#include "bloom/bloom.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>
#include <cuda_runtime.h>

#define NBUCKETS    256
#define MAX_BATCH   1024            /* CPU_GRP_SIZE in keyhunt = 1024 */
#define COALESCE_MAX 32             /* up to 32 producer batches per kernel */
#define QUEUE_CAP   4096            /* pending submission ring */

/* ---- Compact XXH64 for device, 32-byte specialized ---- */
#define PRIME64_1 0x9E3779B185EBCA87ULL
#define PRIME64_2 0xC2B2AE3D27D4EB4FULL
#define PRIME64_3 0x165667B19E3779F9ULL
#define PRIME64_4 0x85EBCA77C2B2AE63ULL

__device__ __forceinline__ uint64_t rotl64(uint64_t x, int r) {
    return (x << r) | (x >> (64 - r));
}
__device__ __forceinline__ uint64_t xxh64_round(uint64_t acc, uint64_t input) {
    acc += input * PRIME64_2; acc = rotl64(acc, 31); acc *= PRIME64_1; return acc;
}
__device__ __forceinline__ uint64_t xxh64_merge_round(uint64_t acc, uint64_t val) {
    val = xxh64_round(0, val); acc ^= val; return acc * PRIME64_1 + PRIME64_4;
}
__device__ __forceinline__ uint64_t load64_le(const uint8_t *p) {
    uint64_t v = 0;
    v |= (uint64_t)p[0]; v |= (uint64_t)p[1] << 8;
    v |= (uint64_t)p[2] << 16; v |= (uint64_t)p[3] << 24;
    v |= (uint64_t)p[4] << 32; v |= (uint64_t)p[5] << 40;
    v |= (uint64_t)p[6] << 48; v |= (uint64_t)p[7] << 56;
    return v;
}
__device__ uint64_t xxh64_32bytes(const uint8_t *input, uint64_t seed) {
    uint64_t v1 = seed + PRIME64_1 + PRIME64_2;
    uint64_t v2 = seed + PRIME64_2;
    uint64_t v3 = seed + 0;
    uint64_t v4 = seed - PRIME64_1;
    v1 = xxh64_round(v1, load64_le(input + 0));
    v2 = xxh64_round(v2, load64_le(input + 8));
    v3 = xxh64_round(v3, load64_le(input + 16));
    v4 = xxh64_round(v4, load64_le(input + 24));
    uint64_t h64 = rotl64(v1, 1) + rotl64(v2, 7) + rotl64(v3, 12) + rotl64(v4, 18);
    h64 = xxh64_merge_round(h64, v1);
    h64 = xxh64_merge_round(h64, v2);
    h64 = xxh64_merge_round(h64, v3);
    h64 = xxh64_merge_round(h64, v4);
    h64 += 32;
    h64 ^= h64 >> 33; h64 *= PRIME64_2;
    h64 ^= h64 >> 29; h64 *= PRIME64_3;
    h64 ^= h64 >> 32;
    return h64;
}

struct DeviceShard {
    uint8_t *bf;
    uint64_t bits;
    uint32_t hashes;
};

/* Per-device bloom shard table. Lives in __constant__ memory. */
__constant__ DeviceShard d_shards[NBUCKETS];

__global__ void bloom_check_256shard_kernel(
    const uint8_t *__restrict__ queries,
    const uint8_t *__restrict__ buckets,
    int n, int *__restrict__ hits)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n) return;
    const uint8_t *q = queries + (size_t)idx * 32;
    uint8_t bkt = buckets[idx];
    DeviceShard s = d_shards[bkt];
    if (s.bits == 0) { hits[idx] = 0; return; }
    uint64_t a = xxh64_32bytes(q, 0x59f2815b16f81798ULL);
    uint64_t b = xxh64_32bytes(q, a);
    for (uint32_t i = 0; i < s.hashes; i++) {
        uint64_t pos = (a + b * i) % s.bits;
        if (((s.bf[pos >> 3] >> (pos & 7)) & 1) == 0) {
            hits[idx] = 0;
            return;
        }
    }
    hits[idx] = 1;
}

namespace {

struct Submission {
    const uint8_t *xpoints;     /* host pinned-or-paged 32*n bytes */
    const uint8_t *buckets;     /* host n bytes */
    int            n;
    int           *hits_out;    /* host n ints */
    std::atomic<int> done;      /* 0 = pending, 1 = done OK, 2 = done FAIL */
    Submission() : xpoints(nullptr), buckets(nullptr), n(0), hits_out(nullptr), done(0) {}
};

struct GpuWorker {
    int           device_id;
    cudaStream_t  stream;
    uint8_t      *d_q;          /* COALESCE_MAX*MAX_BATCH*32 */
    uint8_t      *d_bkt;        /* COALESCE_MAX*MAX_BATCH    */
    int          *d_hits;       /* COALESCE_MAX*MAX_BATCH*4  */
    std::vector<uint8_t *> d_shard_bf;  /* keep for cleanup */
    std::thread   thr;
};

std::vector<GpuWorker> g_workers;
int                    g_ready = 0;

/* MPSC queue: producers push tail, single consumer (round-robined) pops head.
 * For simplicity we use a mutex-guarded ring of submission pointers. The hot
 * path is producer condvar-wait; the GPU worker is the only consumer per
 * device, but multiple device workers can pop, so we serialize pops with
 * the same mutex (cheap because pop-rate is low: each pop drains up to 32
 * submissions). */
struct Queue {
    Submission *ring[QUEUE_CAP];
    int         head = 0;
    int         tail = 0;
    int         size = 0;
    std::mutex  m;
    std::condition_variable cv_nonempty;
    std::condition_variable cv_nonfull;
    std::atomic<int> shutdown{0};
};
Queue g_q;

#define CK(expr) do {                                                            \
    cudaError_t _e = (expr);                                                     \
    if (_e != cudaSuccess) {                                                     \
        fprintf(stderr, "[gpu_bloom] CUDA %s @ %s:%d: %s\n",                     \
                #expr, __FILE__, __LINE__, cudaGetErrorString(_e));              \
        return false;                                                            \
    }                                                                            \
} while (0)

bool worker_init(GpuWorker &w, const struct bloom *blooms_256) {
    if (cudaSetDevice(w.device_id) != cudaSuccess) return false;
    cudaDeviceProp prop;
    cudaGetDeviceProperties(&prop, w.device_id);
    fprintf(stderr, "[gpu_bloom] dev %d: %s, CC %d.%d, %.2f GB\n",
            w.device_id, prop.name, prop.major, prop.minor,
            (double)prop.totalGlobalMem / (1<<30));

    CK(cudaStreamCreate(&w.stream));
    CK(cudaMalloc(&w.d_q,    (size_t)COALESCE_MAX * MAX_BATCH * 32));
    CK(cudaMalloc(&w.d_bkt,  (size_t)COALESCE_MAX * MAX_BATCH));
    CK(cudaMalloc(&w.d_hits, (size_t)COALESCE_MAX * MAX_BATCH * sizeof(int)));

    DeviceShard host_shards[NBUCKETS];
    size_t total_bytes = 0;
    for (int i = 0; i < NBUCKETS; i++) {
        const struct bloom *b = &blooms_256[i];
        if (!b->ready || b->bf == nullptr || b->bytes == 0) {
            fprintf(stderr, "[gpu_bloom] dev %d shard %d not ready\n",
                    w.device_id, i);
            return false;
        }
        uint8_t *d_bf = nullptr;
        CK(cudaMalloc(&d_bf, b->bytes));
        CK(cudaMemcpy(d_bf, b->bf, b->bytes, cudaMemcpyHostToDevice));
        w.d_shard_bf.push_back(d_bf);
        host_shards[i].bf = d_bf;
        host_shards[i].bits = b->bits;
        host_shards[i].hashes = b->hashes;
        total_bytes += b->bytes;
    }
    CK(cudaMemcpyToSymbol(d_shards, host_shards, sizeof(host_shards)));
    fprintf(stderr, "[gpu_bloom] dev %d uploaded 256 shards (%.2f MB)\n",
            w.device_id, (double)total_bytes / 1048576.0);
    return true;
}

void worker_loop(GpuWorker *self) {
    cudaSetDevice(self->device_id);
    Submission *batch[COALESCE_MAX];
    /* host staging in pinned memory for fast DMA */
    uint8_t *h_q   = nullptr;
    uint8_t *h_bkt = nullptr;
    int     *h_hits = nullptr;
    cudaMallocHost(&h_q,    (size_t)COALESCE_MAX * MAX_BATCH * 32);
    cudaMallocHost(&h_bkt,  (size_t)COALESCE_MAX * MAX_BATCH);
    cudaMallocHost(&h_hits, (size_t)COALESCE_MAX * MAX_BATCH * sizeof(int));

    while (!g_q.shutdown.load(std::memory_order_relaxed)) {
        int got = 0;
        {
            std::unique_lock<std::mutex> lk(g_q.m);
            g_q.cv_nonempty.wait_for(lk, std::chrono::microseconds(200), []{
                return g_q.size > 0 || g_q.shutdown.load();
            });
            while (got < COALESCE_MAX && g_q.size > 0) {
                batch[got++] = g_q.ring[g_q.head];
                g_q.head = (g_q.head + 1) % QUEUE_CAP;
                g_q.size--;
            }
            if (got > 0) g_q.cv_nonfull.notify_all();
        }
        if (got == 0) continue;

        /* Pack into staging */
        int total = 0;
        for (int i = 0; i < got; i++) {
            Submission *s = batch[i];
            memcpy(h_q   + (size_t)total * 32, s->xpoints, (size_t)s->n * 32);
            memcpy(h_bkt + (size_t)total,      s->buckets, (size_t)s->n);
            total += s->n;
        }

        /* Fire one fat kernel */
        cudaMemcpyAsync(self->d_q,   h_q,   (size_t)total * 32,
                        cudaMemcpyHostToDevice, self->stream);
        cudaMemcpyAsync(self->d_bkt, h_bkt, (size_t)total,
                        cudaMemcpyHostToDevice, self->stream);
        int block = 256;
        int grid  = (total + block - 1) / block;
        bloom_check_256shard_kernel<<<grid, block, 0, self->stream>>>(
            self->d_q, self->d_bkt, total, self->d_hits);
        cudaMemcpyAsync(h_hits, self->d_hits, (size_t)total * sizeof(int),
                        cudaMemcpyDeviceToHost, self->stream);
        cudaError_t err = cudaStreamSynchronize(self->stream);

        /* Scatter results back to each submission */
        int off = 0;
        for (int i = 0; i < got; i++) {
            Submission *s = batch[i];
            if (err == cudaSuccess) {
                memcpy(s->hits_out, h_hits + off, (size_t)s->n * sizeof(int));
                s->done.store(1, std::memory_order_release);
            } else {
                s->done.store(2, std::memory_order_release);
            }
            off += s->n;
        }
    }
    cudaFreeHost(h_q); cudaFreeHost(h_bkt); cudaFreeHost(h_hits);
}

} /* namespace */

extern "C" int gpu_bloom_init(const struct bloom *blooms_256) {
    if (g_ready) return 1;
    int dev_count = 0;
    if (cudaGetDeviceCount(&dev_count) != cudaSuccess || dev_count == 0) {
        fprintf(stderr, "[gpu_bloom] no CUDA device available\n");
        return 0;
    }
    /* Allow override: KEYHUNT_GPU_DEVICES="0,2" picks specific ones */
    std::vector<int> use_devs;
    const char *envd = getenv("KEYHUNT_GPU_DEVICES");
    if (envd && *envd) {
        const char *p = envd;
        while (*p) {
            char *end = nullptr;
            long v = strtol(p, &end, 10);
            if (end != p && v >= 0 && v < dev_count) use_devs.push_back((int)v);
            p = (*end == ',') ? end + 1 : end;
            while (*p == ' ' || *p == ',') p++;
        }
    }
    if (use_devs.empty()) {
        for (int i = 0; i < dev_count; i++) use_devs.push_back(i);
    }
    fprintf(stderr, "[gpu_bloom] enabling %zu device(s):", use_devs.size());
    for (int d : use_devs) fprintf(stderr, " %d", d);
    fprintf(stderr, "\n");

    g_workers.resize(use_devs.size());
    for (size_t i = 0; i < use_devs.size(); i++) {
        g_workers[i].device_id = use_devs[i];
        if (!worker_init(g_workers[i], blooms_256)) {
            fprintf(stderr, "[gpu_bloom] dev %d init failed\n", use_devs[i]);
            return 0;
        }
    }
    g_ready = 1;
    /* Start worker threads */
    for (auto &w : g_workers) {
        w.thr = std::thread(worker_loop, &w);
    }
    return 1;
}

extern "C" int gpu_bloom_available(void) { return g_ready; }

extern "C" void gpu_bloom_shutdown(void) {
    if (!g_ready) return;
    g_q.shutdown.store(1, std::memory_order_release);
    g_q.cv_nonempty.notify_all();
    for (auto &w : g_workers) {
        if (w.thr.joinable()) w.thr.join();
    }
    for (auto &w : g_workers) {
        cudaSetDevice(w.device_id);
        for (auto p : w.d_shard_bf) cudaFree(p);
        if (w.d_q)    cudaFree(w.d_q);
        if (w.d_bkt)  cudaFree(w.d_bkt);
        if (w.d_hits) cudaFree(w.d_hits);
        cudaStreamDestroy(w.stream);
    }
    g_workers.clear();
    g_ready = 0;
}

extern "C" int gpu_bloom_batch_check(const uint8_t *xpoints,
                                     const uint8_t *bucket_idx,
                                     int n, int *hits_out)
{
    if (!g_ready || n <= 0 || n > MAX_BATCH) return 0;
    Submission s;
    s.xpoints  = xpoints;
    s.buckets  = bucket_idx;
    s.n        = n;
    s.hits_out = hits_out;
    s.done.store(0, std::memory_order_release);

    {
        std::unique_lock<std::mutex> lk(g_q.m);
        g_q.cv_nonfull.wait(lk, []{ return g_q.size < QUEUE_CAP; });
        g_q.ring[g_q.tail] = &s;
        g_q.tail = (g_q.tail + 1) % QUEUE_CAP;
        g_q.size++;
    }
    g_q.cv_nonempty.notify_one();

    /* Wait for completion. Use a short-spin then yield to avoid futex
     * thrash. */
    for (int spin = 0; spin < 1000; spin++) {
        int d = s.done.load(std::memory_order_acquire);
        if (d != 0) return d == 1 ? 1 : 0;
    }
    while (true) {
        int d = s.done.load(std::memory_order_acquire);
        if (d != 0) return d == 1 ? 1 : 0;
        std::this_thread::yield();
    }
}
