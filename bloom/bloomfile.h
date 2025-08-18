#pragma once
#include <stdint.h>
#include <sys/stat.h>
#include <string.h>
#include <cmath>
#include <algorithm>

#ifndef BLOOM_VERSION_MAJOR
#define BLOOM_VERSION_MAJOR 2
#define BLOOM_VERSION_MINOR 201
#endif

inline static bool file_exists(const char* path) {
    struct stat st{};
    return ::stat(path, &st) == 0;
}

struct BloomHeader {
    uint32_t magic;     // 'KHBL' = 0x4B48424C
    uint16_t version;   // 1
    uint16_t tier;      // 1..3
    uint16_t shard;     // 0..255
    uint16_t k;         // hash functions
    uint64_t items;     // expected items
    uint64_t bytes;     // file size (payload only)
};

inline static void write_header(uint8_t* base, const BloomHeader& h) {
    memcpy(base, &h, sizeof(BloomHeader));
}

inline static bool read_header(const uint8_t* base, BloomHeader& h) {
    memcpy(&h, base, sizeof(BloomHeader));
    if (h.magic != 0x4B48424C) return false;
    if (h.version != 1) return false;
    if (h.shard > 255 || h.tier < 1 || h.tier > 3) return false;
    return true;
}

inline static void bloom_size_params(uint64_t n, double p, uint64_t &m_bits, uint32_t &k) {
    if (n == 0) { m_bits = 0; k = 1; return; }
    const double ln2 = 0.6931471805599453;
    double m = - (double)n * std::log(p) / (ln2*ln2);
    m_bits = (uint64_t) std::max(64.0, std::ceil(m));
    k = (uint32_t) std::max(1.0, std::round((m_bits / (double)n) * ln2));
}
