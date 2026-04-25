#include "oracle_schema.h"
#include <cstdio>
#include <cstring>

namespace magicwand {

std::string fp127_hex(const FP127 &fp) {
    char buf[33];
    snprintf(buf, sizeof(buf), "%016lx%016lx",
             (unsigned long)fp.hi, (unsigned long)fp.lo);
    return std::string(buf);
}

std::string fp_key(uint64_t fp64) {
    char buf[17];
    snprintf(buf, sizeof(buf), "%016lx", (unsigned long)fp64);
    return "fp:" + std::string(buf);
}

std::string fp127f_key(const FP127 &fp) { return "fp127f:" + fp127_hex(fp); }
std::string fp127b_key(const FP127 &fp) { return "fp127b:" + fp127_hex(fp); }
std::string fpcombo127_key(const FP127 &fp) { return "fpcombo127:" + fp127_hex(fp); }

FP127 pack_fpcombo127(uint64_t fp64_bwd, uint64_t fp64_fwd) {
    FP127 out;
    /* low 64 bits = full fp64_bwd */
    out.lo = fp64_bwd;
    /* high 63 bits = fp64_fwd shifted right by 1 (drops shared bit 0) */
    out.hi = (fp64_fwd >> 1) & ((1ULL << 63) - 1);
    return out;
}

std::string xset_key(XSet64 x) {
    char buf[17];
    snprintf(buf, sizeof(buf), "%016lx", (unsigned long)x);
    return "xset:" + std::string(buf);
}

std::string encode_k_le(uint64_t k) {
    std::string out(8, '\0');
    for (int i = 0; i < 8; i++) out[i] = (char)((k >> (i * 8)) & 0xff);
    return out;
}

bool decode_k_le(const std::string &v, uint64_t *k_out) {
    if (v.size() != 8 || !k_out) return false;
    uint64_t k = 0;
    for (int i = 0; i < 8; i++) k |= (uint64_t)(uint8_t)v[i] << (i * 8);
    *k_out = k;
    return true;
}

} /* namespace magicwand */
