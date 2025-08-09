#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include "../base58/libbase58.h"

static void roundtrip(const unsigned char *data, size_t len) {
    char b58[128];
    size_t b58sz = sizeof(b58);
    assert(b58enc(b58, &b58sz, data, len));

    unsigned char out[128];
    size_t outsz = len;
    assert(b58tobin(out, &outsz, b58, b58sz - 1));
    assert(outsz == len);
    assert(memcmp(out, data, len) == 0);
}

int main(void) {
    const unsigned char d1[] = {0x01};
    const unsigned char d2[] = {0x01, 0x02};
    const unsigned char d3[] = {0x01, 0x02, 0x03};
    const unsigned char d5[] = {0x00, 0x01, 0x02, 0x03, 0x04};

    roundtrip(d1, sizeof(d1));
    roundtrip(d2, sizeof(d2));
    roundtrip(d3, sizeof(d3));
    roundtrip(d5, sizeof(d5));
    return 0;
}
