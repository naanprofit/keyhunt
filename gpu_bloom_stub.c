/* Stub for non-CUDA builds. All entry points are no-ops so keyhunt links
 * cleanly. Users on this build path cannot enable --gpu-bloom. */
#include "gpu_bloom.h"
#include <stdio.h>

int  gpu_bloom_init(const struct bloom *b) { (void)b; return 0; }
int  gpu_bloom_batch_check(const unsigned char *xp, const unsigned char *bk,
                           int n, int *h) {
    (void)xp; (void)bk; (void)n; (void)h;
    return 0;
}
void gpu_bloom_shutdown(void) {}
int  gpu_bloom_available(void) { return 0; }
