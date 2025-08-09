#include "xxhash/xxhash.h"
#ifdef __SSE2__
#error "__SSE2__ defined for ARM build"
#endif
int main(void) { return 0; }
