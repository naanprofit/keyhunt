#include "ripemd160.h"

// Sequential fallback/NEON-friendly implementation processing
// four independent 32-byte messages using the generic RIPEMD160
// routine. This file is used on ARM/NEON or other targets where
// SSE is unavailable.
void ripemd160neon_32(
  unsigned char *i0,
  unsigned char *i1,
  unsigned char *i2,
  unsigned char *i3,
  unsigned char *d0,
  unsigned char *d1,
  unsigned char *d2,
  unsigned char *d3)
{
  ripemd160_32(i0, d0);
  ripemd160_32(i1, d1);
  ripemd160_32(i2, d2);
  ripemd160_32(i3, d3);
}

