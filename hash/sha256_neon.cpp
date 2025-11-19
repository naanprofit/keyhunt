#include "sha256.h"

// Sequential fallback/NEON-friendly implementation processing
// four independent messages using the generic SHA-256 routine.
// Each input block is expected to be already padded.
void sha256neon_1B(
  uint32_t *i0,
  uint32_t *i1,
  uint32_t *i2,
  uint32_t *i3,
  unsigned char *d0,
  unsigned char *d1,
  unsigned char *d2,
  unsigned char *d3)
{
  sha256((unsigned char*)i0, 64, d0);
  sha256((unsigned char*)i1, 64, d1);
  sha256((unsigned char*)i2, 64, d2);
  sha256((unsigned char*)i3, 64, d3);
}

void sha256neon_2B(
  uint32_t *i0,
  uint32_t *i1,
  uint32_t *i2,
  uint32_t *i3,
  unsigned char *d0,
  unsigned char *d1,
  unsigned char *d2,
  unsigned char *d3)
{
  sha256((unsigned char*)i0, 128, d0);
  sha256((unsigned char*)i1, 128, d1);
  sha256((unsigned char*)i2, 128, d2);
  sha256((unsigned char*)i3, 128, d3);
}

void sha256neon_checksum(
  uint32_t *i0,
  uint32_t *i1,
  uint32_t *i2,
  uint32_t *i3,
  uint8_t *d0,
  uint8_t *d1,
  uint8_t *d2,
  uint8_t *d3)
{
  sha256_checksum((uint8_t*)i0, 32, d0);
  sha256_checksum((uint8_t*)i1, 32, d1);
  sha256_checksum((uint8_t*)i2, 32, d2);
  sha256_checksum((uint8_t*)i3, 32, d3);
}

