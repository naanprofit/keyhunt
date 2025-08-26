/*
 *  Copyright (c) 2012-2019, Jyri J. Virkki
 *  All rights reserved.
 *
 *  This file is under BSD license. See LICENSE file.
 */

/*
 * Refer to bloom.h for documentation on the public interfaces.
 */

#include <assert.h>
#include <fcntl.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#ifndef _WIN64
#include <sys/mman.h>
#endif

#include "bloom.h"
#include "../xxhash/xxhash.h"

#define MAKESTRING(n) STRING(n)
#define STRING(n) #n
#define BLOOM_MAGIC "libbloom2"
#define BLOOM_VERSION_MAJOR 2
#define BLOOM_VERSION_MINOR 201

inline static int test_bit_set_bit(struct bloom *bloom, uint64_t bit, int set_bit)
{
  uint64_t byte = bit >> 3;
  if (bloom->mapped_chunks > 1 && bloom->bf_chunks) {
    uint64_t chunk = byte / bloom->chunk_bytes;
    uint64_t offset = byte % bloom->chunk_bytes;
    uint8_t *bf = bloom->bf_chunks[chunk];
#if defined(__GNUC__) || defined(__clang__)
    __builtin_prefetch(&bf[offset], 0, 1);
#endif
    uint8_t c = bf[offset];
    uint8_t mask = 1 << (bit % 8);
    if (c & mask) {
      return 1;
    } else {
      if (set_bit) {
        bf[offset] = c | mask;
      }
      return 0;
    }
  } else {
    uint8_t *bf = bloom->bf;
#if defined(__GNUC__) || defined(__clang__)
    __builtin_prefetch(&bf[byte], 0, 1);
#endif
    uint8_t c = bf[byte];
    uint8_t mask = 1 << (bit % 8);
    if (c & mask) {
      return 1;
    } else {
      if (set_bit) {
        bf[byte] = c | mask;
      }
      return 0;
    }
  }
}

inline static int test_bit(struct bloom *bloom, uint64_t bit)
{
  uint64_t byte = bit >> 3;
  if (bloom->mapped_chunks > 1 && bloom->bf_chunks) {
    uint64_t chunk = byte / bloom->chunk_bytes;
    uint64_t offset = byte % bloom->chunk_bytes;
    uint8_t *bf = bloom->bf_chunks[chunk];
#if defined(__GNUC__) || defined(__clang__)
    __builtin_prefetch(&bf[offset], 0, 1);
#endif
    uint8_t c = bf[offset];
    uint8_t mask = 1 << (bit % 8);
    if (c & mask) {
      return 1;
    } else {
      return 0;
    }
  } else {
    uint8_t *bf = bloom->bf;
#if defined(__GNUC__) || defined(__clang__)
    __builtin_prefetch(&bf[byte], 0, 1);
#endif
    uint8_t c = bf[byte];
    uint8_t mask = 1 << (bit % 8);
    if (c & mask) {
      return 1;
    } else {
      return 0;
    }
  }
}

static int bloom_check_add(struct bloom * bloom, const void * buffer, int len, int add)
{
  if (bloom->ready == 0) {
    printf("bloom at %p not initialized!\n", (void *)bloom);
    return -1;
  }
  uint8_t hits = 0;
  XXH128_hash_t __h = XXH3_128bits(buffer, len);
  uint64_t a = __h.low64;
  uint64_t b = (__h.high64 << 1) | 1; // ensure odd step
  uint64_t mask = 0;
  if ((bloom->bits & (bloom->bits - 1)) == 0) { mask = bloom->bits - 1; }
  uint64_t x;
  uint8_t i;
  for (i = 0; i < bloom->hashes; i++) {
    x = mask ? ((a + b*i) & mask) : ((a + b*i) % bloom->bits);
    if (test_bit_set_bit(bloom, x, add)) {
      hits++;
    } else if (!add) {
      // Don't care about the presence of all the bits. Just our own.
      return 0;
    }
  }
  if (hits == bloom->hashes) {
    return 1;                // 1 == element already in (or collision)
  }
  return 0;
}

// DEPRECATED - Please migrate to bloom_init2.
int bloom_init(struct bloom * bloom, uint64_t entries, long double error)
{
  return bloom_init2(bloom, entries, error);
}

int bloom_init2(struct bloom * bloom, uint64_t entries, long double error)
{
  memset(bloom, 0, sizeof(struct bloom));
  if (entries < 1000 || error <= 0 || error >= 1) {
    return 1;
  }
  bloom->entries = entries;
  bloom->error = error;

  long double num = -log(bloom->error);
  long double denom = 0.480453013918201; // ln(2)^2
  bloom->bpe = (num / denom);

  long double dentries = (long double)entries;
  long double allbits = dentries * bloom->bpe;
  bloom->bits = (uint64_t)allbits;

  bloom->bytes = (uint64_t) bloom->bits / 8;
  if (bloom->bits % 8) {
    bloom->bytes +=1;
  }

  /* Align bits to next power-of-two to enable fast masking instead of modulo */
  if ((bloom->bits & (bloom->bits - 1)) != 0) {
    uint64_t v = bloom->bits;
    v--;
    v |= v >> 1; v |= v >> 2; v |= v >> 4; v |= v >> 8; v |= v >> 16; v |= v >> 32;
    v++;
    bloom->bits = v;
    bloom->bytes = v >> 3;
  }

  bloom->hashes = (uint8_t)ceil(0.693147180559945 * bloom->bpe);  // ln(2)
  
  bloom->bf = (uint8_t *)calloc(bloom->bytes, sizeof(uint8_t));
  if (bloom->bf == NULL) {                                   // LCOV_EXCL_START
    return 1;
  }                                                          // LCOV_EXCL_STOP

  bloom->ready = 1;
  bloom->major = BLOOM_VERSION_MAJOR;
  bloom->minor = BLOOM_VERSION_MINOR;
  return 0;
}

int bloom_check(struct bloom * bloom, const void * buffer, int len)
{
  if (bloom->ready == 0) {
    printf("bloom at %p not initialized!\n", (void *)bloom);
    return -1;
  }
  uint8_t hits = 0;
  XXH128_hash_t __h = XXH3_128bits(buffer, len);
  uint64_t a = __h.low64;
  uint64_t b = (__h.high64 << 1) | 1; // ensure odd step
  uint64_t mask = 0;
  if ((bloom->bits & (bloom->bits - 1)) == 0) { mask = bloom->bits - 1; }
  uint64_t x;
  uint8_t i;
  for (i = 0; i < bloom->hashes; i++) {
    x = mask ? ((a + b*i) & mask) : ((a + b*i) % bloom->bits);
    if (test_bit(bloom, x)) {
      hits++;
    } else {
      return 0;
    }
  }
  if (hits == bloom->hashes) {
    return 1;                // 1 == element already in (or collision)
  }
  return 0;
}


int bloom_add(struct bloom * bloom, const void * buffer, int len)
{
  return bloom_check_add(bloom, buffer, len, 1);
}

void bloom_print(struct bloom * bloom)
{
  printf("bloom at %p\n", (void *)bloom);
  if (!bloom->ready) { printf(" *** NOT READY ***\n"); }
  printf(" ->version = %d.%d\n", bloom->major, bloom->minor);
  printf(" ->entries = %" PRIu64 "\n", bloom->entries);
  printf(" ->error = %Lf\n", bloom->error);
  printf(" ->bits = %" PRIu64 "\n", bloom->bits);
  printf(" ->bits per elem = %f\n", bloom->bpe);
  printf(" ->bytes = %" PRIu64 "\n", bloom->bytes);
  unsigned int KB = bloom->bytes / 1024;
  unsigned int MB = KB / 1024;
  printf(" (%u KB, %u MB)\n", KB, MB);
  printf(" ->hash functions = %d\n", bloom->hashes);
}

void bloom_free(struct bloom * bloom)
{
  if (bloom->mapped_chunks) {
    bloom_unmap(bloom);
    return;
  }
  if (bloom->ready) {
    free(bloom->bf);
  }
  bloom->ready = 0;
}

int bloom_reset(struct bloom * bloom)
{
  if (!bloom->ready) return 1;
  if (bloom->mapped_chunks > 1 && bloom->bf_chunks) {
    for (uint32_t i = 0; i < bloom->mapped_chunks; i++) {
      uint64_t cbytes = (i == bloom->mapped_chunks - 1) ? bloom->last_chunk_bytes : bloom->chunk_bytes;
      memset(bloom->bf_chunks[i], 0, cbytes);
    }
  } else {
    memset(bloom->bf, 0, bloom->bytes);
  }
  return 0;
}
int bloom_save(struct bloom * bloom, char * filename)
{
  if (filename == NULL || filename[0] == 0) {
    return 1;
  }

  int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) {
    return 1;
  }

  ssize_t out;
  uint16_t size;
  struct bloom copy;

  out = write(fd, BLOOM_MAGIC, strlen(BLOOM_MAGIC));
  if (out != (ssize_t)strlen(BLOOM_MAGIC)) { goto save_error; }        // LCOV_EXCL_LINE

  size = sizeof(struct bloom);
  out = write(fd, &size, sizeof(uint16_t));
  if (out != sizeof(uint16_t)) { goto save_error; }           // LCOV_EXCL_LINE

  copy = *bloom;
  copy.bf = NULL;
  copy.bf_chunks = NULL;
  out = write(fd, &copy, sizeof(struct bloom));
  if (out != sizeof(struct bloom)) { goto save_error; }       // LCOV_EXCL_LINE

  if (bloom->mapped_chunks > 1 && bloom->bf_chunks) {
    close(fd);
    for (uint32_t i = 0; i < bloom->mapped_chunks; i++) {
      uint64_t cbytes = (i == bloom->mapped_chunks - 1) ? bloom->last_chunk_bytes : bloom->chunk_bytes;
      msync(bloom->bf_chunks[i], cbytes, MS_SYNC);
      char fname[1024];
      snprintf(fname, sizeof(fname), "%s.%u", filename, i);
      int cfd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
      if (cfd < 0) {
        return 1;
      }
      ssize_t outc = write(cfd, bloom->bf_chunks[i], cbytes);
      if (outc != (ssize_t)cbytes) {
        close(cfd);
        return 1;
      }
      close(cfd);
    }
    return 0;
  }

  out = write(fd, bloom->bf, bloom->bytes);
  if (out != (ssize_t)bloom->bytes) { goto save_error; }               // LCOV_EXCL_LINE

  close(fd);
  return 0;
                                                             // LCOV_EXCL_START
 save_error:
  close(fd);
  return 1;
                                                             // LCOV_EXCL_STOP
}


int bloom_load(struct bloom * bloom, char * filename)
{
  int rv = 0;

  if (filename == NULL || filename[0] == 0) { return 1; }
  if (bloom == NULL) { return 2; }

  memset(bloom, 0, sizeof(struct bloom));

  int fd = open(filename, O_RDONLY);
  if (fd < 0) { return 3; }

  char line[30];
  memset(line, 0, 30);
  ssize_t in = read(fd, line, strlen(BLOOM_MAGIC));

  if (in != (ssize_t)strlen(BLOOM_MAGIC)) {
    rv = 4;
    goto load_error;
  }

  if (strncmp(line, BLOOM_MAGIC, strlen(BLOOM_MAGIC))) {
    rv = 5;
    goto load_error;
  }

  uint16_t size;
  in = read(fd, &size, sizeof(uint16_t));
  if (in != sizeof(uint16_t)) {
    rv = 6;
    goto load_error;
  }

  if (size != sizeof(struct bloom)) {
    rv = 7;
    goto load_error;
  }

  in = read(fd, bloom, sizeof(struct bloom));
  if (in != sizeof(struct bloom)) {
    rv = 8;
    goto load_error;
  }

  bloom->bf = NULL;
  bloom->bf_chunks = NULL;
  if (bloom->major != BLOOM_VERSION_MAJOR) {
    rv = 9;
    goto load_error;
  }

  if (bloom->mapped_chunks >= 1) {
    if (bloom->mapped_chunks > 1) {
      bloom->bf_chunks = (uint8_t**)calloc(bloom->mapped_chunks, sizeof(uint8_t*));
      if (!bloom->bf_chunks) { rv = 10; goto load_error; }
      for (uint32_t i = 0; i < bloom->mapped_chunks; i++) {
        uint64_t cbytes = (i == bloom->mapped_chunks - 1) ? bloom->last_chunk_bytes : bloom->chunk_bytes;
        char fname[1024];
        snprintf(fname, sizeof(fname), "%s.%u", filename, i);
        int cfd = open(fname, O_RDWR);
        if (cfd < 0) { rv = 11; goto load_error_chunks; }
        uint8_t *map = (uint8_t*)mmap(NULL, cbytes, PROT_READ | PROT_WRITE, MAP_SHARED, cfd, 0);
        close(cfd);
        if (map == MAP_FAILED) { rv = 12; goto load_error_chunks; }
#ifdef __linux__
        madvise(map, cbytes, MADV_RANDOM);
#ifdef MADV_HUGEPAGE
        madvise(map, cbytes, MADV_HUGEPAGE);
#endif
#endif
        bloom->bf_chunks[i] = map;
      }
      bloom->bf = bloom->bf_chunks[0];
    } else {
      off_t offset = strlen(BLOOM_MAGIC) + sizeof(uint16_t) + sizeof(struct bloom);
      int cfd = open(filename, O_RDWR);
      if (cfd < 0) { rv = 11; goto load_error; }
      uint8_t *map = (uint8_t*)mmap(NULL, bloom->bytes, PROT_READ | PROT_WRITE, MAP_SHARED, cfd, offset);
      close(cfd);
      if (map == MAP_FAILED) { rv = 12; goto load_error; }
#ifdef __linux__
      madvise(map, bloom->bytes, MADV_RANDOM);
#ifdef MADV_HUGEPAGE
      madvise(map, bloom->bytes, MADV_HUGEPAGE);
#endif
#endif
      bloom->bf = map;
    }
  } else {
    bloom->bf = (unsigned char *)malloc(bloom->bytes);
    if (bloom->bf == NULL) { rv = 10; goto load_error; }        // LCOV_EXCL_LINE
    in = read(fd, bloom->bf, bloom->bytes);
    if (in != (ssize_t)bloom->bytes) {
      rv = 11;
      free(bloom->bf);
      bloom->bf = NULL;
      goto load_error;
    }
  }

  bloom->ready = 1;
  close(fd);
  return rv;

load_error_chunks:
  if (bloom->bf_chunks) {
    for (uint32_t i = 0; i < bloom->mapped_chunks; i++) {
      if (bloom->bf_chunks[i]) {
        uint64_t cbytes = (i == bloom->mapped_chunks - 1) ? bloom->last_chunk_bytes : bloom->chunk_bytes;
        munmap(bloom->bf_chunks[i], cbytes);
      }
    }
    free(bloom->bf_chunks);
    bloom->bf_chunks = NULL;
  }
  bloom->bf = NULL;

load_error:
  close(fd);
  bloom->ready = 0;
  return rv;
}

const char * bloom_version()
{
  return MAKESTRING(BLOOM_VERSION);
}

#ifndef _WIN64
static uint64_t bytes_for_entries_error(uint64_t entries, long double error) {
  long double num = -log(error);
  long double denom = 0.480453013918201L; // ln(2)^2
  long double bpe = (num / denom);
  long double allbits = (long double)entries * bpe;
  uint64_t bits = (uint64_t)allbits;
  uint64_t bytes = bits / 8;
  if (bits % 8) {
    bytes += 1;
  }
  return bytes;
}

static void entries_hashes_for_bytes(uint64_t bytes, uint64_t *entries, uint8_t *hashes) {
  uint64_t best_n = 0;
  uint32_t best_k = 0;
  for (uint32_t bits = 20; bits <= 64; bits += 2) {
    uint64_t n = 1ULL << bits;
    uint32_t k = 1U << ((bits - 20) / 2);
    long double error = powl(0.5L, (long double)k);
    uint64_t need = bytes_for_entries_error(n, error);
    if (need > bytes) {
      break;
    }
    best_n = n;
    best_k = k;
  }
  if (best_n == 0) {
    best_n = 1ULL << 20;
    best_k = 1;
  }
  if (entries) {
    *entries = best_n;
  }
  if (hashes) {
    *hashes = (uint8_t)best_k;
  }
}

int bloom_load_mmap(struct bloom *bloom, const char *filename, uint32_t chunks)
{
  if (!bloom || !filename) {
    return 1;
  }
  memset(bloom, 0, sizeof(struct bloom));
  if (chunks < 1) {
    chunks = 1;
  }
  bloom->mapped_chunks = chunks;

  uint64_t total_bytes = 0;
  uint64_t first_cbytes = 0;
  uint64_t *sizes = NULL;
  if (chunks > 1) {
    bloom->bf_chunks = (uint8_t**)calloc(chunks, sizeof(uint8_t*));
    sizes = (uint64_t*)calloc(chunks, sizeof(uint64_t));
    if (!bloom->bf_chunks || !sizes) {
      free(bloom->bf_chunks);
      free(sizes);
      return 1;
    }
  }

  for (uint32_t i = 0; i < chunks; i++) {
    char fname[1024];
    if (chunks > 1) {
      snprintf(fname, sizeof(fname), "%s.%u", filename, i);
    } else {
      snprintf(fname, sizeof(fname), "%s", filename);
    }
    int fd = open(fname, O_RDWR);
    if (fd < 0) {
      goto load_error;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
      close(fd);
      goto load_error;
    }
    uint64_t cbytes = (uint64_t)st.st_size;
    uint8_t *map = (uint8_t*)mmap(NULL, cbytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (map == MAP_FAILED) {
      goto load_error;
    }
    if (chunks > 1) {
      bloom->bf_chunks[i] = map;
      sizes[i] = cbytes;
      if (i == 0) {
        bloom->chunk_bytes = cbytes;
      }
      if (i == chunks - 1) {
        bloom->last_chunk_bytes = cbytes;
      }
    } else {
      bloom->bf = map;
      first_cbytes = cbytes;
      bloom->chunk_bytes = cbytes;
      bloom->last_chunk_bytes = cbytes;
    }
    total_bytes += cbytes;
  }

  if (chunks > 1) {
    bloom->bf = bloom->bf_chunks[0];
  }

  bloom->bytes = total_bytes;
  bloom->bits = bloom->bytes * 8;
  entries_hashes_for_bytes(bloom->bytes, &bloom->entries, &bloom->hashes);
  bloom->bpe = (double)bloom->bits / (double)bloom->entries;
  bloom->error = powl(0.5L, (long double)bloom->hashes);
  bloom->ready = 1;
  bloom->major = BLOOM_VERSION_MAJOR;
  bloom->minor = BLOOM_VERSION_MINOR;

  if (sizes) {
    free(sizes);
  }
  return 0;

load_error:
  if (chunks > 1) {
    for (uint32_t j = 0; j < chunks; j++) {
      if (bloom->bf_chunks && bloom->bf_chunks[j] && sizes && sizes[j]) {
        munmap(bloom->bf_chunks[j], sizes[j]);
      }
    }
    free(bloom->bf_chunks);
    if (sizes) {
      free(sizes);
    }
  } else if (bloom->bf && first_cbytes) {
    munmap(bloom->bf, first_cbytes);
  }
  memset(bloom, 0, sizeof(struct bloom));
  return 1;
}

/*
 * Initialize bloom filter backed by a memory mapped file. The resulting
 * bloom->bf points directly to the mapped region so the filter can be
 * larger than available RAM.
 *
 * If the file already exists and its size matches the expected size for the
 * requested number of entries, it will be mapped as is without truncation.
 * When @resize is non-zero, an existing file will be resized to match the
 * requested number of entries. If the file exists with a different size and
 * @resize is zero, an error is returned and no mapping occurs.
 */
int bloom_init_mmap(struct bloom *bloom, uint64_t entries, long double error, const char *filename, int resize, uint32_t chunks)
{
  memset(bloom, 0, sizeof(struct bloom));
  if (entries < 1000 || error <= 0 || error >= 1) {
    return 1;
  }

  bloom->entries = entries;
  bloom->error = error;

  long double num = -log(bloom->error);
  long double denom = 0.480453013918201; // ln(2)^2
  bloom->bpe = (num / denom);

  long double dentries = (long double)entries;
  long double allbits = dentries * bloom->bpe;
  bloom->bits = (uint64_t)allbits;

  bloom->bytes = (uint64_t)bloom->bits / 8;
  if (bloom->bits % 8) {
    bloom->bytes += 1;
  }

  /* Align bits to next power-of-two for fast masking */
  if ((bloom->bits & (bloom->bits - 1)) != 0) {
    uint64_t v = bloom->bits;
    v--;
    v |= v >> 1; v |= v >> 2; v |= v >> 4; v |= v >> 8; v |= v >> 16; v |= v >> 32;
    v++;
    bloom->bits = v;
    bloom->bytes = v >> 3;
  }

  bloom->hashes = (uint8_t)ceil(0.693147180559945 * bloom->bpe); // ln(2)

  if (chunks < 1) {
    chunks = 1;
  }
  bloom->mapped_chunks = chunks;
  bloom->chunk_bytes = (chunks > 1) ? bloom->bytes / chunks : bloom->bytes;
  bloom->last_chunk_bytes = bloom->bytes - bloom->chunk_bytes * (chunks - 1);

  if (chunks > 1) {
    bloom->bf_chunks = (uint8_t**)calloc(chunks, sizeof(uint8_t*));
    if (!bloom->bf_chunks) {
      return 1;
    }
  }

  struct stat st;
  int fd;
  for (uint32_t i = 0; i < chunks; i++) {
    uint64_t cbytes = (i == chunks - 1) ? bloom->last_chunk_bytes : bloom->chunk_bytes;
    char fname[1024];
    if (chunks > 1) {
      snprintf(fname, sizeof(fname), "%s.%u", filename, i);
    } else {
      snprintf(fname, sizeof(fname), "%s", filename);
    }

    int file_exists = (stat(fname, &st) == 0);
    if (file_exists) {
      fd = open(fname, O_RDWR);
      if (fd < 0) {
        int err = errno;
        fprintf(stderr, "bloom_init_mmap: open('%s') failed: %s\n", fname, strerror(err));
        return 1;
      }
      if ((uint64_t)st.st_size != cbytes) {
        if (resize) {
          if (ftruncate(fd, cbytes) != 0) {
            int err = errno;
            close(fd);
            fprintf(stderr, "bloom_init_mmap: ftruncate('%s', %llu) failed: %s\n", fname,
                    (unsigned long long)cbytes, strerror(err));
            return 1;
          }
        } else {
          fprintf(stderr, "bloom_init_mmap: file '%s' size %lld does not match expected %llu\n",
                  fname, (long long)st.st_size, (unsigned long long)cbytes);
          close(fd);
          return 1;
        }
      }
    } else {
      fd = open(fname, O_RDWR | O_CREAT, 0644);
      if (fd < 0) {
        int err = errno;
        fprintf(stderr, "bloom_init_mmap: open('%s') failed: %s\n", fname, strerror(err));
        return 1;
      }
      if (ftruncate(fd, cbytes) != 0) {
        int err = errno;
        close(fd);
        fprintf(stderr, "bloom_init_mmap: ftruncate('%s', %llu) failed: %s\n", fname,
                (unsigned long long)cbytes, strerror(err));
        return 1;
      }
    }

    uint8_t *map = (uint8_t*)mmap(NULL, cbytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
      int err = errno;
      close(fd);
      fprintf(stderr, "bloom_init_mmap: mmap('%s', %llu) failed: %s\n", fname,
              (unsigned long long)cbytes, strerror(err));
      return 1;
    }
    close(fd);
#ifdef __linux__
    madvise(map, cbytes, MADV_RANDOM);
#ifdef MADV_HUGEPAGE
    madvise(map, cbytes, MADV_HUGEPAGE);
#endif
#endif
    if (chunks > 1) {
      bloom->bf_chunks[i] = map;
    } else {
      bloom->bf = map;
    }
  }

  if (chunks > 1) {
    bloom->bf = bloom->bf_chunks[0];
  }

  bloom->ready = 1;
  bloom->major = BLOOM_VERSION_MAJOR;
  bloom->minor = BLOOM_VERSION_MINOR;
  return 0;
}

void bloom_unmap(struct bloom *bloom)
{
  if (bloom->mapped_chunks >= 1 && bloom->bf_chunks) {
    for (uint32_t i = 0; i < bloom->mapped_chunks; i++) {
      uint64_t cbytes = (i == bloom->mapped_chunks - 1) ? bloom->last_chunk_bytes : bloom->chunk_bytes;
      if (bloom->bf_chunks[i] && cbytes) {
        munmap(bloom->bf_chunks[i], cbytes);
      }
    }
    free(bloom->bf_chunks);
    bloom->bf_chunks = NULL;
    bloom->bf = NULL;
  } else if (bloom->mapped_chunks >= 1 && bloom->bf && bloom->bytes) {
    munmap(bloom->bf, bloom->bytes);
    bloom->bf = NULL;
  }
  bloom->ready = 0;
}
#else
int bloom_init_mmap(struct bloom *bloom, uint64_t entries, long double error, const char *filename, int resize, uint32_t chunks)
{
  (void)filename;
  (void)resize;
  (void)chunks;
  return bloom_init2(bloom, entries, error);
}

int bloom_load_mmap(struct bloom *bloom, const char *filename, uint32_t chunks)
{
  (void)bloom;
  (void)filename;
  (void)chunks;
  return 1;
}

void bloom_unmap(struct bloom *bloom)
{
  bloom_free(bloom);
}
#endif
