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
    uint8_t c = bloom->bf_chunks[chunk][offset];
    uint8_t mask = 1 << (bit % 8);
    if (c & mask) {
      return 1;
    } else {
      return 0;
    }
  } else {
    uint8_t c = bloom->bf[byte];
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
  uint64_t a = XXH64(buffer, len, 0x59f2815b16f81798);
  uint64_t b = XXH64(buffer, len, a);
  uint64_t x;
  uint8_t i;
  for (i = 0; i < bloom->hashes; i++) {
    x = (a + b*i) % bloom->bits;
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
  uint64_t a = XXH64(buffer, len, 0x59f2815b16f81798);
  uint64_t b = XXH64(buffer, len, a);
  uint64_t x;
  uint8_t i;
  for (i = 0; i < bloom->hashes; i++) {
    x = (a + b*i) % bloom->bits;
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
        return 1;
      }
      if ((uint64_t)st.st_size != cbytes) {
        if (resize) {
          if (ftruncate(fd, cbytes) != 0) {
            close(fd);
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
        return 1;
      }
      if (ftruncate(fd, cbytes) != 0) {
        close(fd);
        return 1;
      }
    }

    uint8_t *map = (uint8_t*)mmap(NULL, cbytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
      close(fd);
      return 1;
    }
    close(fd);
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

void bloom_unmap(struct bloom *bloom)
{
  bloom_free(bloom);
}
#endif
