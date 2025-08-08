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
#ifndef _WIN64
#include <sys/mman.h>
#else
#include <io.h>
#endif
#include <unistd.h>
#include <pthread.h>

#include "bloom.h"
#include "../xxhash/xxhash.h"

#define MAKESTRING(n) STRING(n)
#define STRING(n) #n
#define BLOOM_MAGIC "libbloom2"
#define BLOOM_VERSION_MAJOR 2
#define BLOOM_VERSION_MINOR 201

inline static int test_bit_set_bit(uint8_t *bf, uint64_t bit, int set_bit)
{
  uint64_t byte = bit >> 3;
  uint8_t c = bf[byte];	 // expensive memory access
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

inline static int test_bit(uint8_t *bf, uint64_t bit)
{
  uint64_t byte = bit >> 3;
  uint8_t c = bf[byte];	 // expensive memory access
  uint8_t mask = 1 << (bit % 8);
  if (c & mask) {
    return 1;
  } else {
    return 0;
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
    if (test_bit_set_bit(bloom->bf, x, add)) {
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

int bloom_init_mapped(struct bloom *bloom, const char *path,
                      uint64_t entries, long double error,
                      uint32_t segments)
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

  if (segments == 0) segments = 1;
  bloom->segments = segments;

  bloom->segment_ptrs =
      (uint8_t **)calloc(bloom->segments, sizeof(uint8_t *));
  bloom->segment_sizes =
      (size_t *)calloc(bloom->segments, sizeof(size_t));
#ifdef _WIN64
  bloom->segment_fds =
      (HANDLE *)calloc(bloom->segments, sizeof(HANDLE));
#else
  bloom->segment_fds =
      (int *)calloc(bloom->segments, sizeof(int));
#endif
  if (!bloom->segment_ptrs || !bloom->segment_sizes || !bloom->segment_fds) {
    free(bloom->segment_ptrs);
    free(bloom->segment_sizes);
    free(bloom->segment_fds);
    return 1;
  }

  size_t seg_bytes = bloom->bytes / bloom->segments;
  size_t remainder = bloom->bytes % bloom->segments;

  void *addr = NULL;
  for (uint32_t i = 0; i < bloom->segments; i++) {
    size_t this_seg = seg_bytes + (i == bloom->segments - 1 ? remainder : 0);
    bloom->segment_sizes[i] = this_seg;
    char *fname;
    size_t pathlen = strlen(path) + 32;
    fname = (char *)malloc(pathlen);
    if (!fname) {
      bloom_free_mapped(bloom);
      return 1;
    }
    if (bloom->segments == 1) {
      snprintf(fname, pathlen, "%s", path);
    } else {
      snprintf(fname, pathlen, "%s.%u", path, i);
    }
#ifdef _WIN64
    HANDLE hFile = CreateFile(fname, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                              OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    free(fname);
    if (hFile == INVALID_HANDLE_VALUE) {
      bloom_free_mapped(bloom);
      return 1;
    }
    LARGE_INTEGER sz;
    sz.QuadPart = this_seg;
    if (SetFilePointerEx(hFile, sz, NULL, FILE_BEGIN) == 0 ||
        SetEndOfFile(hFile) == 0) {
      CloseHandle(hFile);
      bloom_free_mapped(bloom);
      return 1;
    }
    HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (hMap == NULL) {
      CloseHandle(hFile);
      bloom_free_mapped(bloom);
      return 1;
    }
    void *map = MapViewOfFileEx(hMap, FILE_MAP_ALL_ACCESS, 0, 0, this_seg, addr);
    CloseHandle(hMap);
    if (!map) {
      CloseHandle(hFile);
      bloom_free_mapped(bloom);
      return 1;
    }
    bloom->segment_fds[i] = hFile;
    bloom->segment_ptrs[i] = (uint8_t *)map;
#else
    int fd = open(fname, O_RDWR | O_CREAT, 0644);
    free(fname);
    if (fd < 0) {
      bloom_free_mapped(bloom);
      return 1;
    }
    if (ftruncate(fd, (off_t)this_seg) != 0) {
      close(fd);
      bloom_free_mapped(bloom);
      return 1;
    }
    void *map = mmap(addr, this_seg, PROT_READ | PROT_WRITE,
                     MAP_SHARED | (addr ? MAP_FIXED : 0), fd, 0);
    if (map == MAP_FAILED) {
      close(fd);
      bloom_free_mapped(bloom);
      return 1;
    }
    bloom->segment_fds[i] = fd;
    bloom->segment_ptrs[i] = (uint8_t *)map;
#endif
    if (i == 0) {
      bloom->bf = bloom->segment_ptrs[i];
    }
    addr = bloom->segment_ptrs[i] + this_seg;
  }

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
    if (test_bit(bloom->bf, x)) {
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

void bloom_free_mapped(struct bloom *bloom)
{
  if (!bloom->ready && bloom->segments == 0) {
    return;
  }

  if (bloom->segments == 0) {
    if (bloom->ready && bloom->bf) {
      free(bloom->bf);
    }
    bloom->ready = 0;
    return;
  }

  for (uint32_t i = 0; i < bloom->segments; i++) {
    if (bloom->segment_ptrs && bloom->segment_ptrs[i]) {
#ifdef _WIN64
      UnmapViewOfFile(bloom->segment_ptrs[i]);
      if (bloom->segment_fds)
        CloseHandle(bloom->segment_fds[i]);
#else
      munmap(bloom->segment_ptrs[i], bloom->segment_sizes[i]);
      if (bloom->segment_fds)
        close(bloom->segment_fds[i]);
#endif
    }
  }
  free(bloom->segment_ptrs);
  free(bloom->segment_sizes);
  free(bloom->segment_fds);
  bloom->segment_ptrs = NULL;
  bloom->segment_sizes = NULL;
  bloom->segment_fds = NULL;
  bloom->segments = 0;
  bloom->bf = NULL;
  bloom->ready = 0;
}

void bloom_free(struct bloom * bloom)
{
  if (bloom->segments > 0) {
    bloom_free_mapped(bloom);
    return;
  }
  if (bloom->ready && bloom->bf) {
    free(bloom->bf);
  }
  bloom->ready = 0;
}

int bloom_reset(struct bloom * bloom)
{
  if (!bloom->ready) return 1;
  memset(bloom->bf, 0, bloom->bytes);
  return 0;
}
/*
int bloom_save(struct bloom * bloom, char * filename)
{
  if (filename == NULL || filename[0] == 0) {
    return 1;
  }

  int fd = open(filename, O_WRONLY | O_CREAT, 0644);
  if (fd < 0) {
    return 1;
  }

  ssize_t out = write(fd, BLOOM_MAGIC, strlen(BLOOM_MAGIC));
  if (out != strlen(BLOOM_MAGIC)) { goto save_error; }        // LCOV_EXCL_LINE

  uint16_t size = sizeof(struct bloom);
  out = write(fd, &size, sizeof(uint16_t));
  if (out != sizeof(uint16_t)) { goto save_error; }           // LCOV_EXCL_LINE

  out = write(fd, bloom, sizeof(struct bloom));
  if (out != sizeof(struct bloom)) { goto save_error; }       // LCOV_EXCL_LINE

  out = write(fd, bloom->bf, bloom->bytes);
  if (out != bloom->bytes) { goto save_error; }               // LCOV_EXCL_LINE

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

  if (in != strlen(BLOOM_MAGIC)) {
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
  if (bloom->major != BLOOM_VERSION_MAJOR) {
    rv = 9;
    goto load_error;
  }

  bloom->bf = (unsigned char *)malloc(bloom->bytes);
  if (bloom->bf == NULL) { rv = 10; goto load_error; }        // LCOV_EXCL_LINE

  in = read(fd, bloom->bf, bloom->bytes);
  if (in != bloom->bytes) {
    rv = 11;
    free(bloom->bf);
    bloom->bf = NULL;
    goto load_error;
  }

  close(fd);
  return rv;

 load_error:
  close(fd);
  bloom->ready = 0;
  return rv;
}
*/

const char * bloom_version()
{
  return MAKESTRING(BLOOM_VERSION);
}
