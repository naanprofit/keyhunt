#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <inttypes.h>
#include <cstring>

#if defined(_WIN64) && !defined(__CYGWIN__)
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "util.h"


typedef struct {
        uint32_t h[4];
        uint64_t length;
        uint8_t buffer[64];
        size_t buffer_len;
} md5_ctx;

static const uint32_t md5_init_state[4] = {
        0x67452301U, 0xefcdab89U, 0x98badcfeU, 0x10325476U
};

static inline uint32_t md5_leftrotate(uint32_t x, uint32_t c) {
        return (x << c) | (x >> (32 - c));
}

static void md5_transform(md5_ctx *ctx, const uint8_t block[64]) {
        uint32_t a = ctx->h[0];
        uint32_t b = ctx->h[1];
        uint32_t c = ctx->h[2];
        uint32_t d = ctx->h[3];
        uint32_t w[16];

        for (int i = 0; i < 16; i++) {
                w[i] = (uint32_t)block[i * 4] |
                       ((uint32_t)block[i * 4 + 1] << 8) |
                       ((uint32_t)block[i * 4 + 2] << 16) |
                       ((uint32_t)block[i * 4 + 3] << 24);
        }

        const uint32_t k[] = {
                0xd76aa478U, 0xe8c7b756U, 0x242070dbU, 0xc1bdceeeU,
                0xf57c0fafU, 0x4787c62aU, 0xa8304613U, 0xfd469501U,
                0x698098d8U, 0x8b44f7afU, 0xffff5bb1U, 0x895cd7beU,
                0x6b901122U, 0xfd987193U, 0xa679438eU, 0x49b40821U,
                0xf61e2562U, 0xc040b340U, 0x265e5a51U, 0xe9b6c7aaU,
                0xd62f105dU, 0x02441453U, 0xd8a1e681U, 0xe7d3fbc8U,
                0x21e1cde6U, 0xc33707d6U, 0xf4d50d87U, 0x455a14edU,
                0xa9e3e905U, 0xfcefa3f8U, 0x676f02d9U, 0x8d2a4c8aU,
                0xfffa3942U, 0x8771f681U, 0x6d9d6122U, 0xfde5380cU,
                0xa4beea44U, 0x4bdecfa9U, 0xf6bb4b60U, 0xbebfbc70U,
                0x289b7ec6U, 0xeaa127faU, 0xd4ef3085U, 0x04881d05U,
                0xd9d4d039U, 0xe6db99e5U, 0x1fa27cf8U, 0xc4ac5665U,
                0xf4292244U, 0x432aff97U, 0xab9423a7U, 0xfc93a039U,
                0x655b59c3U, 0x8f0ccc92U, 0xffeff47dU, 0x85845dd1U,
                0x6fa87e4fU, 0xfe2ce6e0U, 0xa3014314U, 0x4e0811a1U,
                0xf7537e82U, 0xbd3af235U, 0x2ad7d2bbU, 0xeb86d391U
        };

        const uint32_t r[] = {
                7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
        };

        for (uint32_t i = 0; i < 64; i++) {
                uint32_t f, g;
                if (i < 16) {
                        f = (b & c) | (~b & d);
                        g = i;
                } else if (i < 32) {
                        f = (d & b) | (~d & c);
                        g = (5 * i + 1) % 16;
                } else if (i < 48) {
                        f = b ^ c ^ d;
                        g = (3 * i + 5) % 16;
                } else {
                        f = c ^ (b | ~d);
                        g = (7 * i) % 16;
                }
                uint32_t temp = d;
                d = c;
                c = b;
                uint32_t sum = a + f + k[i] + w[g];
                b = b + md5_leftrotate(sum, r[i]);
                a = temp;
        }

        ctx->h[0] += a;
        ctx->h[1] += b;
        ctx->h[2] += c;
        ctx->h[3] += d;
}

static void md5_init(md5_ctx *ctx) {
        memcpy(ctx->h, md5_init_state, sizeof(md5_init_state));
        ctx->length = 0;
        ctx->buffer_len = 0;
}

static void md5_update(md5_ctx *ctx, const uint8_t *data, size_t len) {
        ctx->length += (uint64_t)len * 8;
        size_t offset = 0;
        if (ctx->buffer_len) {
                size_t to_copy = 64 - ctx->buffer_len;
                if (to_copy > len) {
                        to_copy = len;
                }
                memcpy(ctx->buffer + ctx->buffer_len, data, to_copy);
                ctx->buffer_len += to_copy;
                offset += to_copy;
                if (ctx->buffer_len == 64) {
                        md5_transform(ctx, ctx->buffer);
                        ctx->buffer_len = 0;
                }
        }
        while (offset + 64 <= len) {
                md5_transform(ctx, data + offset);
                offset += 64;
        }
        if (offset < len) {
                ctx->buffer_len = len - offset;
                memcpy(ctx->buffer, data + offset, ctx->buffer_len);
        }
}

static void md5_final(md5_ctx *ctx, uint8_t digest[16]) {
        uint8_t padding[64] = {0x80};
        uint8_t length_bytes[8];
        for (int i = 0; i < 8; i++) {
                length_bytes[i] = (uint8_t)((ctx->length >> (8 * i)) & 0xff);
        }
        size_t padding_len = (ctx->buffer_len < 56) ? (56 - ctx->buffer_len) : (120 - ctx->buffer_len);
        md5_update(ctx, padding, padding_len);
        md5_update(ctx, length_bytes, 8);
        for (int i = 0; i < 4; i++) {
                digest[i * 4] = (uint8_t)(ctx->h[i] & 0xff);
                digest[i * 4 + 1] = (uint8_t)((ctx->h[i] >> 8) & 0xff);
                digest[i * 4 + 2] = (uint8_t)((ctx->h[i] >> 16) & 0xff);
                digest[i * 4 + 3] = (uint8_t)((ctx->h[i] >> 24) & 0xff);
        }
}

int md5_file(const char *path, uint8_t digest[16]) {
        if (digest == NULL || path == NULL) {
                return -1;
        }
        FILE *f = fopen(path, "rb");
        if (!f) {
                return -1;
        }
        md5_ctx ctx;
        md5_init(&ctx);
        uint8_t buffer[4096];
        size_t read_bytes;
        while ((read_bytes = fread(buffer, 1, sizeof(buffer), f)) > 0) {
                md5_update(&ctx, buffer, read_bytes);
        }
        int error = ferror(f);
        fclose(f);
        if (error) {
                return -1;
        }
        md5_final(&ctx, digest);
        return 0;
}

void md5_to_hex(const uint8_t digest[16], char hex[33]) {
        static const char hexdigits[] = "0123456789abcdef";
        if (!digest || !hex) {
                return;
        }
        for (int i = 0; i < 16; i++) {
                hex[i * 2] = hexdigits[(digest[i] >> 4) & 0x0f];
                hex[i * 2 + 1] = hexdigits[digest[i] & 0x0f];
        }
        hex[32] = '\0';
}


char *ltrim(char *str, const char *seps)	{
	size_t totrim;
	if (seps == NULL) {
		seps = "\t\n\v\f\r ";
	}
	totrim = strspn(str, seps);
	if (totrim > 0) {
		size_t len = strlen(str);
		if (totrim == len) {
			str[0] = '\0';
		}
		else {
			memmove(str, str + totrim, len + 1 - totrim);
		}
	}
	return str;
}

char *rtrim(char *str, const char *seps)	{
	int i;
	if (seps == NULL) {
		seps = "\t\n\v\f\r ";
	}
	i = strlen(str) - 1;
	while (i >= 0 && strchr(seps, str[i]) != NULL) {
		str[i] = '\0';
		i--;
	}
	return str;
}

char *trim(char *str, const char *seps)	{
	return ltrim(rtrim(str, seps), seps);
}

int indexOf(char *s,const char **array,int length_array)	{
	int index = -1,i,continuar = 1;
	for(i = 0; i <length_array && continuar; i++)	{
		if(strcmp(s,array[i]) == 0)	{
			index = i;
			continuar = 0;
		}
	}
	return index;
}

char *nextToken(Tokenizer *t)	{
	if(t->current < t->n)	{
		t->current++;
		return t->tokens[t->current-1];
	}
	else {
		return  NULL;
	}
}
int hasMoreTokens(Tokenizer *t)	{
	return (t->current < t->n);
}

void stringtokenizer(char *data,Tokenizer *t)	{
	char *token;
	t->tokens = NULL;
	t->n = 0;
	t->current = 0;
	trim(data,"\t\n\r :");
	token = strtok(data," \t:");
	while(token != NULL)	{
		t->n++;
		t->tokens = (char**) realloc(t->tokens,sizeof(char*)*t->n);
		if(t->tokens == NULL)	{
			printf("Out of memory\n");
			exit(0);
		}
		t->tokens[t->n - 1] = token;
		token = strtok(NULL," \t:");
	}
}

void freetokenizer(Tokenizer *t)	{
	if(t->n > 0)	{
		free(t->tokens);
	}
	memset(t,0,sizeof(Tokenizer));
}


/*
	Aux function to get the hexvalues of the data
*/
char *tohex(char *ptr,int length){
  char *buffer;
  int offset = 0;
  unsigned char c;
  buffer = (char *) malloc((length * 2)+1);
  for (int i = 0; i <length; i++) {
    c = ptr[i];
	sprintf((char*) (buffer + offset),"%.2x",c);
	offset+=2;
  }
  buffer[length*2] = 0;
  return buffer;
}

void tohex_dst(char *ptr,int length,char *dst)	{
  int offset = 0;
  unsigned char c;
  for (int i = 0; i <length; i++) {
    c = ptr[i];
	sprintf((char*) (dst + offset),"%.2x",c);
	offset+=2;
  }
  dst[length*2] = 0;
}

int hexs2bin(char *hex, unsigned char *out)	{
	int len;
	char   b1;
	char   b2;
	int i;

	if (hex == NULL || *hex == '\0' || out == NULL)
		return 0;

	len = strlen(hex);
	if (len % 2 != 0)
		return 0;
	len /= 2;

	memset(out, 'A', len);
	for (i=0; i<len; i++) {
		if (!hexchr2bin(hex[i*2], &b1) || !hexchr2bin(hex[i*2+1], &b2)) {
			return 0;
		}
		out[i] = (b1 << 4) | b2;
	}
	return len;
}

int hexchr2bin(const char hex, char *out)	{
	if (out == NULL)
		return 0;

	if (hex >= '0' && hex <= '9') {
		*out = hex - '0';
	} else if (hex >= 'A' && hex <= 'F') {
		*out = hex - 'A' + 10;
	} else if (hex >= 'a' && hex <= 'f') {
		*out = hex - 'a' + 10;
	} else {
		return 0;
	}

	return 1;
}

void addItemList(char *data, List *l)	{
	l->data = (char**) realloc(l->data,sizeof(char*)* (l->n +1));
	l->data[l->n] = data;
	l->n++;
}

int isValidHex(char *data)	{
	char c;
	int len,i,valid = 1;
	len = strlen(data);
	for(i = 0 ; i <  len && valid ;i++ )	{
		c = data[i];
		valid = ( (c >= '0' && c <='9') || (c >= 'A' && c <='F' ) || (c >= 'a' && c <='f' ) );
	}
        return valid;
}

int validate_nk(uint64_t n, uint64_t k) {
        if(n < (1ULL << 20)) {
                fprintf(stderr,"[E] n must be at least 2^20 (0x100000)\n");
                return 0;
        }
        if(n & (n - 1)) {
                fprintf(stderr,"[E] n must be a power of two\n");
                return 0;
        }
        static const struct { int bits; uint64_t k; } table[] = {
                {20,1},{22,2},{24,4},{26,8},{28,16},{30,32},{32,64},{34,128},{36,256},
                {38,512},{40,1024},{42,2048},{44,4096},{46,8192},{48,16384},{50,32768},
                {52,65536},{54,131072},{56,262144},{58,524288},{60,1048576},{62,2097152},{64,4194304}
        };
        int bits = 0;
        uint64_t tmp = n;
        while(tmp > 1) {
                tmp >>= 1;
                bits++;
        }
        for(unsigned int i=0; i<sizeof(table)/sizeof(table[0]); i++) {
                if(table[i].bits == bits) {
                        if(k > table[i].k) {
                                fprintf(stderr,"[E] k value %" PRIu64 " is too large for n 0x%" PRIx64 " (max %" PRIu64 ")\n",k,n,table[i].k);
                                return 0;
                        }
                        return 1;
                }
        }
        fprintf(stderr,"[E] invalid n 0x%" PRIx64 "\n",n);
        return 0;
}

void print_nk_table(void) {
        printf("+------+----------------------+-------------+\n");
        printf("| bits |  n in hexadecimal    | k max value |\n");
        printf("+------+----------------------+-------------+\n");
        printf("|   20 |             0x100000 | 1 (default) |\n");
        printf("|   22 |             0x400000 | 2           |\n");
        printf("|   24 |            0x1000000 | 4           |\n");
        printf("|   26 |            0x4000000 | 8           |\n");
        printf("|   28 |           0x10000000 | 16          |\n");
        printf("|   30 |           0x40000000 | 32          |\n");
        printf("|   32 |          0x100000000 | 64          |\n");
        printf("|   34 |          0x400000000 | 128         |\n");
        printf("|   36 |         0x1000000000 | 256         |\n");
        printf("|   38 |         0x4000000000 | 512         |\n");
        printf("|   40 |        0x10000000000 | 1024        |\n");
        printf("|   42 |        0x40000000000 | 2048        |\n");
        printf("|   44 |       0x100000000000 | 4096        |\n");
        printf("|   46 |       0x400000000000 | 8192        |\n");
        printf("|   48 |      0x1000000000000 | 16384       |\n");
        printf("|   50 |      0x4000000000000 | 32768       |\n");
        printf("|   52 |     0x10000000000000 | 65536       |\n");
        printf("|   54 |     0x40000000000000 | 131072      |\n");
        printf("|   56 |    0x100000000000000 | 262144      |\n");
        printf("|   58 |    0x400000000000000 | 524288      |\n");
        printf("|   60 |   0x1000000000000000 | 1048576     |\n");
        printf("|   62 |   0x4000000000000000 | 2097152     |\n");
        printf("|   64 |  0x10000000000000000 | 4194304     |\n");
        printf("+------+----------------------+-------------+\n");
}
uint64_t get_total_ram(void){
#if defined(_WIN64) && !defined(__CYGWIN__)
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    if(GlobalMemoryStatusEx(&statex)){
        return statex.ullTotalPhys;
    }
    return 0;
#else
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    if(pages <= 0 || page_size <= 0){
        return 0;
    }
    return (uint64_t)pages * (uint64_t)page_size;
#endif
}
