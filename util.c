#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <inttypes.h>

#if defined(_WIN64) && !defined(__CYGWIN__)
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "util.h"


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
