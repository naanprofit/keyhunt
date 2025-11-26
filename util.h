#ifndef CUSTOMUTILH
#define CUSTOMUTILH

#include <stdint.h>
typedef struct str_list	{
	int n;
	char **data;
	int *lengths;
}List;

typedef struct str_tokenizer	{
	int current;
	int n;
	char **tokens;
}Tokenizer;

char *ltrim(char *str, const char *seps);
char *rtrim(char *str, const char *seps);
char *trim(char *str, const char *seps);
int indexOf(char *s,const char **array,int length_array);

int hexchr2bin(char hex, char *out);
int hexs2bin(char *hex, unsigned char *out);
char *tohex(char *ptr,int length);
void tohex_dst(char *ptr,int length,char *dst);

int hasMoreTokens(Tokenizer *t);
char *nextToken(Tokenizer *t);

int isValidHex(char *data);
void freetokenizer(Tokenizer *t);
void stringtokenizer(char *data,Tokenizer *t);

int validate_nk(uint64_t n, uint64_t k);
void print_nk_table(void);

uint64_t get_total_ram(void);

int md5_file(const char *path, uint8_t digest[16]);
void md5_to_hex(const uint8_t digest[16], char hex[33]);

#endif // CUSTOMUTILH
