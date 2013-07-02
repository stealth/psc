#ifndef __rc4_h__
#define __rc4_h__

#ifdef __cplusplus

extern "C" {
#endif

typedef struct    {
	unsigned char state[256];
	unsigned char x;
	unsigned char y;
} rc4_key;


void prepare_key(unsigned char *, size_t, rc4_key *);
void rc4(unsigned char *,int , rc4_key *);
void swap_byte(unsigned char *,unsigned char *);

#ifdef __cplusplus
}
#endif

#endif

