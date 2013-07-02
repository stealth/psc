#ifndef __misc_h__
#define __misc_h__

void die(const char *);

void fix_size(int);

size_t b64_decode(const char *, unsigned char *);

unsigned char *b64_encode(const char *, size_t, unsigned char *);

const unsigned int BLOCK_SIZE = 1024;

#endif


