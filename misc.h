#ifndef psc_misc_h
#define psc_misc_h

namespace ns_psc {

void die(const char *);

void fix_size(int);

size_t b64_decode(const char *, unsigned char *);

unsigned char *b64_encode(const char *, size_t, unsigned char *);

const unsigned int BLOCK_SIZE = 1024;

}

#endif


