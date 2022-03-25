#ifndef psc_deleters_h
#define psc_deleters_h

extern "C" {
#include <openssl/evp.h>
}

#include <cstdio>

extern "C" typedef void (*EVP_MD_CTX_del)(EVP_MD_CTX *);

#endif
