#ifndef psc_missing_h
#define psc_missing_h

extern "C" {
#include <openssl/crypto.h>
}


#if OPENSSL_VERSION_NUMBER > 0x10100000L && !(defined HAVE_LIBRESSL)

/* Idiots... Not just they are renaming EVP_MD_CTX_destroy() to EVP_MD_CTX_free() in OpenSSL >= 1.1,
 * they define EVP_MD_CTX_destroy(ctx) macro along (with braces) so we cant define the symbol
 * ourself. Forces me to introduce an entirely new name to stay compatible with older
 * versions and libressl.
 */
#define EVP_MD_CTX_delete EVP_MD_CTX_free
#else
#define EVP_MD_CTX_delete EVP_MD_CTX_destroy
#endif


#endif

