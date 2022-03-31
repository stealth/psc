#ifndef _AES_H_
#define _AES_H_

#include <cstdint>

#define AES256 1

#define AES_BLOCKLEN 16		// Block length in bytes - AES is 128b block only

#if defined(AES256) && (AES256 == 1)
#define AES_KEYLEN 32
#define AES_keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
#define AES_KEYLEN 24
#define AES_keyExpSize 208
#else
#define AES_KEYLEN 16		// Key length in bytes
#define AES_keyExpSize 176
#endif

struct AES_ctx {
	uint8_t RoundKey[AES_keyExpSize]{0};
	struct {
		uint8_t iv[AES_BLOCKLEN]{0};
		//uint32_t ctr32{0};
	} iv;
	uint8_t xor_block[AES_BLOCKLEN]{0};
	uint8_t xidx{0};
};

void AES_init_ctx(struct AES_ctx *, const uint8_t *);

void AES_init_ctx_iv(struct AES_ctx *, const uint8_t *, const uint8_t *);

void AES_ctx_set_iv(struct AES_ctx *, const uint8_t *);

void AES_CTR_xcrypt(struct AES_ctx *, const uint8_t *, size_t, uint8_t *);


#endif // _AES_H_
