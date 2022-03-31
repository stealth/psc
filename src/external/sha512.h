/*
 *	BIRD Library -- SHA-512 and SHA-384 Hash Functions
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Based on the code from libgcrypt-1.6.0, which is
 *	(c) 2003, 2006, 2008, 2009 Free Software Foundation, Inc.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_SHA512_H_
#define _BIRD_SHA512_H_

#define SHA512_SIZE 		64
#define SHA512_HEX_SIZE		129
#define SHA512_BLOCK_SIZE	128

#include <cstdint>


struct sha512_context {
	uint64_t h0, h1, h2, h3, h4, h5, h6, h7;
	uint8_t buf[SHA512_BLOCK_SIZE];
	uint32_t nblocks;
	uint32_t count;
};


void sha512_init(struct sha512_context *);

void sha512_update(struct sha512_context *, const uint8_t *, uint32_t);

uint8_t *sha512_final(struct sha512_context *);


#endif /* _BIRD_SHA512_H_ */
