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

#include <cstdint>
#include <cstring>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "sha512.h"

static inline uint64_t
get_u64(const uint8_t * p)
{
	uint32_t xh, xl;
	memcpy(&xh, p, 4);
	memcpy(&xl, p + 4, 4);
	return (((uint64_t) ntohl(xh)) << 32) | ntohl(xl);
}

static inline void
put_u64(uint8_t * p, uint64_t x)
{
	uint32_t xh, xl;
	xh = htonl(x >> 32);
	xl = htonl((uint32_t) x);
	memcpy(p, &xh, 4);
	memcpy(p + 4, &xl, 4);
}


// #define SHA512_UNROLLED

void
sha512_init(struct sha512_context *ctx)
{
	ctx->h0 = UINT64_C(0x6a09e667f3bcc908);
	ctx->h1 = UINT64_C(0xbb67ae8584caa73b);
	ctx->h2 = UINT64_C(0x3c6ef372fe94f82b);
	ctx->h3 = UINT64_C(0xa54ff53a5f1d36f1);
	ctx->h4 = UINT64_C(0x510e527fade682d1);
	ctx->h5 = UINT64_C(0x9b05688c2b3e6c1f);
	ctx->h6 = UINT64_C(0x1f83d9abfb41bd6b);
	ctx->h7 = UINT64_C(0x5be0cd19137e2179);

	ctx->nblocks = 0;
	ctx->count = 0;
}

static inline uint64_t
ROTR(uint64_t x, uint64_t n)
{
	return ((x >> n) | (x << (64 - n)));
}

static inline uint64_t
Ch(uint64_t x, uint64_t y, uint64_t z)
{
	return ((x & y) ^ (~x & z));
}

static inline uint64_t
Maj(uint64_t x, uint64_t y, uint64_t z)
{
	return ((x & y) ^ (x & z) ^ (y & z));
}

static inline uint64_t
sum0(uint64_t x)
{
	return (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39));
}

static inline uint64_t
sum1(uint64_t x)
{
	return (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41));
}

static const uint64_t k[] = {
	UINT64_C(0x428a2f98d728ae22), UINT64_C(0x7137449123ef65cd),
	UINT64_C(0xb5c0fbcfec4d3b2f), UINT64_C(0xe9b5dba58189dbbc),
	UINT64_C(0x3956c25bf348b538), UINT64_C(0x59f111f1b605d019),
	UINT64_C(0x923f82a4af194f9b), UINT64_C(0xab1c5ed5da6d8118),
	UINT64_C(0xd807aa98a3030242), UINT64_C(0x12835b0145706fbe),
	UINT64_C(0x243185be4ee4b28c), UINT64_C(0x550c7dc3d5ffb4e2),
	UINT64_C(0x72be5d74f27b896f), UINT64_C(0x80deb1fe3b1696b1),
	UINT64_C(0x9bdc06a725c71235), UINT64_C(0xc19bf174cf692694),
	UINT64_C(0xe49b69c19ef14ad2), UINT64_C(0xefbe4786384f25e3),
	UINT64_C(0x0fc19dc68b8cd5b5), UINT64_C(0x240ca1cc77ac9c65),
	UINT64_C(0x2de92c6f592b0275), UINT64_C(0x4a7484aa6ea6e483),
	UINT64_C(0x5cb0a9dcbd41fbd4), UINT64_C(0x76f988da831153b5),
	UINT64_C(0x983e5152ee66dfab), UINT64_C(0xa831c66d2db43210),
	UINT64_C(0xb00327c898fb213f), UINT64_C(0xbf597fc7beef0ee4),
	UINT64_C(0xc6e00bf33da88fc2), UINT64_C(0xd5a79147930aa725),
	UINT64_C(0x06ca6351e003826f), UINT64_C(0x142929670a0e6e70),
	UINT64_C(0x27b70a8546d22ffc), UINT64_C(0x2e1b21385c26c926),
	UINT64_C(0x4d2c6dfc5ac42aed), UINT64_C(0x53380d139d95b3df),
	UINT64_C(0x650a73548baf63de), UINT64_C(0x766a0abb3c77b2a8),
	UINT64_C(0x81c2c92e47edaee6), UINT64_C(0x92722c851482353b),
	UINT64_C(0xa2bfe8a14cf10364), UINT64_C(0xa81a664bbc423001),
	UINT64_C(0xc24b8b70d0f89791), UINT64_C(0xc76c51a30654be30),
	UINT64_C(0xd192e819d6ef5218), UINT64_C(0xd69906245565a910),
	UINT64_C(0xf40e35855771202a), UINT64_C(0x106aa07032bbd1b8),
	UINT64_C(0x19a4c116b8d2d0c8), UINT64_C(0x1e376c085141ab53),
	UINT64_C(0x2748774cdf8eeb99), UINT64_C(0x34b0bcb5e19b48a8),
	UINT64_C(0x391c0cb3c5c95a63), UINT64_C(0x4ed8aa4ae3418acb),
	UINT64_C(0x5b9cca4f7763e373), UINT64_C(0x682e6ff3d6b2b8a3),
	UINT64_C(0x748f82ee5defb2fc), UINT64_C(0x78a5636f43172f60),
	UINT64_C(0x84c87814a1f0ab72), UINT64_C(0x8cc702081a6439ec),
	UINT64_C(0x90befffa23631e28), UINT64_C(0xa4506cebde82bde9),
	UINT64_C(0xbef9a3f7b2c67915), UINT64_C(0xc67178f2e372532b),
	UINT64_C(0xca273eceea26619c), UINT64_C(0xd186b8c721c0c207),
	UINT64_C(0xeada7dd6cde0eb1e), UINT64_C(0xf57d4f7fee6ed178),
	UINT64_C(0x06f067aa72176fba), UINT64_C(0x0a637dc5a2c898a6),
	UINT64_C(0x113f9804bef90dae), UINT64_C(0x1b710b35131c471b),
	UINT64_C(0x28db77f523047d84), UINT64_C(0x32caab7b40c72493),
	UINT64_C(0x3c9ebe0a15c9bebc), UINT64_C(0x431d67c49c100d4c),
	UINT64_C(0x4cc5d4becb3e42b6), UINT64_C(0x597f299cfc657e2a),
	UINT64_C(0x5fcb6fab3ad6faec), UINT64_C(0x6c44198c4a475817)
};

/*
 * Transform the message W which consists of 16 64-bit-words
 */
static uint32_t
sha512_transform(struct sha512_context *ctx, const uint8_t * data)
{
	uint64_t a, b, c, d, e, f, g, h;
	uint64_t w[16];
	uint32_t t;

	/* get values from the chaining vars */
	a = ctx->h0;
	b = ctx->h1;
	c = ctx->h2;
	d = ctx->h3;
	e = ctx->h4;
	f = ctx->h5;
	g = ctx->h6;
	h = ctx->h7;

	for (t = 0; t < 16; t++)
		w[t] = get_u64(data + t * 8);

#define S0(x) (ROTR((x),1) ^ ROTR((x),8) ^ ((x)>>7))
#define S1(x) (ROTR((x),19) ^ ROTR((x),61) ^ ((x)>>6))

	for (t = 0; t < 80 - 16;) {
		uint64_t t1, t2;

		/* Performance on a AMD Athlon(tm) Dual Core Processor 4050e
		   with gcc 4.3.3 using gcry_md_hash_buffer of each 10000 uint8_ts
		   initialized to 0,1,2,3...255,0,... and 1000 iterations:

		   Not unrolled with macros:  440ms
		   Unrolled with macros:      350ms
		   Unrolled with inline:      330ms
		 */
#ifndef SHA512_UNROLLED
		t1 = h + sum1(e) + Ch(e, f, g) + k[t] + w[t % 16];
		w[t % 16] +=
			S1(w[(t - 2) % 16]) + w[(t - 7) % 16] +
			S0(w[(t - 15) % 16]);
		t2 = sum0(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
		t++;
#else /* Unrolled */
		t1 = h + sum1(e) + Ch(e, f, g) + k[t] + w[0];
		w[0] += S1(w[14]) + w[9] + S0(w[1]);
		t2 = sum0(a) + Maj(a, b, c);
		d += t1;
		h = t1 + t2;

		t1 = g + sum1(d) + Ch(d, e, f) + k[t + 1] + w[1];
		w[1] += S1(w[15]) + w[10] + S0(w[2]);
		t2 = sum0(h) + Maj(h, a, b);
		c += t1;
		g = t1 + t2;

		t1 = f + sum1(c) + Ch(c, d, e) + k[t + 2] + w[2];
		w[2] += S1(w[0]) + w[11] + S0(w[3]);
		t2 = sum0(g) + Maj(g, h, a);
		b += t1;
		f = t1 + t2;

		t1 = e + sum1(b) + Ch(b, c, d) + k[t + 3] + w[3];
		w[3] += S1(w[1]) + w[12] + S0(w[4]);
		t2 = sum0(f) + Maj(f, g, h);
		a += t1;
		e = t1 + t2;

		t1 = d + sum1(a) + Ch(a, b, c) + k[t + 4] + w[4];
		w[4] += S1(w[2]) + w[13] + S0(w[5]);
		t2 = sum0(e) + Maj(e, f, g);
		h += t1;
		d = t1 + t2;

		t1 = c + sum1(h) + Ch(h, a, b) + k[t + 5] + w[5];
		w[5] += S1(w[3]) + w[14] + S0(w[6]);
		t2 = sum0(d) + Maj(d, e, f);
		g += t1;
		c = t1 + t2;

		t1 = b + sum1(g) + Ch(g, h, a) + k[t + 6] + w[6];
		w[6] += S1(w[4]) + w[15] + S0(w[7]);
		t2 = sum0(c) + Maj(c, d, e);
		f += t1;
		b = t1 + t2;

		t1 = a + sum1(f) + Ch(f, g, h) + k[t + 7] + w[7];
		w[7] += S1(w[5]) + w[0] + S0(w[8]);
		t2 = sum0(b) + Maj(b, c, d);
		e += t1;
		a = t1 + t2;

		t1 = h + sum1(e) + Ch(e, f, g) + k[t + 8] + w[8];
		w[8] += S1(w[6]) + w[1] + S0(w[9]);
		t2 = sum0(a) + Maj(a, b, c);
		d += t1;
		h = t1 + t2;

		t1 = g + sum1(d) + Ch(d, e, f) + k[t + 9] + w[9];
		w[9] += S1(w[7]) + w[2] + S0(w[10]);
		t2 = sum0(h) + Maj(h, a, b);
		c += t1;
		g = t1 + t2;

		t1 = f + sum1(c) + Ch(c, d, e) + k[t + 10] + w[10];
		w[10] += S1(w[8]) + w[3] + S0(w[11]);
		t2 = sum0(g) + Maj(g, h, a);
		b += t1;
		f = t1 + t2;

		t1 = e + sum1(b) + Ch(b, c, d) + k[t + 11] + w[11];
		w[11] += S1(w[9]) + w[4] + S0(w[12]);
		t2 = sum0(f) + Maj(f, g, h);
		a += t1;
		e = t1 + t2;

		t1 = d + sum1(a) + Ch(a, b, c) + k[t + 12] + w[12];
		w[12] += S1(w[10]) + w[5] + S0(w[13]);
		t2 = sum0(e) + Maj(e, f, g);
		h += t1;
		d = t1 + t2;

		t1 = c + sum1(h) + Ch(h, a, b) + k[t + 13] + w[13];
		w[13] += S1(w[11]) + w[6] + S0(w[14]);
		t2 = sum0(d) + Maj(d, e, f);
		g += t1;
		c = t1 + t2;

		t1 = b + sum1(g) + Ch(g, h, a) + k[t + 14] + w[14];
		w[14] += S1(w[12]) + w[7] + S0(w[15]);
		t2 = sum0(c) + Maj(c, d, e);
		f += t1;
		b = t1 + t2;

		t1 = a + sum1(f) + Ch(f, g, h) + k[t + 15] + w[15];
		w[15] += S1(w[13]) + w[8] + S0(w[0]);
		t2 = sum0(b) + Maj(b, c, d);
		e += t1;
		a = t1 + t2;

		t += 16;
#endif
	}

	for (; t < 80;) {
		uint64_t t1, t2;

#ifndef SHA512_UNROLLED
		t1 = h + sum1(e) + Ch(e, f, g) + k[t] + w[t % 16];
		t2 = sum0(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
		t++;
#else /* Unrolled */
		t1 = h + sum1(e) + Ch(e, f, g) + k[t] + w[0];
		t2 = sum0(a) + Maj(a, b, c);
		d += t1;
		h = t1 + t2;

		t1 = g + sum1(d) + Ch(d, e, f) + k[t + 1] + w[1];
		t2 = sum0(h) + Maj(h, a, b);
		c += t1;
		g = t1 + t2;

		t1 = f + sum1(c) + Ch(c, d, e) + k[t + 2] + w[2];
		t2 = sum0(g) + Maj(g, h, a);
		b += t1;
		f = t1 + t2;

		t1 = e + sum1(b) + Ch(b, c, d) + k[t + 3] + w[3];
		t2 = sum0(f) + Maj(f, g, h);
		a += t1;
		e = t1 + t2;

		t1 = d + sum1(a) + Ch(a, b, c) + k[t + 4] + w[4];
		t2 = sum0(e) + Maj(e, f, g);
		h += t1;
		d = t1 + t2;

		t1 = c + sum1(h) + Ch(h, a, b) + k[t + 5] + w[5];
		t2 = sum0(d) + Maj(d, e, f);
		g += t1;
		c = t1 + t2;

		t1 = b + sum1(g) + Ch(g, h, a) + k[t + 6] + w[6];
		t2 = sum0(c) + Maj(c, d, e);
		f += t1;
		b = t1 + t2;

		t1 = a + sum1(f) + Ch(f, g, h) + k[t + 7] + w[7];
		t2 = sum0(b) + Maj(b, c, d);
		e += t1;
		a = t1 + t2;

		t1 = h + sum1(e) + Ch(e, f, g) + k[t + 8] + w[8];
		t2 = sum0(a) + Maj(a, b, c);
		d += t1;
		h = t1 + t2;

		t1 = g + sum1(d) + Ch(d, e, f) + k[t + 9] + w[9];
		t2 = sum0(h) + Maj(h, a, b);
		c += t1;
		g = t1 + t2;

		t1 = f + sum1(c) + Ch(c, d, e) + k[t + 10] + w[10];
		t2 = sum0(g) + Maj(g, h, a);
		b += t1;
		f = t1 + t2;

		t1 = e + sum1(b) + Ch(b, c, d) + k[t + 11] + w[11];
		t2 = sum0(f) + Maj(f, g, h);
		a += t1;
		e = t1 + t2;

		t1 = d + sum1(a) + Ch(a, b, c) + k[t + 12] + w[12];
		t2 = sum0(e) + Maj(e, f, g);
		h += t1;
		d = t1 + t2;

		t1 = c + sum1(h) + Ch(h, a, b) + k[t + 13] + w[13];
		t2 = sum0(d) + Maj(d, e, f);
		g += t1;
		c = t1 + t2;

		t1 = b + sum1(g) + Ch(g, h, a) + k[t + 14] + w[14];
		t2 = sum0(c) + Maj(c, d, e);
		f += t1;
		b = t1 + t2;

		t1 = a + sum1(f) + Ch(f, g, h) + k[t + 15] + w[15];
		t2 = sum0(b) + Maj(b, c, d);
		e += t1;
		a = t1 + t2;

		t += 16;
#endif
	}

	/* Update chaining vars.  */
	ctx->h0 += a;
	ctx->h1 += b;
	ctx->h2 += c;
	ctx->h3 += d;
	ctx->h4 += e;
	ctx->h5 += f;
	ctx->h6 += g;
	ctx->h7 += h;

	return /* burn_stack */ (8 + 16) * sizeof(uint64_t) + sizeof(uint32_t) +
		3 * sizeof(void *);
}

void
sha512_update(struct sha512_context *ctx, const uint8_t * buf, uint32_t len)
{

	if (ctx->count) {
		/* Fill rest of internal buffer */
		for (; len && ctx->count < SHA512_BLOCK_SIZE; len--)
			ctx->buf[ctx->count++] = *buf++;

		if (ctx->count < SHA512_BLOCK_SIZE)
			return;

		/* Process data from internal buffer */
		sha512_transform(ctx, ctx->buf);
		ctx->nblocks++;
		ctx->count = 0;
	}

	if (!len)
		return;

	/* Process data from input buffer */
	while (len >= SHA512_BLOCK_SIZE) {
		sha512_transform(ctx, buf);
		ctx->nblocks++;
		buf += SHA512_BLOCK_SIZE;
		len -= SHA512_BLOCK_SIZE;
	}

	/* Copy remaining data to internal buffer */
	memcpy(ctx->buf, buf, len);
	ctx->count = len;
}

/*
 * The routine final terminates the computation and returns the digest. The
 * handle is prepared for a new cycle, but adding uint8_ts to the handle will the
 * destroy the returned buffer.
 *
 * Returns: 64 uint8_ts representing the digest. When used for sha384, we take the
 * first 48 of those uint8_ts.
 */
uint8_t *
sha512_final(struct sha512_context *ctx)
{
	uint64_t t, th, msb, lsb;

	sha512_update(ctx, nullptr, 0);	/* flush */

	t = ctx->nblocks;
	th = 0;

	/* multiply by 128 to make a uint8_t count */
	lsb = t << 7;
	msb = (th << 7) | (t >> 57);
	/* add the count */
	t = lsb;
	if ((lsb += ctx->count) < t)
		msb++;
	/* multiply by 8 to make a bit count */
	t = lsb;
	lsb <<= 3;
	msb <<= 3;
	msb |= t >> 61;

	if (ctx->count < 112) {
		/* enough room */
		ctx->buf[ctx->count++] = 0x80;	/* pad */
		while (ctx->count < 112)
			ctx->buf[ctx->count++] = 0;	/* pad */
	} else {
		/* need one extra block */
		ctx->buf[ctx->count++] = 0x80;	/* pad character */
		while (ctx->count < 128)
			ctx->buf[ctx->count++] = 0;
		sha512_update(ctx, nullptr, 0);	/* flush */
		memset(ctx->buf, 0, 112);	/* fill next block with zeroes */
	}

	/* append the 128 bit count */
	put_u64(ctx->buf + 112, msb);
	put_u64(ctx->buf + 120, lsb);
	sha512_transform(ctx, ctx->buf);

	uint8_t *p = ctx->buf;
#define X(a) do { put_u64(p, ctx->h##a); p += 8; } while(0)
	X(0);
	X(1);
	X(2);
	X(3);
	X(4);
	X(5);
	X(6);
	X(7);
#undef X

	return ctx->buf;
}
