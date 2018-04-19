/*
 * This file is part of port shell crypter (psc).
 *
 * (C) 2006-2018 by Sebastian Krahmer,
 *                  sebastian [dot] krahmer [at] gmail [dot] com
 *
 * psc is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * psc is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with psc.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef psc_bio_h
#define psc_bio_h

extern "C" {
#include <openssl/bio.h>
}

namespace ns_psc {

typedef void (*bio_info_cb)(BIO *b, int oper, const char *ptr, int arg1, long arg2, long arg3);

struct bio_method_st {
	int type;
	const char *name;
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
	int (*bwrite) (BIO *, const char *, size_t, size_t *);
#endif
	int (*bwrite_old) (BIO *, const char *, int);
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
	int (*bread) (BIO *, char *, size_t, size_t *);
#endif
	int (*bread_old) (BIO *, char *, int);
	int (*bputs) (BIO *, const char *);
	int (*bgets) (BIO *, char *, int);
	long (*ctrl) (BIO *, int, long, void *);
	int (*create) (BIO *);
	int (*destroy) (BIO *);
	long (*callback_ctrl) (BIO *, int, bio_info_cb);
};

const BIO_METHOD *BIO_f_b64();

}

#endif

