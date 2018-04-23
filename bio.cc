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

#include <string>
#include <cstring>
#include "base64.h"
#include "bio.h"

extern "C" {
#include <openssl/bio.h>
}

using namespace std;

namespace ns_psc {


struct b64_ctx {
	string input{""};
};


int b64_write(BIO *b, const char *buf, int blen)
{
	string b64 = "";

	BIO *next = BIO_next(b);
	int n = blen > 1024 ? 1024 : blen, r = 0;
	string s = string(buf, n);
	b64_encode(s, b64);
	b64 += "\n";

	do {
		if ((r = BIO_write(next, b64.c_str(), b64.size())) <= 0)
			return r;
		b64.erase(0, r);
	} while (!b64.empty());

	return n;
}


int b64_read(BIO *b, char *buf, int blen)
{
	b64_ctx *ctx = reinterpret_cast<b64_ctx *>(BIO_get_data(b));
	if (!ctx)
		return -1;
	string &input = ctx->input;

	int n = 0;
	if (input.size() > 0) {
		n = blen > (int)input.size() ? input.size() : blen;
		memcpy(buf, input.c_str(), n);
		input.erase(0, n);
		return n;
	}

	BIO *next = BIO_next(b);

	char tmp[4096] = {0};
	int r = 0;
	string b64 = "";
	for (;;) {
		if ((r = BIO_gets(next, tmp, sizeof(tmp) - 1)) <= 0)
			return r;
		b64 += string(tmp, r);

		// If there was no \n (which isnt stored by BIO_gets())
		// in the buffer, slurp more.
		if (r < (int)sizeof(tmp) - 2)
			break;
	}
	b64_decode(b64, input);

	n = blen > (int)input.size() ? input.size() : blen;
	memcpy(buf, input.c_str(), n);
	input.erase(0, n);
	return n;
}


int b64_write_new(BIO *b, const char *data, size_t datal, size_t *written)
{
	int ret;

	if (datal > INT_MAX)
		datal = INT_MAX;

	ret = b64_write(b, data, (int)datal);

	if (ret <= 0) {
		*written = 0;
		return ret;
	}

	*written = (size_t)ret;
	return 1;
}


int b64_read_new(BIO *b, char *data, size_t datal, size_t *readbytes)
{
 	int ret;

	if (datal > INT_MAX)
        	datal = INT_MAX;

	ret = b64_read(b, data, (int)datal);

	if (ret <= 0) {
		*readbytes = 0;
		return ret;
	}

	*readbytes = (size_t)ret;

	return 1;
}


long b64_ctrl(BIO *b, int cmd, long num, void *ptr)
{
	BIO *next = BIO_next(b);
	b64_ctx *ctx = reinterpret_cast<b64_ctx *>(BIO_get_data(b));

	switch (cmd) {
	case BIO_CTRL_RESET:
	case BIO_CTRL_FLUSH:
		ctx->input.clear();
		break;
	case BIO_CTRL_PENDING:
		if (!ctx->input.empty())
			return 1;
	default:
		break;
	}

	return BIO_ctrl(next, cmd, num, ptr);
}


int b64_create(BIO *b)
{
	b64_ctx *ctx = new (nothrow) b64_ctx;
	if (!ctx)
		return 0;
	BIO_set_data(b, ctx);
	BIO_set_init(b, 1);
	return 1;
}


int b64_destroy(BIO *b)
{
	delete reinterpret_cast<b64_ctx *>(BIO_get_data(b));
	BIO_set_data(b, nullptr);
	BIO_set_init(b, 0);
	return 1;
}


long b64_callback_ctrl(BIO *b, int cmd, bio_info_cb cb)
{
	BIO *next = BIO_next(b);
	return BIO_callback_ctrl(next, cmd, cb);
}


static bio_method_st biom_b64 = {
	0x743c7350,
	"psc BIO b64",
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
	b64_write_new,
#endif
	b64_write,
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
	b64_read_new,
#endif
	b64_read,
	nullptr,
	nullptr,
	b64_ctrl,
	b64_create,
	b64_destroy,
	b64_callback_ctrl
};


const BIO_METHOD *BIO_f_b64()
{
	return reinterpret_cast<const BIO_METHOD *>(&biom_b64);
}

}

