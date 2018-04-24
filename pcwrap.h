/*
 * This file is part of port shell crypter (psc).
 *
 * (C) 2006-2013 by Sebastian Krahmer,
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

/* Plain/crypted forwrad wrapper */

#ifndef __pcwrap_h__
#define __pcwrap_h__

#include <sys/types.h>
#include <string.h>
#include <string>
#include <stdint.h>
#include <termios.h>
#include <unistd.h>
extern "C" {
#include <openssl/evp.h>
}

class pc_wrap {
private:

	int r_fd, w_fd;
	bool seen_starttls{0};
	std::string err{""}, recent{""};
	bool server_mode{0};
	struct winsize ws;
	bool wsize_signalled{0};

	EVP_CIPHER_CTX *r_ctx, *w_ctx;
	unsigned char w_key[EVP_MAX_KEY_LENGTH], r_key[EVP_MAX_KEY_LENGTH];
	unsigned char iv[32];

	std::string encrypt(char *, int);

	std::string decrypt(char *, int);

public:
	pc_wrap(int, int);

	int init(const std::string &, const std::string &, bool);

	int reset();

	~pc_wrap();

	int read(char *, size_t);

	int write(const void *buf, size_t blen);

	int write_wsize();

	int write_cmd(const char *);

	int check_wsize(int);

	int r_fileno();

	int w_fileno();

	const char *why();

	int enable_crypto();

	bool is_crypted() { return seen_starttls; }

	char *get_iv() { return reinterpret_cast<char *>(iv); }
};


#endif

