/*
 * This file is part of port shell crypter (psc).
 *
 * (C) 2006-2020 by Sebastian Krahmer,
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

#ifndef psc_pcwrap_h
#define psc_pcwrap_h

#include <sys/types.h>
#include <string.h>
#include <string>
#include <stdint.h>
#include <termios.h>
#include <unistd.h>
extern "C" {
#include <openssl/evp.h>
}

namespace ns_psc {

class pc_wrap {
private:

	int r_fd{-1}, w_fd{-1};
	bool seen_starttls{0};
	std::string err{""}, recent{""}, inq{""};
	bool server_mode{0};
	struct winsize ws;
	bool wsize_signalled{0};

	termios d_saved_rfd_tattr;
	EVP_CIPHER_CTX *r_ctx, *w_ctx;
	unsigned char w_key[EVP_MAX_KEY_LENGTH]{0}, r_key[EVP_MAX_KEY_LENGTH]{0};
	unsigned char iv[32]{0};

	std::string encrypt(const std::string &);

	std::string decrypt(const std::string &);

public:
	pc_wrap(int, int);

	int init(const std::string &, const std::string &, bool);

	int reset();

	~pc_wrap();

	int read(bool, std::string &, std::string &, int &);

	std::string possibly_b64encrypt(const std::string &, const std::string &);

	std::string wsize_cmd();

	int check_wsize(int);

	int r_fileno();

	int w_fileno();

	const char *why();

	int enable_crypto();

	bool is_crypted() { return seen_starttls; }

	char *get_iv() { return reinterpret_cast<char *>(iv); }
};

}

#endif

