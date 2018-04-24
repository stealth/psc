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

#ifndef psc_pcwrap_h
#define psc_pcwrap_h

#include <sys/types.h>
#include <string.h>
#include <string>
#include <stdint.h>
#include <termios.h>
#include <unistd.h>
extern "C" {
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
}


namespace ns_psc {

class pc_wrap {
private:

	std::string d_ciphers{"!LOW:!EXP:!MD5:!CAMELLIA:!RC4:!MEDIUM:!DES:!ADH:!3DES:AES256:AESGCM:SHA256:SHA384:@STRENGTH"};
	int d_rfd{-1}, d_wfd{-1};
	bool d_seen_starttls{0}, d_was_ssl_error{0};
	std::string d_err{""}, d_recent{""}, d_starttls{STARTTLS}, d_me{""};
	bool d_is_remote{0};
	struct winsize d_ws;
	bool d_wsize_signalled{0};
	termios d_saved_rfd_tattr;

	SSL_CTX *d_ssl_ctx{nullptr};
	const SSL_METHOD *d_ssl_method{nullptr};
	SSL *d_ssl{nullptr};
	BIO *d_rbio_b64{nullptr}, *d_wbio_b64{nullptr}, *d_bio_wfd{nullptr}, *d_bio_rfd{nullptr};
	X509 *d_pinned_x509{nullptr};
	int d_ssl_e{0};

	template<class T>
	T build_error(const std::string &msg, T r)
	{
		unsigned long e = 0;

		d_was_ssl_error = 0;
		d_err = d_me + "::pcwrap::";
		d_err += msg;
		if ((e = ERR_get_error()) || d_ssl_e) {
			if (e == 0)
				e = d_ssl_e;
			d_err += ":";
			d_err += ERR_error_string(e, nullptr);
			ERR_clear_error();
			d_ssl_e = 0;
			d_was_ssl_error = 1;
		} else if (errno) {
			d_err += ":";
			d_err += strerror(errno);
		}
		errno = 0;
		return r;
	}



public:
	pc_wrap(const std::string&, int, int);

	int init(const std::string&, const std::string&, bool);

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

	bool is_crypted() { return d_seen_starttls; }

	bool ssl_error() { return d_was_ssl_error; }
};

}

#endif

