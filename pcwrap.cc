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

#include <sys/types.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <memory>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <termios.h>
#include <sys/ioctl.h>

#include "pcwrap.h"
#include "cert.h"
#include "misc.h"
#include "bio.h"

extern "C" {
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
}

using namespace std;

namespace ns_psc {


pc_wrap::pc_wrap(const string &me, int rfd, int wfd)
	: d_rfd(rfd), d_wfd(wfd)
{
	d_me = me;

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();
}


int pc_wrap::init(const string &cert, const string &key, bool rem)
{
	d_is_remote = rem;

	if (!(d_bio_rfd = BIO_new_fd(d_rfd, BIO_NOCLOSE)))
		return build_error("init::BIO_new_fd", -1);
	if (!(d_bio_wfd = BIO_new_fd(d_wfd, BIO_NOCLOSE)))
		return build_error("init::BIO_new_fd", -1);

	if (!(d_rbio_b64 = BIO_new(ns_psc::BIO_f_b64())))
		return build_error("init::BIO_new", -1);
	if (!(d_wbio_b64 = BIO_new(ns_psc::BIO_f_b64())))
		return build_error("init::BIO_new", -1);

	BIO_push(d_rbio_b64, d_bio_rfd);
	BIO_push(d_wbio_b64, d_bio_wfd);

	if (d_is_remote) {
		if (!(d_ssl_method = TLS_client_method()))
			return build_error("init::SSLv23_client_method", -1);
	} else {
		if (!(d_ssl_method = TLS_server_method()))
			return build_error("init::SSLv23_server_method", -1);
	}

	if (!(d_ssl_ctx = SSL_CTX_new(d_ssl_method)))
		return build_error("init::SSL_CTX_new", -1);

	//  psc-remote is using the cert to check against what it gets from server
	if (cert.size()) {
		if (!d_is_remote) {
			if (SSL_CTX_use_certificate_file(d_ssl_ctx, cert.c_str(), SSL_FILETYPE_PEM) != 1)
				return build_error("init::SSL_CTX_use_certificate", -1);
		} else {
			FILE *f = fopen(cert.c_str(), "r");
			if (f)
				d_pinned_x509 = PEM_read_X509(f, nullptr, nullptr, nullptr);
			fclose(f);
		}
	}

	if (key.size()) {
		if (SSL_CTX_use_PrivateKey_file(d_ssl_ctx, key.c_str(), SSL_FILETYPE_PEM) != 1)
			return build_error("init::SSL_CTX_use_PrivateKey_file", -1);
		if (SSL_CTX_check_private_key(d_ssl_ctx) != 1)
			return build_error("init::SSL_CTX_check_private_key", -1);
	}

	long op = SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_1;
	op |= (SSL_OP_SINGLE_DH_USE|SSL_OP_SINGLE_ECDH_USE|SSL_OP_NO_TICKET);

	if ((unsigned long)(SSL_CTX_set_options(d_ssl_ctx, op) & op) != (unsigned long)op)
		return build_error("init::SSL_CTX_set_options", -1);

	if (d_ciphers.size() > 0 && SSL_CTX_set_cipher_list(d_ssl_ctx, d_ciphers.c_str()) != 1)
		return build_error("init::SSL_CTX_set_cipher_list", -1);

	// In case psc-remote wasnt given a PEM file on start,
	// it will use the built-in X509
	if (!d_pinned_x509 && sizeof(the_certificate) > 1) {
		const unsigned char *ptr = the_certificate;
		if (!d2i_X509(&d_pinned_x509, &ptr, sizeof(the_certificate)))
			d_pinned_x509 = nullptr;
	}

	return 0;
}


int pc_wrap::reset()
{
	SSL_free(d_ssl); d_ssl = nullptr;

	// freed via SSL_free()
	d_rbio_b64 = nullptr;
	d_wbio_b64 = nullptr;

	d_bio_rfd = nullptr;
	d_bio_wfd = nullptr;

	d_seen_starttls = 0;

	if (!(d_bio_rfd = BIO_new_fd(d_rfd, BIO_NOCLOSE)))
		return build_error("reset:BIO_new_fd", -1);
	if (!(d_bio_wfd = BIO_new_fd(d_wfd, BIO_NOCLOSE)))
		return build_error("reset:BIO_new_fd", -1);

	if (!(d_rbio_b64 = BIO_new(ns_psc::BIO_f_b64())))
		return build_error("reset:BIO_new", -1);
	if (!(d_wbio_b64 = BIO_new(ns_psc::BIO_f_b64())))
		return build_error("reset:BIO_new", -1);

	BIO_push(d_rbio_b64, d_bio_rfd);
	BIO_push(d_wbio_b64, d_bio_wfd);

	return 0;
}


pc_wrap::~pc_wrap()
{
	SSL_CTX_free(d_ssl_ctx);
	X509_free(d_pinned_x509);
}


int pc_wrap::check_wsize(int fd)
{
	if (!d_wsize_signalled)
		return 0;
	d_wsize_signalled = 0;
	int r = ioctl(fd, TIOCSWINSZ, &d_ws);
	if (r == 0)
		return 1;
	return r;
}



int pc_wrap::enable_crypto()
{
	int r = 0;

	if (!(d_ssl = SSL_new(d_ssl_ctx)))
		return build_error("enable_crypto::SSL_new", -1);

	SSL_set0_rbio(d_ssl, d_rbio_b64);
	SSL_set0_wbio(d_ssl, d_wbio_b64);

	do {
		r = SSL_connect(d_ssl);
		d_ssl_e = ERR_peek_error();
		switch (SSL_get_error(d_ssl, r)) {
		case SSL_ERROR_NONE:
			d_seen_starttls = 1;
			break;
		// not ready yet? try later
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			continue;
		default:
			return build_error("read::SSL_connect", -1);
		}
	} while (!d_seen_starttls);

	d_seen_starttls = 1;

	X509 *x509 = SSL_get_peer_certificate(d_ssl);
	if (!x509)
		return build_error("enable_crypto: No peer certificate!", -1);

	if (d_pinned_x509) {
		if (X509_cmp(x509, d_pinned_x509) != 0)
			return build_error("enable_crypto: Mismatch with pinned x509.", -1);
	}

	return 0;
}


int pc_wrap::read(char *buf, size_t blen)
{
	ssize_t r;

	if (d_seen_starttls) {
		retry: r = SSL_read(d_ssl, buf, blen);
		d_ssl_e = ERR_peek_error();
		switch (SSL_get_error(d_ssl, r)) {
		case SSL_ERROR_NONE:
			break;
		// not ready yet? try later
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			goto retry;
		default:
			return build_error("read::SSL_read", -1);
		}

		string s = string(buf, r);

		// normal data?
		if (s.find("D:channel0:") == 0) {
			memcpy(buf, s.c_str() + 11, s.size() - 11);
			return s.size() - 11;
		// some command
		} else if (s.find("C:window-size:") == 0) {
			d_wsize_signalled = 1;
			if (sscanf(s.c_str() + 14, "%hu:%hu:%hu:%hu", &d_ws.ws_row, &d_ws.ws_col,
			           &d_ws.ws_xpixel, &d_ws.ws_ypixel) != 4)
				d_wsize_signalled = 0;
		} else if (s.find("C:want-wsize:") == 0) {
			write_wsize();
		} else if (s.find("C:exit:") == 0) {
			// psc-remote is quitting, reset crypto state
			if (this->reset() < 0)
				return -1;
			printf("psc: Seen end-sequence, disabling crypto!\r\n");
		}

		return 0;
	}

	r = ::read(d_rfd, buf, 1);
	if (r <= 0)
		return build_error("read::read", -1);

	// as slow links read output one-bye-one or in small chunks, we need
	// to slide-match STARTTLS sequence
	d_recent += buf[0];
	string::size_type i = d_recent.find(d_starttls);
	if (i != string::npos && !d_is_remote) {
		if (i > 0 && i < blen)
			memcpy(buf, d_recent.c_str(), i);
		else
			i = 0;

		d_recent = "";
		printf("psc: Seen STARTTLS sequence, enabling crypto.\r\n");

		if (!(d_ssl = SSL_new(d_ssl_ctx)))
			return build_error("read::SSL_new", -1);
		SSL_set0_rbio(d_ssl, d_rbio_b64);
		SSL_set0_wbio(d_ssl, d_wbio_b64);

		// Disable local echo now, since remote site is
		// opening another PTY with echo
		struct termios tattr;
		if (tcgetattr(d_rfd, &tattr) == 0) {
			cfmakeraw(&tattr);
			tattr.c_cc[VMIN] = 1;
			tattr.c_cc[VTIME] = 0;
			tcsetattr(d_rfd, TCSANOW, &tattr);
		}

		d_seen_starttls = 0;

		do {
			r = SSL_accept(d_ssl);
			d_ssl_e = ERR_peek_error();
			switch (SSL_get_error(d_ssl, r)) {
			case SSL_ERROR_NONE:
				d_seen_starttls = 1;
				break;
			// not ready yet? try later
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				continue;
			default:
				return build_error("read::SSL_accept", -1);
			}
		} while (!d_seen_starttls);

		return i;
	}

	string::size_type nl = d_recent.find_last_of('\n');
	if (nl != string::npos && nl + 1 < d_recent.size())
		d_recent.erase(0, nl + 1);

	return r;
}


int pc_wrap::write_cmd(const char *buf)
{
	if (!d_seen_starttls)
		return 0;

	int r = 0;
	char cmd_buf[256] = {0};
	if (snprintf(cmd_buf, sizeof(cmd_buf) - 1, "C:%s:", buf) >= (int)sizeof(cmd_buf))
		return build_error("write_cmd: Too large buffer.", -1);

	// as we dont have SSL_MODE_ENABLE_PARTIAL_WRITES set,
	// this will write the entire buffer, i.e. it slurps away
	// blen bytes
	retry: r = SSL_write(d_ssl, cmd_buf, strlen(cmd_buf));
	d_ssl_e = ERR_peek_error();
	switch (SSL_get_error(d_ssl, r)) {
	case SSL_ERROR_NONE:
		break;
	// not ready yet? try later
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
		goto retry;
	default:
		return build_error("write_cmd::SSL_write", -1);
	}
	return 0;
}


int pc_wrap::write(const void *buf, size_t blen)
{
	int r = 0;

	if (blen > BLOCK_SIZE)
		return build_error("write: too large buffer!\n", -1);

	if (d_seen_starttls) {
		unique_ptr<char[]> cbuf(new (nothrow) char[blen + 128]);
		if (!cbuf.get())
			return build_error("write: OOM", -1);

		snprintf(cbuf.get(), 32, "D:channel0:");
		memcpy(cbuf.get() + 11, buf, blen);
		blen += 11;

		// as we dont have SSL_MODE_ENABLE_PARTIAL_WRITES set,
		// this will write the entire buffer, i.e. it slurps away
		// blen bytes
		retry: r = SSL_write(d_ssl, cbuf.get(), blen);
		d_ssl_e = ERR_peek_error();
		switch (SSL_get_error(d_ssl, r)) {
		case SSL_ERROR_NONE:
			break;
		// not ready yet? try later
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			goto retry;
		default:
			return build_error("write::SSL_write", -1);
		}

		return r;
	}

	r = ::write(d_wfd, buf, blen);
	return r;
}


int pc_wrap::write_wsize()
{
	if (!d_seen_starttls)
		return 0;

	char wsbuf[64] = {0};
	if (ioctl(0, TIOCGWINSZ, &d_ws) < 0)
		return -1;
	snprintf(wsbuf, sizeof(wsbuf), "window-size:%hu:%hu:%hu:%hu", d_ws.ws_row,
	         d_ws.ws_col, d_ws.ws_xpixel, d_ws.ws_ypixel);
	return write_cmd(wsbuf);
}


int pc_wrap::r_fileno()
{
	return d_rfd;
}


int pc_wrap::w_fileno()
{
	return d_wfd;
}


const char *pc_wrap::why()
{
	return d_err.c_str();
}

}

