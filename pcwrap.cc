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

#include <sys/types.h>
#include <cstdio>
#include <string.h>
#include <string>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <termios.h>
#include <sys/ioctl.h>

#include "pcwrap.h"
#include "misc.h"
#include "rc4.h"

#ifdef USE_SSL
#include <openssl/evp.h>
#endif

using namespace std;


pc_wrap::pc_wrap(int rfd, int wfd)
	: r_fd(rfd), w_fd(wfd), seen_starttls(0),
	  marker("*"), err(""), recent(""), starttls(STARTTLS), r_stream(NULL), w_stream(NULL),
	  server_mode(0), rc4_k1(NULL), rc4_k2(NULL), wsize_signalled(0)
{
	if ((r_stream = fdopen(r_fd, "r")) == NULL)
		die("pc_wrap::pc_wrap::fdopen(r)");
	if ((w_stream = fdopen(w_fd, "w")) == NULL)
		die("pc_wrap::pc_wrap::fdopen(w)");
	setbuffer(r_stream, NULL, 0);
	setbuffer(w_stream, NULL, 0);

#ifdef USE_SSL
	memset(w_key, 0, sizeof(w_key));
	memset(r_key, 0, sizeof(r_key));
	memset(w_iv, 'W', sizeof(w_iv));
	memset(r_iv, 'R', sizeof(r_iv));
#endif

	seq = 0;
}


int pc_wrap::init(unsigned char *k1, unsigned char *k2, bool s)
{
	tcgetattr(r_fd, &old_client_tattr);

	rc4_k1 = (unsigned char*)strdup((char*)k1);
	rc4_k2 = (unsigned char*)strdup((char*)k2);

	prepare_key(rc4_k1, strlen((char*)rc4_k1), &rc4_read_key);
	prepare_key(rc4_k2, strlen((char*)rc4_k2), &rc4_write_key);

	server_mode = s;

#ifdef USE_SSL
	err = "pc_wrap::init: Initializing crypto CTX failed.";

	r_ctx = (EVP_CIPHER_CTX *)new (nothrow) char[sizeof(EVP_CIPHER_CTX)];
	w_ctx = (EVP_CIPHER_CTX *)new (nothrow) char[sizeof(EVP_CIPHER_CTX)];
	if (!r_ctx || !w_ctx)
		return -1;

	EVP_CIPHER_CTX_init(r_ctx);
	EVP_CIPHER_CTX_init(w_ctx);

	if (EVP_EncryptInit(w_ctx, EVP_bf_ofb(), NULL, w_iv) != 1)
		return -1;
	if (EVP_DecryptInit(r_ctx, EVP_bf_ofb(), NULL, r_iv) != 1)
		return -1;

	if (EVP_CIPHER_CTX_set_key_length(r_ctx, strlen((char *)rc4_k1)) != 1)
		return -1;
	if (EVP_CIPHER_CTX_set_key_length(w_ctx, strlen((char *)rc4_k2)) != 1)
		return -1;

	if (EVP_EncryptInit(w_ctx, EVP_bf_ofb(), w_key, NULL) != 1)
		return -1;
	if (EVP_DecryptInit(r_ctx, EVP_bf_ofb(), r_key, NULL) != 1)
		return -1;
#endif
	return 0;
}


int pc_wrap::reset()
{
	seen_starttls = 0;

	// rc4 state machine reset
	prepare_key(rc4_k1, strlen((char*)rc4_k1), &rc4_read_key);
	prepare_key(rc4_k2, strlen((char*)rc4_k2), &rc4_write_key);

#ifdef USE_SSL

	err = "pc_wrap::reset: Resetting crypto CTX failed.";

	EVP_CIPHER_CTX_cleanup(r_ctx);
	EVP_CIPHER_CTX_cleanup(w_ctx);

	EVP_CIPHER_CTX_init(r_ctx);
	EVP_CIPHER_CTX_init(w_ctx);

	if (EVP_EncryptInit(w_ctx, EVP_bf_ofb(), NULL, w_iv) != 1)
		return -1;
	if (EVP_DecryptInit(r_ctx, EVP_bf_ofb(), NULL, r_iv) != 1)
		return -1;

	if (EVP_CIPHER_CTX_set_key_length(r_ctx, strlen((char *)rc4_k1)) != 1)
		return -1;
	if (EVP_CIPHER_CTX_set_key_length(w_ctx, strlen((char *)rc4_k2)) != 1)
		return -1;

	if (EVP_EncryptInit(w_ctx, EVP_bf_ofb(), w_key, NULL) != 1)
		return -1;
	if (EVP_DecryptInit(r_ctx, EVP_bf_ofb(), r_key, NULL) != 1)
		return -1;
#endif

	seq = 0;

	if (!server_mode)
		tcsetattr(r_fd, TCSANOW, &old_client_tattr);

	return 0;
}


pc_wrap::~pc_wrap()
{
	fclose(r_stream);
	fclose(w_stream);
	free(rc4_k1);
	free(rc4_k2);

#ifdef USE_SSL

	EVP_CIPHER_CTX_cleanup(r_ctx);
	EVP_CIPHER_CTX_cleanup(w_ctx);

	delete [] r_ctx;
	delete [] w_ctx;
#endif

}


int pc_wrap::check_wsize(int fd)
{
	if (!wsize_signalled)
		return 0;
	wsize_signalled = 0;
	int r = ioctl(fd, TIOCSWINSZ, &ws);
	if (r == 0)
		return 1;
	return r;
}


string pc_wrap::decrypt(char *buf, int len)
{
	string result = "";
	if (len <= 0)
		return result;
#ifndef USE_SSL
	rc4((unsigned char*)buf, len, &rc4_read_key);
	result.assign(buf, len);
#else
	int olen = 0;
	char *obuf = new (nothrow) char[2*len + EVP_MAX_BLOCK_LENGTH];
	if (!obuf)
		return result;
	EVP_DecryptUpdate(r_ctx, (unsigned char *)obuf, &olen, (unsigned char *)buf, len);
	result.assign(obuf, olen);
	delete [] obuf;
#endif
	++seq;
	return result;
}


string pc_wrap::encrypt(char *buf, int len)
{
	string result = "";
	if (len <= 0)
		return result;

#ifndef USE_SSL
	rc4((unsigned char*)buf, len, &rc4_write_key);
	result.assign(buf, len);
#else
	int olen = 0;
	char *obuf = new (nothrow) char[2*len + EVP_MAX_BLOCK_LENGTH];
	if (!obuf)
		return result;
	EVP_EncryptUpdate(w_ctx, (unsigned char *)obuf, &olen, (unsigned char *)buf, len);
	result.assign(obuf, olen);
	delete [] obuf;
#endif
	++seq;
	return result;
}


int pc_wrap::read(char *buf, size_t blen)
{
	ssize_t r;
	size_t ur;
	char b64_crypt_buf[2*BLOCK_SIZE], esc = 0;
	char *s = NULL;

	if (blen < 3*sizeof(b64_crypt_buf)/4 || blen < sizeof(esc)) {
		err = "pc_wrap::read: input buffer too small";
		return -1;
	}
	memset(b64_crypt_buf, 0, sizeof(b64_crypt_buf));

	if (seen_starttls) {
		// peek into stream to find potential ESC sequences
		if ((ur = fread(&esc, 1, 1, r_stream)) == 0) {
			err = "pc_wrap::read: invalid fread!\n";
			return -1;
		}

		// marker found?
		if (marker[0] == esc) {
			ungetc(esc, r_stream);
			fgets(b64_crypt_buf, sizeof(b64_crypt_buf), r_stream);
		} else {
			if (!server_mode)
				printf("psc: invalid character, ignoring\n");
			return 0;
		}

		// when here, we have a valid b64 encoded crypted string

		if ((s = strchr(b64_crypt_buf, '\n')) == NULL) {
			err = "pc_wrap::read: No newline in b64 rstream!";
			return -1;
		}

		*s = 0;
		char *tbuf = new (nothrow) char[sizeof(b64_crypt_buf)];
		if (!tbuf) {
			err = "pc_wrap::read: OOM";
			return -1;
		}
		memset(tbuf, 0, sizeof(b64_crypt_buf));
		r = b64_decode(b64_crypt_buf + marker.size(), (unsigned char*)tbuf);
		string s = decrypt(tbuf, r);
		delete [] tbuf;

		// normal data?
		if (s.find("D:channel0:") == 0) {
			memcpy(buf, s.c_str() + 11, s.size() - 11);
			return s.size() - 11;
		// some command
		} else if (s.find("C:window-size:") == 0) {
			wsize_signalled = 1;
			if (sscanf(s.c_str() + 14, "%hu:%hu:%hu:%hu", &ws.ws_row, &ws.ws_col,
			           &ws.ws_xpixel, &ws.ws_ypixel) != 4)
				wsize_signalled = 0;
		} else if (s.find("C:exit:") == 0) {
			// psc-remote is quitting, reset crypto state
			if (this->reset() < 0)
				return -1;
			printf("psc: Seen end-sequence, disabling crypto!\r\n");
			return 0;
		}

		return 0;
	}

	r = ::read(r_fd, buf, 1);
	if (r != 1) {
		err = "pc_wrap::read::";
		err += strerror(errno);
		return -1;
	}

	// as slow links read output one-bye-one or in small chunks, we need
	// to slide-match STARTTLS sequence
	recent += buf[0];
	string::size_type i = recent.find(starttls);
	if (i != string::npos) {
		fflush(r_stream);

		if (i > 0 && i < blen)
			memcpy(buf, recent.c_str(), i);
		else
			i = 0;

		recent = "";
		printf("psc: Seen STARTTLS sequence, enabling crypto.\r\n");
		seen_starttls = 1;
		if (!server_mode) {
			// Disable local echo now, since remote site is
			// opening another PTY with echo
			struct termios tattr;
			if (tcgetattr(r_fd, &tattr) == 0) {
				cfmakeraw(&tattr);
				tattr.c_cc[VMIN] = 1;
				tattr.c_cc[VTIME] = 0;
				tcsetattr(r_fd, TCSANOW, &tattr);
			}
			write_wsize();
		}
		return i;
	}

	string::size_type nl = recent.find_last_of('\n');
	if (nl != string::npos && nl + 1 < recent.size())
		recent = recent.substr(nl + 1);

	return r;
}


int pc_wrap::write_cmd(const char *buf)
{
	if (!seen_starttls)
		return 0;

	char cmd_buf[256];
	unsigned char cbuf[512];
	memset(cmd_buf, 0, sizeof(cmd_buf));
	memset(cbuf, 0, sizeof(cbuf));
	snprintf(cmd_buf, sizeof(cmd_buf), "C:%s:", buf);
	string s = encrypt(cmd_buf, strlen(cmd_buf));
	b64_encode(s.c_str(), s.size(), cbuf);
	fprintf(w_stream, "%s%s\n", marker.c_str(), cbuf);
	return 0;

}


int pc_wrap::write(const void *buf, size_t blen)
{
	int r = 0;

	if (blen > BLOCK_SIZE) {
		err = "pc_wrap::write: too large buffer!\n";
		return -1;
	}

	char *crypt_buf = NULL;
	unsigned char *b64_crypt_buf = NULL;

	if (seen_starttls) {
		crypt_buf = new (nothrow) char[blen + 32];
		if (!crypt_buf)
			return -1;

		snprintf(crypt_buf, 32, "D:channel0:");
		memcpy(crypt_buf + 11, buf, blen);
		blen += 11;
		string s = encrypt(crypt_buf, (int)blen);
		b64_crypt_buf = new (nothrow) unsigned char[2*s.size() + 64];
		if (!b64_crypt_buf)
			return -1;
		memset(b64_crypt_buf, 0, 2*s.size() + 64);
		b64_encode(s.c_str(), s.size(), b64_crypt_buf);
		fprintf(w_stream, "%s%s\n", marker.c_str(), b64_crypt_buf);

		delete [] crypt_buf;
		delete [] b64_crypt_buf;
		return blen - 11;
	}
	r = ::write(w_fd, buf, blen);
	return r;
}


int pc_wrap::write_wsize()
{
	if (!seen_starttls)
		return 0;

	char wsbuf[64];
	if (ioctl(0, TIOCGWINSZ, &ws) < 0)
		return -1;
	memset(wsbuf, 0, sizeof(wsbuf));
	snprintf(wsbuf, sizeof(wsbuf), "window-size:%hu:%hu:%hu:%hu", ws.ws_row,
	         ws.ws_col, ws.ws_xpixel, ws.ws_ypixel);
	return write_cmd(wsbuf);
}


int pc_wrap::r_fileno()
{
	return r_fd;
}


int pc_wrap::w_fileno()
{
	return w_fd;
}


const char *pc_wrap::why()
{
	return err.c_str();
}

