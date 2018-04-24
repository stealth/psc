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
#include <string.h>
#include <string>
#include <memory>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <sys/ioctl.h>

#include "pcwrap.h"
#include "misc.h"
#include "deleters.h"
#include "missing.h"

extern "C" {
#include <openssl/evp.h>
#include <openssl/rand.h>
}

using namespace std;


pc_wrap::pc_wrap(int rfd, int wfd)
	: r_fd(rfd), w_fd(wfd)
{
	memset(w_key, 0, sizeof(w_key));
	memset(r_key, 0, sizeof(r_key));
	memset(iv, 0, sizeof(iv));
}


static int kdf(const char *secret, int slen, unsigned char key[EVP_MAX_KEY_LENGTH])
{
	unsigned int hlen = 0;
	unsigned char digest[EVP_MAX_MD_SIZE];	// 64 which matches sha512

	if (slen <= 0)
		return -1;
	memset(key, 0xff, EVP_MAX_KEY_LENGTH);

	unique_ptr<EVP_MD_CTX, EVP_MD_CTX_del> md_ctx(EVP_MD_CTX_create(), EVP_MD_CTX_delete);
	if (!md_ctx.get())
		return -1;
	if (EVP_DigestInit_ex(md_ctx.get(), EVP_sha512(), nullptr) != 1)
		return -1;
	if (EVP_DigestUpdate(md_ctx.get(), reinterpret_cast<const void *>(secret), slen) != 1)
		return -1;

	string vs = "v1";
	if (EVP_DigestUpdate(md_ctx.get(), vs.c_str(), vs.size()) != 1)
		return -1;

	if (EVP_DigestFinal_ex(md_ctx.get(), digest, &hlen) != 1)
		return -1;

	if (hlen > EVP_MAX_KEY_LENGTH)
		hlen = EVP_MAX_KEY_LENGTH;
	memcpy(key, digest, hlen);
	return 0;
}


int pc_wrap::init(const string &k1, const string &k2, bool s)
{
	server_mode = s;

	err = "pc_wrap::init: Initializing crypto CTX failed.";

	RAND_load_file("/dev/urandom", 128);

	unsigned char tmp[16] = {0};
	RAND_bytes(tmp, sizeof(tmp));
	b64_encode(reinterpret_cast<char *>(tmp), sizeof(tmp), iv);
	memset(iv + 16, 0, sizeof(iv) - 16);

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	r_ctx = new (nothrow) EVP_CIPHER_CTX;
	w_ctx = new (nothrow) EVP_CIPHER_CTX;
	if (!r_ctx || !w_ctx)
		return -1;

	EVP_CIPHER_CTX_init(r_ctx);
	EVP_CIPHER_CTX_init(w_ctx);
#else
	r_ctx = EVP_CIPHER_CTX_new();
	w_ctx = EVP_CIPHER_CTX_new();
	if (!r_ctx || !w_ctx)
		return -1;
#endif

	if (kdf(k1.c_str(), k1.size(), w_key) < 0)
		return -1;
	if (kdf(k2.c_str(), k2.size(), r_key) < 0)
		return -1;

	// must be a stream cipher, so we are not bound by block sizes
	if (EVP_EncryptInit_ex(w_ctx, EVP_aes_256_ctr(), nullptr, w_key, nullptr) != 1)
		return -1;
	if (EVP_DecryptInit_ex(r_ctx, EVP_aes_256_ctr(), nullptr, r_key, nullptr) != 1)
		return -1;

	return 0;
}


int pc_wrap::reset()
{
	seen_starttls = 0;

	err = "pc_wrap::reset: Resetting crypto CTX failed.";

	unsigned char tmp[16] = {0};
	RAND_bytes(tmp, sizeof(tmp));
	b64_encode(reinterpret_cast<char *>(tmp), sizeof(tmp), iv);

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	EVP_CIPHER_CTX_cleanup(r_ctx);
	EVP_CIPHER_CTX_cleanup(w_ctx);

	EVP_CIPHER_CTX_init(r_ctx);
	EVP_CIPHER_CTX_init(w_ctx);
#else

	EVP_CIPHER_CTX_reset(r_ctx);
	EVP_CIPHER_CTX_reset(w_ctx);
#endif

	if (EVP_EncryptInit_ex(w_ctx, EVP_aes_256_ctr(), nullptr, w_key, nullptr) != 1)
		return -1;
	if (EVP_DecryptInit_ex(r_ctx, EVP_aes_256_ctr(), nullptr, r_key, nullptr) != 1)
		return -1;

	return 0;
}


pc_wrap::~pc_wrap()
{

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	EVP_CIPHER_CTX_cleanup(r_ctx);
	EVP_CIPHER_CTX_cleanup(w_ctx);

	delete r_ctx;
	delete w_ctx;
#else
	EVP_CIPHER_CTX_free(r_ctx);
	EVP_CIPHER_CTX_free(w_ctx);

#endif

}


int pc_wrap::enable_crypto()
{
	if (EVP_EncryptInit_ex(w_ctx, nullptr, nullptr, nullptr, iv) != 1) {
		err = "pc_wrap::enable_crypto: EncryptInit failed.";
		return -1;
	}
	if (EVP_DecryptInit_ex(r_ctx, nullptr, nullptr, nullptr, iv) != 1) {
		err = "pc_wrap::enable_crypto: DecryptInit failed.";
		return -1;
	}

	seen_starttls = 1;

	return 0;
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

	int olen = 0;
	char *obuf = new (nothrow) char[2*len + EVP_MAX_BLOCK_LENGTH];
	if (!obuf)
		return result;
	EVP_DecryptUpdate(r_ctx, (unsigned char *)obuf, &olen, (unsigned char *)buf, len);
	result.assign(obuf, olen);
	delete [] obuf;

	return result;
}


string pc_wrap::encrypt(char *buf, int len)
{
	string result = "";
	if (len <= 0)
		return result;

	int olen = 0;
	char *obuf = new (nothrow) char[2*len + EVP_MAX_BLOCK_LENGTH];
	if (!obuf)
		return result;
	EVP_EncryptUpdate(w_ctx, (unsigned char *)obuf, &olen, (unsigned char *)buf, len);
	result.assign(obuf, olen);
	delete [] obuf;

	return result;
}


int pc_wrap::read(char *buf, size_t blen)
{
	ssize_t r;
	char b64_crypt_buf[2*BLOCK_SIZE] = {0}, tbuf[2*BLOCK_SIZE] = {0};
	bool found_nl = 0;

	if (seen_starttls) {
		for (unsigned int i = 0; i < sizeof(b64_crypt_buf); ++i) {
			if (::read(r_fd, b64_crypt_buf + i, 1) <= 0)
				return -1;
			if (b64_crypt_buf[i] == '\n') {
				b64_crypt_buf[i] = 0;
				found_nl = 1;
				break;
			}
		}
		if (!found_nl) {
			err = "pc_wrap::read: No NL found.";
			return -1;
		}

		// when here, we have a valid b64 encoded crypted string
		r = b64_decode(b64_crypt_buf, (unsigned char*)tbuf);
		string s = decrypt(tbuf, r);

		if (s.size() > blen) {
			err = "pc_wrap::read: input buffer too small";
			return -1;
		}

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
	if (recent.size() == 18 + 16 && recent.find("psc-2018-STARTTLS-") == 0) {
		memcpy(iv, recent.c_str() + 18, 16);
		recent.clear();

		if (EVP_EncryptInit_ex(w_ctx, nullptr, nullptr, nullptr, iv) != 1) {
			err = "pc_wrap::read: EVP_EncryptInit failed.";
			return -1;
		}
		if (EVP_DecryptInit_ex(r_ctx, nullptr, nullptr, nullptr, iv) != 1) {
			err = "pc_wrap::read: EVP_DecryptInit failed.";
			return -1;
		}

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
		return 0;
	}

	string::size_type nl = recent.find_last_of('\n');
	if (nl != string::npos && nl + 1 < recent.size())
		recent.erase(0, nl + 1);

	return r;
}


static int writen(int fd, const char *buf, size_t blen)
{
	ssize_t r;
	size_t n = blen;

	for (int i = 0; n > 0;) {
		if ((r = write(fd, buf + i, n)) <= 0)
			return r;
		i += r;
		n -= r;
	}
	return (int)blen;
}


int pc_wrap::write_cmd(const char *buf)
{
	if (!seen_starttls)
		return 0;

	char cmd_buf[256] = {0};
	unsigned char cbuf[512] = {0};
	snprintf(cmd_buf, sizeof(cmd_buf) - 1, "C:%s:", buf);
	string s = encrypt(cmd_buf, strlen(cmd_buf));
	string b64 = b64_encode(s.c_str(), s.size(), cbuf);
	b64 += "\n";
	return writen(w_fd, b64.c_str(), b64.size());
}


int pc_wrap::write(const void *buf, size_t blen)
{
	int r = 0;

	if (blen > BLOCK_SIZE) {
		err = "pc_wrap::write: too large buffer!\n";
		return -1;
	}

	char *crypt_buf = nullptr;
	unsigned char *b64_crypt_buf = nullptr;

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
		string b64 = b64_encode(s.c_str(), s.size(), b64_crypt_buf);
		b64 += "\n";
		writen(w_fd, b64.c_str(), b64.size());

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

	char wsbuf[64] = {0};
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

