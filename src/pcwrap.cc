/*
 * This file is part of port shell crypter (psc).
 *
 * (C) 2006-2023 by Sebastian Krahmer,
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

#include "external/aes.h"
#include "external/sha512.h"


using namespace std;

namespace ns_psc {


const string PSC_STARTTLS = START_BANNER;


pc_wrap::pc_wrap(int rfd, int wfd)
	: d_r_fd(rfd), d_w_fd(wfd)
{
	d_inq.reserve(16*BLOCK_SIZE);
	d_recent.reserve(4096);
}


static int kdf(const char *secret, int slen, unsigned char key[SHA512_SIZE])
{
	if (slen <= 0)
		return -1;
	memset(key, 0xff, SHA512_SIZE);

	sha512_context md_ctx;

	sha512_init(&md_ctx);
	sha512_update(&md_ctx, reinterpret_cast<const uint8_t *>(secret), slen);

	string vs = "v1";
	sha512_update(&md_ctx, reinterpret_cast<const uint8_t *>(vs.c_str()), vs.size());
	uint8_t *md = sha512_final(&md_ctx);

	memcpy(key, md, SHA512_SIZE);
	return 0;
}


int pc_wrap::init(const string &k1, const string &k2, bool s)
{
	d_server_mode = s;

	d_err = "pc_wrap::init: Initializing crypto CTX failed.";

	unsigned char tmp[16] = {0};
	if (RAND_bytes(tmp, sizeof(tmp)) != 1)
		return -1;

	b64_encode(reinterpret_cast<char *>(tmp), sizeof(tmp), d_iv);
	memset(d_iv + 16, 0, sizeof(d_iv) - 16);

	if (kdf(k1.c_str(), k1.size(), d_w_key) < 0)
		return -1;
	if (kdf(k2.c_str(), k2.size(), d_r_key) < 0)
		return -1;

	d_err = "";

	AES_init_ctx(&d_w_ctx, d_w_key);
	AES_init_ctx(&d_r_ctx, d_r_key);

	return 0;
}


int pc_wrap::reset()
{
	d_seen_starttls = 0;

	if (!d_server_mode)
		tcsetattr(d_r_fd, TCSANOW, &d_saved_rfd_tattr);

	d_err = "pc_wrap::reset: resetting crypto CTX failed.";

	unsigned char tmp[16] = {0};
	if (RAND_bytes(tmp, sizeof(tmp)) != 1)
		return -1;

	b64_encode(reinterpret_cast<char *>(tmp), sizeof(tmp), d_iv);

	d_err = "";

	AES_init_ctx(&d_w_ctx, d_w_key);
	AES_init_ctx(&d_r_ctx, d_r_key);

	return 0;
}


pc_wrap::~pc_wrap()
{
}


int pc_wrap::enable_crypto()
{
	AES_ctx_set_iv(&d_w_ctx, reinterpret_cast<uint8_t *>(d_iv));
	AES_ctx_set_iv(&d_r_ctx, reinterpret_cast<uint8_t *>(d_iv));

	d_seen_starttls = 1;

	return 0;
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


string pc_wrap::decrypt(const string &buf)
{
	string result = "";
	if (buf.size() <= 0 || buf.size() > 2*BLOCK_SIZE)
		return result;

	char obuf[2*BLOCK_SIZE] = {0};

	AES_CTR_xcrypt(&d_r_ctx, reinterpret_cast<const uint8_t *>(buf.c_str()), buf.size(), reinterpret_cast<uint8_t *>(obuf));

	result.assign(obuf, buf.size());
	return result;
}


string pc_wrap::encrypt(const string &buf)
{
	string result = "";
	if (buf.size() <= 0 || buf.size() > 2*BLOCK_SIZE)
		return result;

	char obuf[2*BLOCK_SIZE] = {0};

	AES_CTR_xcrypt(&d_w_ctx, reinterpret_cast<const uint8_t *>(buf.c_str()), buf.size(), reinterpret_cast<uint8_t *>(obuf));

	result.assign(obuf, buf.size());
	return result;
}


int pc_wrap::read(bool nosys, string &buf, string &ext_cmd, int &starttls)
{
	ssize_t r;
	char tbuf[2*BLOCK_SIZE] = {0};	// do not change buf-size w/o reflecting ::encrypt() and ::decrypt() limits
	string inbuf = "";

	buf.clear();
	ext_cmd.clear();
	starttls = 0;

	string::size_type idx1 = 0, idx2 = 0;

	// Do not call syscall if we just want to check for remaining data to avoid
	// blocking other pollfd's in the main loop by calling read() on the same fd
	// again and again for potentially mass of data pumped through
	if (!nosys) {
		if ((r = ::read(d_r_fd, tbuf, sizeof(tbuf))) <= 0) {
			d_err = "pc_wrap::read::";
			d_err += strerror(errno);
			return -1;
		}
		inbuf = string(tbuf, r);
		d_inq += inbuf;
	}

	if (d_seen_starttls) {

		if ((idx2 = d_inq.find(")")) == string::npos)
			return 0;
		if ((idx1 = d_inq.find("(")) == string::npos) {
			d_inq.clear();
			return 0;
		}

		// silently ignore too large chunks
		if (idx2 - idx1 > BLOCK_SIZE || idx2 < idx1) {
			d_inq.clear();
			return 0;
		}

		// when here, we have a valid b64 encoded crypted string. b64 decode will automatically
		// stop at closing `)` since its an invalid B64 char and so the target bufsize is large enough
		r = b64_decode(d_inq.c_str() + idx1 + 1, reinterpret_cast<unsigned char *>(tbuf));
		string s = decrypt(string(tbuf, r));

		d_inq.erase(0, idx2 + 1);

		// normal data?
		if (s.find("D:0:") == 0) {
			buf = s.substr(4);
		// window-size command
		} else if (s.find("C:WS:") == 0) {
			d_wsize_signalled = 1;
			if (sscanf(s.c_str() + 5, "%hu:%hu:%hu:%hu", &d_ws.ws_row, &d_ws.ws_col,
			           &d_ws.ws_xpixel, &d_ws.ws_ypixel) != 4)
				d_wsize_signalled = 0;
		} else if (s.find("C:exit:") == 0) {
			// if pscr is executed directly in pscl, there is a race of pscr vanishing with its
			// pty while we are trying to reset pty master to old state. Increase chances of pscr
			// finishing and pscl (us) resetting the right pty and not the pty of exiting pscr.
			usleep(50000);

			// psc-remote is quitting, reset crypto state
			if (this->reset() < 0)
				printf("\r\npscl: Seen end-sequence, but resetting crypto state failed! Continuing halfdead.\r\n");
			else
				printf("\r\npscl: Seen end-sequence, disabling crypto!\r\npscl: If tty is hangup, type 'reset'.\r\n");

		// any other command needs to be handled by external filter
		} else if (s.find("C:") == 0)
			ext_cmd = move(s);

		// more complete data blobs in the in queue?
		return d_inq.find(")") != string::npos;
	}

	d_recent += inbuf;

	// as slow links read output one-bye-one or in small chunks, we need
	// to slide-match STARTTLS sequence
	if (d_recent.size() >= PSC_STARTTLS.size() + 16 && (idx1 = d_recent.find(PSC_STARTTLS)) != string::npos) {
		memcpy(d_iv, d_recent.c_str() + idx1 + PSC_STARTTLS.size(), 16);

		d_recent.erase(0, idx1 + PSC_STARTTLS.size() + 16);

		AES_ctx_set_iv(&d_w_ctx, reinterpret_cast<uint8_t *>(d_iv));
		AES_ctx_set_iv(&d_r_ctx, reinterpret_cast<uint8_t *>(d_iv));

		printf("\r\npscl: Seen STARTTLS sequence, enabling crypto.\r\n");
		d_seen_starttls = 1;
		starttls = 1;
		if (!d_server_mode) {
			// Disable local echo now, since remote site is
			// opening another PTY with echo
			struct termios tattr;
			if (tcgetattr(d_r_fd, &tattr) == 0) {
				d_saved_rfd_tattr = tattr;
				cfmakeraw(&tattr);
				tattr.c_cc[VMIN] = 1;
				tattr.c_cc[VTIME] = 0;
				tcsetattr(d_r_fd, TCSANOW, &tattr);
			}
			// window size will be signalled in main loop() since we set starttls = 1
		}

		buf = d_inq;

		// the remaining bytes after STARTTLS tag
		d_inq = d_recent;

		// Everything after starttls sequence will be b64encrypted, so check whether there
		// is already an entire block read
		return d_inq.find(")") != string::npos;
	}

	string::size_type nl = d_recent.find_last_of('\n');
	if (nl != string::npos && nl + 1 < d_recent.size())
		d_recent.erase(0, nl + 1);

	buf = d_inq;
	d_inq.clear();
	return 0;
}


string pc_wrap::possibly_b64encrypt(const std::string &tag, const string &buf)
{
	string r = "";

	if (buf.size() > BLOCK_SIZE) {
		d_err = "pc_wrap::possibly_b64encrypt: bufsize too large";
		return r;
	}

	unsigned char *b64_crypt_buf = nullptr;

	if (d_seen_starttls) {
		string s = encrypt(tag + buf);
		b64_crypt_buf = new (nothrow) unsigned char[2*s.size()];
		if (!b64_crypt_buf)
			return r;
		memset(b64_crypt_buf, 0, 2*s.size());
		r = "(";
		r += b64_encode(s.c_str(), s.size(), b64_crypt_buf);
		r += ")";

		delete [] b64_crypt_buf;
		return r;
	}

	// if starttls not seen yet, just pass plain buf
	r = buf;
	return r;
}


string pc_wrap::wsize_cmd()
{
	if (!d_seen_starttls)
		return "";

	char wsbuf[64] = {0};
	if (ioctl(0, TIOCGWINSZ, &d_ws) < 0)
		return "";
	snprintf(wsbuf, sizeof(wsbuf), "WS:%hu:%hu:%hu:%hu", d_ws.ws_row,
	         d_ws.ws_col, d_ws.ws_xpixel, d_ws.ws_ypixel);
	return possibly_b64encrypt("C:", wsbuf);
}


int pc_wrap::r_fileno()
{
	return d_r_fd;
}


int pc_wrap::w_fileno()
{
	return d_w_fd;
}


const char *pc_wrap::why()
{
	return d_err.c_str();
}

}

