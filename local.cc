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
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>

#include "pty.h"
#include "pcwrap.h"
#include "misc.h"

using namespace std;
using namespace ns_psc;

pc_wrap *psc = nullptr;

struct termios global_tcattr, exit_tattr;

void sig_chld(int)
{
	tcsetattr(0, TCSANOW, &exit_tattr);
	printf("psc: exiting\n");
	exit(0);
}


void sig_int(int)
{
	if (!psc)
		return;

	if (psc->is_crypted())
		printf("\r\npsc: encryption enabled\r\n");
	else
		printf("\r\npsc: encryption disabled\r\n");
}


bool winsize_changed = 0;

void sig_win(int)
{
	winsize_changed = 1;
}


int main(int argc, char **argv)
{
#ifdef HAVE_UNIX98
	pty98 pt;
#else
	pty pt;
#endif
	fd_set rset;
	pid_t pid;
	int r;
	char wbuf[BLOCK_SIZE] = {0}, rbuf[2*BLOCK_SIZE] = {0};
	struct termios tattr;

	string keyfile = "./key.pem", certfile = "./cert.pem";

	if (argc > 1)
		keyfile = argv[1];
	if (argc > 2)
		certfile = argv[2];

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_chld;
	sa.sa_flags = SA_RESTART;

	if (sigaction(SIGCHLD, &sa, NULL) < 0)
		die("psc: sigaction");

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = sig_int;
	if (sigaction(SIGINT, &sa, NULL) < 0)
		die("psc: sigaction");

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_win;
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGWINCH, &sa, NULL) < 0)
		die("psc: sigaction");

	if (pt.open() < 0)
		die(pt.why());
	fix_size(pt.slave());

	if (tcgetattr(0, &tattr) < 0) {
		die("psc: tcgetattr");
	}

	exit_tattr = tattr;

	cfmakeraw(&tattr);
	tattr.c_cc[VMIN] = 1;
	tattr.c_cc[VTIME] = 0;
	tattr.c_lflag |= ISIG;

	//tattr.c_lflag &= ~ECHO;

	global_tcattr = tattr;
	if (tcsetattr(0, TCSANOW, &tattr) < 0)
		die("psc: tcsetattr");

	if ((pid = fork()) == 0) {
		char *a[] = {getenv("SHELL"), NULL};
		extern char **environ;

		if (!*a) {
			die("psc: no shell set via $SHELL");
		}

		close(0); close(1); close(2);
		dup2(pt.slave(), 0); dup2(pt.slave(), 1);
		dup2(pt.slave(), 2);
		setsid();
		ioctl(0, TIOCSCTTY, 0);
		pt.close();
		execve(*a, a, environ);
		die("psc: execve");
	} else if (pid < 0)
		die("psc: fork");

	psc = new (nothrow) pc_wrap("local", pt.master(), pt.master());
	if (!psc)
		die("new pc_wrap OOM");

	if (psc->init(certfile, keyfile, 0) < 0)
		die(psc->why());
	close(pt.slave());

	for (;;) {
		FD_ZERO(&rset);
		FD_SET(pt.master(), &rset);
		FD_SET(0, &rset);

		memset(wbuf, 0, sizeof(wbuf));
		memset(rbuf, 0, sizeof(rbuf));

		if (winsize_changed) {
			psc->write_wsize();
			winsize_changed = 0;
		}

		if (select(pt.master() + 1, &rset, NULL, NULL, NULL) < 0) {
			if (errno == EINTR)
				continue;
			else
				die("psc: select");
		}

		if (FD_ISSET(0, &rset)) {
			if ((r = read(0, wbuf, sizeof(wbuf))) <= 0) {
				if (errno == EINTR)
					continue;
				else
					die("psc: read");
			}
			if (psc->write(wbuf, r) <= 0) {
				if (errno == EINTR)
					continue;
				else {
					if (psc->ssl_error()) {
						fprintf(stderr, "%s\n", psc->why());
						if (psc->reset() < 0)
							die(psc->why());
						continue;
					}
					die(psc->why());
				}
			}
		} else if (FD_ISSET(pt.master(), &rset)) {
			if ((r = psc->read(rbuf, sizeof(rbuf))) < 0) {
				if (errno == EINTR)
					continue;
				else {
					// reset on SSL errors
					if (psc->ssl_error()) {
						fprintf(stderr, "%s\n", psc->why());
						if (psc->reset() < 0)
							die(psc->why());
						continue;
					}
					die(psc->why());
				}
			}
			// STARTTLS/end-sequence seen
			if (r == 0)
				continue;
			if (write(1, rbuf, r) <= 0) {
				if (errno == EINTR)
					continue;
				else
					die("psc: write");
			}
		}
	}

	return 0;
}

