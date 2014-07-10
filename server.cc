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
#include <termios.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "pty.h"
#include "misc.h"
#include "pcwrap.h"

struct termios exit_tattr;
bool exit_attr_set = 0;

// child == bash exited, send end-sequence
// so psc-local can reset its crypto state
void sig_chld(int)
{
	// empty, just set to get an EINTR
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
	char wbuf[BLOCK_SIZE], rbuf[2*BLOCK_SIZE];
	struct termios tattr;
	const char *starttls = STARTTLS;
	unsigned char *rkey = (unsigned char*)PSC_WRITE_KEY;
	unsigned char *wkey = (unsigned char*)PSC_READ_KEY;

	setbuffer(stdin, NULL, 0);
	setbuffer(stdout, NULL, 0);
	setbuffer(stderr, NULL, 0);

	if (pt.open() < 0)
		die(pt.why());

	fix_size(pt.slave());

	if (tcgetattr(fileno(stdin), &tattr) >= 0) {
		exit_tattr = tattr;

		//tattr.c_lflag &= ~ECHO;
		cfmakeraw(&tattr);

		/* May fails when we are on a portshell */
		tcsetattr(fileno(stdin), TCSANOW, &tattr);
		exit_attr_set = 1;
	}

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_chld;
	sa.sa_flags = SA_RESTART;

	if (sigaction(SIGCHLD, &sa, NULL) < 0)
		die("sigaction");

	if ((pid = fork()) == 0) {
		char *a[] = {getenv("SHELL"), NULL};
		extern char **environ;

		if (!*a) {
			die("No shell set via $SHELL");
		}

		// someone is using it as login-shell?
		if (strstr(a[0], "psc"))
			a[0] = strdup("/bin/sh");

		dup2(pt.slave(), 0); dup2(pt.slave(), 1);
		dup2(pt.slave(), 2);
		setsid();
		ioctl(0, TIOCSCTTY, 0);
		pt.close();

		execve(*a, a, environ);
		die("execve");
	} else if (pid < 0)
		die("fork");

	close(pt.slave());

	printf("%s", starttls);

	pc_wrap psc(0, 1);
	if (psc.init(rkey, wkey, 1) < 0)
		die(psc.why());
	psc.enable_crypto();

	for (;;) {
		FD_ZERO(&rset);
		FD_SET(pt.master(), &rset);
		FD_SET(0, &rset);
		memset(rbuf, 0, sizeof(rbuf));
		memset(wbuf, 0, sizeof(wbuf));

		if (select(pt.master() + 1, &rset, NULL, NULL, NULL) < 0) {
			if (errno == EINTR)
				continue;
			else {
				break;
			}
		}
		if (FD_ISSET(0, &rset)) {
			if ((r = psc.read(rbuf, sizeof(rbuf))) < 0)
				break;
			// STARTTLS/command seen
			if (r == 0) {
				psc.check_wsize(pt.master());
				continue;
			}
			if (write(pt.master(), rbuf, r) <= 0) {
				break;
			}
		} else if (FD_ISSET(pt.master(), &rset)) {
			if ((r = read(pt.master(), wbuf, sizeof(wbuf))) <= 0) {
				break;
			}
			if (psc.write(wbuf, r) <= 0)
				break;
		}
	}

	if (exit_attr_set)
		tcsetattr(fileno(stdin), TCSANOW, &exit_tattr);

	psc.write_cmd("exit");
	return 0;
}

