/*
 * This file is part of port shell crypter (psc).
 *
 * (C) 2006-2021 by Sebastian Krahmer,
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

#include <cstdio>
#include <string>
#include <fcntl.h>
#include <signal.h>
#include <termios.h>
#include <cerrno>
#include <cstdlib>
#include <vector>
#include <unistd.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "net.h"
#include "pty.h"
#include "misc.h"
#include "pcwrap.h"


using namespace std;
using namespace ns_psc;

namespace ns_psc {

struct termios exit_tattr;
bool exit_attr_set = 0;

}

// child == bash exited, send end-sequence
// so psc-local can reset its crypto state
void sig_chld(int)
{
	// empty, just set to get an EINTR
}


int proxy_loop()
{
#ifdef HAVE_UNIX98
	pty98 pt;
#else
	pty pt;
#endif
	pid_t pid;
	int r, i;
	char sbuf[BLOCK_SIZE/2] = {0};	// 1 MTU
	struct termios tattr;

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

	if (sigaction(SIGCHLD, &sa, nullptr) < 0)
		die("pscr: sigaction");

	if ((pid = fork()) == 0) {
		char *a[] = {getenv("SHELL"), nullptr};
		extern char **environ;

		if (!*a) {
			die("pscr: No shell set via $SHELL");
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
		die("pscr: execve");
	} else if (pid < 0)
		die("pscr: fork");

	close(pt.slave());

	pc_wrap psc(0, 1);
	if (psc.init(PSC_READ_KEY, PSC_WRITE_KEY, 1) < 0)
		die(psc.why());

	printf("psc-2020-STARTTLS-%s", psc.get_iv());
	if (psc.enable_crypto() < 0)
		die(psc.why());

	struct rlimit rl;
	if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
		die("pscr: getrlimit");

	struct pollfd *pfds = new (nothrow) pollfd[rl.rlim_cur];
	struct state *fd2state = new (nothrow) state[rl.rlim_cur];

	fd2state[0].fd = 0;
	fd2state[0].state = STATE_STDIN;

	fd2state[1].fd = 1;
	fd2state[1].state = STATE_STDOUT;

	fd2state[pt.master()].fd = pt.master();
	fd2state[pt.master()].state = STATE_PTY;

	for (unsigned int i = 0; i < rl.rlim_cur; ++i) {
		pfds[i].fd = -1;
		pfds[i].events = pfds[i].revents = 0;
	}

	pfds[0].fd = 0;
	pfds[0].events = POLLIN;
	pfds[1].fd = 1;
	pfds[pt.master()].fd = pt.master();
	pfds[pt.master()].events = POLLIN;

	int max_fd = rl.rlim_cur - 1;

	bool breakout = 0;
	string ext_cmd = "", tbuf = "";

	do {
		memset(sbuf, 0, sizeof(sbuf));

		for (i = rl.rlim_cur - 1; i > 0; --i) {
			if (fd2state[i].state != STATE_INVALID && fd2state[i].fd != -1) {
				max_fd = i;
				break;
			}
		}

		if ((r = poll(pfds, max_fd + 1, 1000)) < 0) {
			if (errno == EINTR)
				continue;
			else
				break;
		}

		time_t now = time(nullptr);

		for (i = 0; i <= max_fd; ++i) {

			if (fd2state[i].state == STATE_INVALID)
				continue;

			if ((fd2state[i].state == STATE_CLOSING && (now - fd2state[i].time) > CLOSING_TIME) ||
			    (fd2state[i].state == STATE_UDPCLIENT && (now - fd2state[i].time) > UDP_CLOSING_TIME && fd2state[i].odgrams.empty())) {
				close(i);
				fd2state[i].fd = -1;
				fd2state[i].state = STATE_INVALID;
				fd2state[i].obuf.clear();
				pfds[i].fd = -1;
				pfds[i].events = 0;
				continue;
			}

			if (pfds[i].revents & (POLLERR|POLLHUP|POLLNVAL)) {
				if (fd2state[i].state == STATE_STDOUT || fd2state[i].state == STATE_PTY) {
					breakout = 1;
					break;
				}
				if (fd2state[i].state == STATE_CONNECTED || fd2state[i].state == STATE_CONNECT) {
					pfds[1].events |= POLLOUT;
					fd2state[1].obuf += psc.possibly_b64encrypt("C:T:F:", fd2state[i].rnode);     // signal finished connection to remote
					tcp_nodes2sock.erase(fd2state[i].rnode);
				}

				close(i);
				fd2state[i].fd = -1;
				fd2state[i].state = STATE_INVALID;
				fd2state[i].obuf.clear();
				pfds[i].fd = -1;
				pfds[i].events = 0;
				continue;
			}

			ext_cmd.clear();

			if (pfds[i].revents & POLLIN) {
				pfds[i].revents = 0;
				if (fd2state[i].state == STATE_PTY) {
					// read into small buf
					if ((r = read(pt.master(), sbuf, sizeof(sbuf))) <= 0) {
						breakout = 1;
						break;
					}
					fd2state[1].time = now;
					fd2state[1].obuf += psc.possibly_b64encrypt("D:0:", string(sbuf, r));
					pfds[1].events |= POLLOUT;

				} else if (fd2state[i].state == STATE_STDIN) {
					int starttls = 0, nosys = 0;
					do {
						tbuf = ext_cmd = "";
						if ((r = psc.read(nosys, tbuf, ext_cmd, starttls)) < 0) {
							breakout = 1;
							break;
						}
						nosys = 1;
						psc.check_wsize(pt.master());

						if (ext_cmd.size() > 0)
							cmd_handler(ext_cmd, fd2state, pfds, NETCMD_SEND_ALLOW);
						else if (tbuf.size() > 0) {
							fd2state[pt.master()].time = now;
							fd2state[pt.master()].obuf += tbuf;
							pfds[pt.master()].events |= POLLOUT;
						}
					} while (r == 1);

				} else if (fd2state[i].state == STATE_CONNECTED) {
					if ((r = recv(i, sbuf, sizeof(sbuf), 0)) <= 0) {
						close(i);
						pfds[i].fd = -1;
						pfds[i].events = 0;
						fd2state[i].state = STATE_INVALID;
						fd2state[i].fd = -1;
						fd2state[i].obuf.clear();
						tcp_nodes2sock.erase(fd2state[i].rnode);

						pfds[1].events |= POLLOUT;
						fd2state[1].obuf += psc.possibly_b64encrypt("C:T:F:", fd2state[i].rnode);	// signal finished connection via stdout to remote
						continue;
					}

					pfds[1].events |= POLLOUT;
					fd2state[1].obuf += psc.possibly_b64encrypt("C:T:R:", fd2state[i].rnode + string(sbuf, r));	// received TCP data
				} else if (fd2state[i].state == STATE_UDPCLIENT) {
					if ((r = recv(i, sbuf, sizeof(sbuf), 0)) <= 0)
						continue;

					pfds[1].events |= POLLOUT;
					fd2state[1].obuf += psc.possibly_b64encrypt("C:U:R:", fd2state[i].rnode + string(sbuf, r));	// received UDP data
				}
			} else if (pfds[i].revents & POLLOUT) {
				pfds[i].revents = 0;
				if (fd2state[i].state == STATE_PTY) {
					if ((r = write(pt.master(), fd2state[i].obuf.c_str(), fd2state[i].obuf.size())) <= 0) {
						breakout = 1;
						break;
					}

					fd2state[i].obuf.erase(0, r);
				} else if (fd2state[i].state == STATE_STDOUT) {
					if ((r = write(psc.w_fileno(), fd2state[i].obuf.c_str(), fd2state[i].obuf.size())) <= 0) {
						breakout = 1;
						break;
					}

					fd2state[i].obuf.erase(0, r);
				} else if (fd2state[i].state == STATE_CONNECT) {
					int e = 0;
					socklen_t elen = sizeof(e);
					if (getsockopt(i, SOL_SOCKET, SO_ERROR, &e, &elen) < 0 || e != 0) {
						close(i);
						pfds[i].fd = -1;
						pfds[i].events = 0;
						fd2state[i].state = STATE_INVALID;
						fd2state[i].fd = -1;
						fd2state[i].obuf.clear();
						tcp_nodes2sock.erase(fd2state[i].rnode);

						pfds[1].events |= POLLOUT;
						fd2state[1].obuf += psc.possibly_b64encrypt("C:T:F:", fd2state[i].rnode);	// signal finished connection via stdout to remote
						continue;
					}

					pfds[i].events = POLLIN;
					fd2state[i].state = STATE_CONNECTED;
					fd2state[i].time = now;

					pfds[1].events |= POLLOUT;
					fd2state[1].obuf += psc.possibly_b64encrypt("C:T:C:", fd2state[i].rnode);	// TCP connect() finished, connection is set up

				} else if (fd2state[i].state == STATE_CONNECTED) {
					if ((r = send(i, fd2state[i].obuf.c_str(), fd2state[i].obuf.size(), 0)) <= 0) {
						close(i);
						pfds[i].fd = -1;
						pfds[i].events = 0;
						fd2state[i].state = STATE_INVALID;
						fd2state[i].fd = -1;
						fd2state[i].obuf.clear();
						tcp_nodes2sock.erase(fd2state[i].rnode);

						pfds[1].events |= POLLOUT;
						fd2state[1].obuf += psc.possibly_b64encrypt("C:T:F:", fd2state[i].rnode);	// signal finished connection via stdout to remote
						continue;
					}

					fd2state[i].obuf.erase(0, r);
				} else if (fd2state[i].state == STATE_UDPCLIENT) {
					string &dgram = fd2state[i].odgrams.front();
					// No need to sendto(), each socket with ID is connect()'ed since -U binding already knows
					// the remote IP:port to send to
					if ((r = send(i, dgram.c_str(), dgram.size(), 0)) <= 0)
						continue;

					fd2state[i].odgrams.pop_front();
					fd2state[i].ulports.pop_front();	// unused in server part; yet filled in external cmd_handler()
				}

				if (fd2state[i].obuf.empty() && fd2state[i].odgrams.empty())
					pfds[i].events &= ~POLLOUT;
			}
		}
	} while (!breakout);

	if (exit_attr_set)
		tcsetattr(fileno(stdin), TCSANOW, &exit_tattr);

	string ex = psc.possibly_b64encrypt("C:", "exit:0");
	writen(psc.w_fileno(), ex.c_str(), ex.size());
	return 0;
}


int main(int argc, char **argv)
{
	setbuffer(stdin, nullptr, 0);
	setbuffer(stdout, nullptr, 0);
	setbuffer(stderr, nullptr, 0);

	printf("\nPortShellCrypter [pscr] v0.63 (C) 2006-2021 stealth -- github.com/stealth/psc\n\n");

	if (!getenv("SHELL")) {
		printf("pscr: No $SHELL set in environment. Exiting.\n");
		exit(1);
	}

	proxy_loop();

	return 0;
}

