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


#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <signal.h>
#include <termios.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "net.h"
#include "pty.h"
#include "pcwrap.h"
#include "misc.h"


using namespace std;
using namespace ns_psc;

namespace ns_psc {

pc_wrap *psc = nullptr;

struct termios global_tcattr, exit_tattr;

}

void sig_chld(int)
{
	tcsetattr(0, TCSANOW, &exit_tattr);
	printf("pscl: exiting\n");
	exit(0);
}


void sig_int(int)
{
	if (!psc)
		return;

	if (psc->is_crypted())
		printf("\r\npscl: encryption enabled\r\n");
	else
		printf("\r\npscl: encryption disabled\r\n");
}


bool winsize_changed = 0;

void sig_win(int)
{
	winsize_changed = 1;
}


int proxy_loop()
{

#ifdef HAVE_UNIX98
	pty98 pt;
#else
	pty pt;
#endif
	pid_t pid;
	int r, afd = -1, i;

	char sbuf[BLOCK_SIZE/2] = {0};	// 1 MTU
	struct termios tattr;

	if (pt.open() < 0)
		die(pt.why());
	fix_size(pt.slave());

	if (tcgetattr(0, &tattr) < 0)
		die("pscl: tcgetattr");

	exit_tattr = tattr;

	cfmakeraw(&tattr);
	tattr.c_cc[VMIN] = 1;
	tattr.c_cc[VTIME] = 0;
	tattr.c_lflag |= ISIG;

	//tattr.c_lflag &= ~ECHO;

	global_tcattr = tattr;
	if (tcsetattr(0, TCSANOW, &tattr) < 0)
		die("pscl: tcsetattr");

	if ((pid = fork()) == 0) {
		char *a[] = {getenv("SHELL"), NULL};
		extern char **environ;

		if (!*a) {
			die("pscl: no shell set via $SHELL");
		}

		close(0); close(1); close(2);
		dup2(pt.slave(), 0); dup2(pt.slave(), 1);
		dup2(pt.slave(), 2);
		setsid();
		ioctl(0, TIOCSCTTY, 0);
		pt.close();
		execve(*a, a, environ);
		die("pscl: execve");
	} else if (pid < 0)
		die("pscl: fork");

	psc = new (nothrow) pc_wrap(pt.master(), pt.master());
	if (!psc)
		die("new pc_wrap OOM");

	if (psc->init(PSC_WRITE_KEY, PSC_READ_KEY, 0) < 0)
		die(psc->why());
	close(pt.slave());

	struct rlimit rl;
	if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
		die("getrlimit");

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

	for (auto it = config::tcp_listens.begin(); it != config::tcp_listens.end(); ++it) {
		if ((r = tcp_listen("127.0.0.1", it->first)) < 0)
			continue;
		pfds[r].fd = r;
		pfds[r].events = POLLIN;

		fd2state[r].fd = r;
		fd2state[r].rnode = it->second;
		fd2state[r].state = STATE_ACCEPT;
	}

	for (auto it = config::udp_listens.begin(); it != config::udp_listens.end(); ++it) {
		if ((r = udp_listen("127.0.0.1", it->first)) < 0)
			continue;
		pfds[r].fd = r;
		pfds[r].events = POLLIN;

		fd2state[r].fd = r;
		fd2state[r].rnode = it->second;
		fd2state[r].state = STATE_UDPSERVER;
	}

	// Build a local address for sending reply UDP dgrams. Only the dst port is unknown yet
	// and will be constructed from the ID part of the IP/port/ID header
	struct sockaddr_in lsin;
	lsin.sin_family = AF_INET;
	inet_pton(AF_INET, "127.0.0.1", &lsin.sin_addr);

	int max_fd = rl.rlim_cur - 1;

	string ext_cmd = "", tbuf = "";

	for (;;) {

		memset(sbuf, 0, sizeof(sbuf));

		if (winsize_changed) {
			fd2state[pt.master()].obuf += psc->wsize_cmd();
			pfds[pt.master()].events |= POLLOUT;
			winsize_changed = 0;
		}

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
				die("pscl: poll");
		}

		time_t now = time(nullptr);

		for (i = 0; i <= max_fd; ++i) {

			if (fd2state[i].state == STATE_INVALID)
				continue;

			if ((fd2state[i].state == STATE_CLOSING && (now - fd2state[i].time) > CLOSING_TIME) ||
			    (fd2state[i].state == STATE_CONNECT && (now - fd2state[i].time) > CONNECT_TIME)) {
				close(i);
				fd2state[i].fd = -1;
				fd2state[i].state = STATE_INVALID;
				pfds[i].fd = -1;
				continue;
			}

			if (pfds[i].revents & (POLLERR|POLLHUP)) {
				if (fd2state[i].state == STATE_STDIN || fd2state[i].state == STATE_PTY)
					die("pscl: TTY hangup");
				close(i);
				fd2state[i].fd = -1;
				fd2state[i].state = STATE_INVALID;
				fd2state[i].obuf.clear();
				pfds[i].fd = -1;
				pfds[i].events = 0;
				continue;
			}

			errno = 0;
			ext_cmd.clear();

			if (pfds[i].revents & POLLIN) {
				pfds[i].revents = 0;
				if (fd2state[i].state == STATE_STDIN) {
					if ((r = read(0, sbuf, sizeof(sbuf))) <= 0) {
						if (errno == EINTR)
							continue;
						else
							die("pscl: read");
					}
					fd2state[pt.master()].obuf += psc->possibly_b64encrypt("D:0:", string(sbuf, r));
					pfds[pt.master()].events |= POLLOUT;

				} else if (fd2state[i].state == STATE_PTY) {
					int starttls = 0;
					bool nosys = 0;
					do {
						tbuf = ext_cmd = "";
						if ((r = psc->read(nosys, tbuf, ext_cmd, starttls)) < 0)
							die(psc->why());

						nosys = 1;

						// STARTTLS/end-sequence seen
						if (starttls == 1) {
							winsize_changed = 1;
							continue;
						}

						if (ext_cmd.size() > 0) {
							cmd_handler(ext_cmd, fd2state, pfds);
						} else if (tbuf.size() > 0) {
							fd2state[1].time = now;
							fd2state[1].obuf += tbuf;
							pfds[1].events |= POLLOUT;
						}
					} while (r == 1);

				} else if (fd2state[i].state == STATE_ACCEPT) {
					if ((afd = accept(i, nullptr, nullptr)) < 0)
						continue;

					// append ID part of host/port/id/ header. We use the accepted sock fd
					// as ID, as this is unique and identifies the TCP connection
					char id[16] = {0};
					snprintf(id, sizeof(id) - 1, "%d/", afd);

					pfds[afd].fd = afd;
					pfds[afd].events = 0;	// dont accept data until remote peer established proxy conn

					fd2state[afd].fd = afd;
					fd2state[afd].rnode = fd2state[i].rnode + id;
					fd2state[afd].state = STATE_CONNECT;
					fd2state[afd].time = now;
					fd2state[afd].obuf.clear();

					nodes2sock[fd2state[afd].rnode] = afd;

					pfds[pt.master()].events |= POLLOUT;
					fd2state[pt.master()].obuf += psc->possibly_b64encrypt("C:T:N:", fd2state[afd].rnode);	// trigger tcp_connect() on remote side
				} else if (fd2state[i].state == STATE_CONNECTED) {
					if ((r = recv(i, sbuf, sizeof(sbuf), 0)) <= 0) {
						close(i);
						pfds[i].fd = -1;
						pfds[i].events = 0;
						fd2state[i].state = STATE_INVALID;
						fd2state[i].fd = -1;
						fd2state[i].obuf.clear();
						nodes2sock.erase(fd2state[i].rnode);

						pfds[pt.master()].events |= POLLOUT;
						fd2state[pt.master()].obuf += psc->possibly_b64encrypt("C:T:F:", fd2state[i].rnode);	// signal finished connection via PTY to remote
						continue;
					}
					pfds[pt.master()].events |= POLLOUT;
					fd2state[pt.master()].obuf += psc->possibly_b64encrypt("C:T:S:", fd2state[i].rnode + string(sbuf, r));
					fd2state[i].time = now;
				} else if (fd2state[i].state == STATE_UDPSERVER) {

					// Always listens on 127.0.0.1, so this is always AF_INET
					sockaddr_in sin;
					socklen_t slen = sizeof(sin);
					if ((r = recvfrom(i, sbuf, sizeof(sbuf), 0, reinterpret_cast<sockaddr *>(&sin), &slen)) <= 0)
						continue;

					// in UDP case, we use the local port as ID.
					char id[16] = {0};
					snprintf(id, sizeof(id) - 1, "%d/", sin.sin_port);

					pfds[pt.master()].events |= POLLOUT;

					// Note here that ID needs to be appended, unlike with TCP. This is since sock fd doesnt
					// distinguish sessions but local ports do this in UDP mode
					fd2state[pt.master()].obuf += psc->possibly_b64encrypt("C:U:S:", fd2state[i].rnode + id + string(sbuf, r));
					fd2state[i].time = now;

					nodes2sock[fd2state[i].rnode + id] = i;
				}
			} else if (pfds[i].revents & POLLOUT) {
				pfds[i].revents = 0;
				if (fd2state[i].state == STATE_STDOUT) {
					if ((r = write(1, fd2state[i].obuf.c_str(), fd2state[i].obuf.size())) <= 0) {
						if (errno == EINTR)
							continue;
						else
							die("pscl: write");
					}

					fd2state[i].obuf.erase(0, r);
				} else if (fd2state[i].state == STATE_PTY) {
					if ((r = write(psc->w_fileno(), fd2state[i].obuf.c_str(), fd2state[i].obuf.size())) <= 0) {
						if (errno == EAGAIN || errno == EWOULDBLOCK)
							continue;
						else
							die(psc->why());
					}

					fd2state[i].obuf.erase(0, r);
				} else if (fd2state[i].state == STATE_CONNECTED) {
					if ((r = write(i, fd2state[i].obuf.c_str(), fd2state[i].obuf.size())) <= 0) {
						close(i);
						pfds[i].fd = -1;
						pfds[i].events = 0;
						fd2state[i].state = STATE_INVALID;
						fd2state[i].fd = -1;
						fd2state[i].obuf.clear();
						nodes2sock.erase(fd2state[i].rnode);

						pfds[pt.master()].events |= POLLOUT;
						fd2state[pt.master()].obuf += psc->possibly_b64encrypt("C:T:F:", fd2state[i].rnode);	// signal finished connection via PTY to remote
						continue;
					}

					fd2state[i].time = now;
					fd2state[i].obuf.erase(0, r);
				} else if (fd2state[i].state == STATE_UDPSERVER) {
					string &dgram = fd2state[i].odgrams.front();
					lsin.sin_port = fd2state[i].ulports.front();	// ID == dst port of reply datagram already in network order
					if ((r = sendto(i, dgram.c_str(), dgram.size(), 0, reinterpret_cast<const sockaddr *>(&lsin), sizeof(lsin))) <= 0)
						continue;

					fd2state[i].odgrams.pop_front();
					fd2state[i].ulports.pop_front();
					fd2state[i].time = now;
				}

				if (fd2state[i].obuf.empty() && fd2state[i].odgrams.empty())
					pfds[i].events &= ~POLLOUT;
			}
		}
	}

	return 0;
}


int main(int argc, char **argv)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_chld;
	sa.sa_flags = SA_RESTART;

	if (sigaction(SIGCHLD, &sa, NULL) < 0)
		die("pscl: sigaction");

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = sig_int;
	if (sigaction(SIGINT, &sa, NULL) < 0)
		die("pscl: sigaction");

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_win;
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGWINCH, &sa, NULL) < 0)
		die("pscl: sigaction");

	printf("\nPortShellCrypter [pscl] v0.60 (C) 2006-2020 stealth -- github.com/stealth/psc\n\n");

	int c = -1;
	char lport[16] = {0}, ip[128] = {0}, rport[16] = {0};

	while ((c = getopt(argc, argv, "T:U:")) != -1) {
		switch (c) {
		case 'T':
			sscanf(optarg, "%15[0-9]:[%127[^]]]:%15[0-9]", lport, ip, rport);
			config::tcp_listens[lport] = string(ip) + "/" + string(rport) + "/";
			printf("pscl: set up local TCP port %s to proxy to %s:%s @ remote.\n", lport, ip, rport);
			break;
		case 'U':
			sscanf(optarg, "%15[0-9]:[%127[^]]]:%15[0-9]", lport, ip, rport);
			config::udp_listens[lport] = string(ip) + "/" + string(rport) + "/";
			printf("pscl: set up local UDP port %s to proxy to %s:%s @ remote.\n", lport, ip, rport);
			break;
		}
	}

	printf("\npscl: Waiting for [pscr] session to appear ...\n");

	proxy_loop();

	return 0;
}

