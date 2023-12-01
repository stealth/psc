/*
 * This file is part of port shell crypter (psc).
 *
 * (C) 2006-2022 by Sebastian Krahmer,
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
#include <netinet/in.h>

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


void sig_usr1(int)
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


void usage(const char *argv0)
{
	printf("Usage: %s\t[-4 socks4 lport] [-5 socks5 lport] [-T lport:[ip]:rport]\n"
	       "\t\t[-U lport:[ip]:rport] [-X local proxy IP (127.0.0.1 dflt)]\n"
	       "\t\t[-B lport:[bounce cmd] [-S scripting socket] [-N]\n\n", argv0);
}


// do not use replace_if() for easier C++98 ports
string trim_bcmd_output(const string &s)
{
	string ret = s.substr(0, 75);
	size_t retl = ret.size();
	for (size_t i = 0; i < retl; ++i) {
		if (ret[i] < 32 || ret[i] > 125)
			ret[i] = '.';
	}
	return ret;
}


int proxy_loop()
{

#ifdef HAVE_UNIX98
	pty98 pt;
#else
	pty pt;
#endif
	pid_t pid;
	int r, afd = -1, i, bcmd_accept_fd = -1;

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
	tattr.c_lflag &= ~ISIG;

	//tattr.c_lflag &= ~ECHO;

	global_tcattr = tattr;
	if (tcsetattr(0, TCSANOW, &tattr) < 0)
		die("pscl: tcsetattr");

	struct rlimit rl;
	if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
		die("getrlimit");
	if (rl.rlim_cur > FDID_MAX) {
		rl.rlim_cur = rl.rlim_max = FDID_MAX;
		setrlimit(RLIMIT_NOFILE, &rl);
	}

	if ((pid = fork()) == 0) {
		char *a[] = {getenv("SHELL"), nullptr};
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
		for (unsigned int i = 3; i < rl.rlim_cur; ++i)
			close(i);
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
		if ((r = tcp_listen(config::local_proxy_ip, it->first)) < 0)
			continue;
		pfds[r].fd = r;
		pfds[r].events = POLLIN;

		fd2state[r].fd = r;
		fd2state[r].rnode = it->second;
		fd2state[r].state = STATE_ACCEPT;
	}

	for (auto it = config::udp_listens.begin(); it != config::udp_listens.end(); ++it) {
		if ((r = udp_listen(config::local_proxy_ip, it->first)) < 0)
			continue;
		pfds[r].fd = r;
		pfds[r].events = POLLIN;

		fd2state[r].fd = r;
		fd2state[r].rnode = it->second;
		fd2state[r].state = STATE_UDPSERVER;
	}

	// bouncing via bounce command
	for (auto it = config::bcmd_tcp_listens.begin(); it != config::bcmd_tcp_listens.end(); ++it) {
		if ((r = tcp_listen(config::local_proxy_ip, it->first)) < 0)
			continue;
		pfds[r].fd = r;
		pfds[r].events = POLLIN;

		fd2state[r].fd = r;
		fd2state[r].rnode = it->second;	// actually the cmd e.g. `stty -echo raw;nc example.com 22`
		fd2state[r].state = STATE_BCMD_ACCEPT;
	}

	if (config::socks5_fd != -1) {
		pfds[config::socks5_fd].fd = config::socks5_fd;
		pfds[config::socks5_fd].events = POLLIN;

		fd2state[config::socks5_fd].fd = config::socks5_fd;
		fd2state[config::socks5_fd].rnode = "";
		fd2state[config::socks5_fd].state = STATE_SOCKS5_ACCEPT;
	}

	if (config::socks4_fd != -1) {
		pfds[config::socks4_fd].fd = config::socks4_fd;
		pfds[config::socks4_fd].events = POLLIN;

		fd2state[config::socks4_fd].fd = config::socks4_fd;
		fd2state[config::socks4_fd].rnode = "";
		fd2state[config::socks4_fd].state = STATE_SOCKS4_ACCEPT;
	}

	if (config::script_sock != -1) {
		pfds[config::script_sock].fd = config::script_sock;
		pfds[config::script_sock].events = POLLIN;

		fd2state[config::script_sock].fd = config::script_sock;
		fd2state[config::script_sock].rnode = "";
		fd2state[config::script_sock].state = STATE_SCRIPT_ACCEPT;
	}

	// Since we have no fd per "connection" for UDP, we need to keep track of
	// local sockaddrs <-> id by ourself in order to know to which dst to send replies
	// we receive from remote
	udp_node2id udp_nodes2id;

	int max_fd = rl.rlim_cur - 1, script_fd = -1;

	string ext_cmd = "", tbuf = "", bcmd = "";

	enum { CHUNK_SIZE = 8192 };

	long double bcmd_tx = 0, BCMD_PTY_SPEED_BYTES = BCMD_PTY_SPEED/8.0;
	time_t bcmd_tx_start = 0;

	for (;;) {

		memset(sbuf, 0, sizeof(sbuf));

		if (winsize_changed && psc->is_crypted()) {
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

				if (fd2state[i].state == STATE_CONNECT) {
					pfds[pt.master()].events |= POLLOUT;
					fd2state[pt.master()].obuf += psc->possibly_b64encrypt("C:T:F:", fd2state[i].rnode);     // signal interrupted connection to remote
					tcp_nodes2sock.erase(fd2state[i].rnode);
				}

				close(i);
				fd2state[i].fd = -1;
				fd2state[i].state = STATE_INVALID;
				pfds[i].fd = -1;
				pfds[i].events = 0;
				continue;
			}

			if (pfds[i].revents & (POLLERR|POLLHUP|POLLNVAL)) {
				if (fd2state[i].state == STATE_STDIN || fd2state[i].state == STATE_PTY)
					die("pscl: TTY hangup");
				if (fd2state[i].state == STATE_CONNECTED || fd2state[i].state == STATE_CONNECT) {
					pfds[pt.master()].events |= POLLOUT;
					fd2state[pt.master()].obuf += psc->possibly_b64encrypt("C:T:F:", fd2state[i].rnode);     // signal finished connection to remote
					tcp_nodes2sock.erase(fd2state[i].rnode);
				}

				if (fd2state[i].state == STATE_SCRIPT_IO) {
					pfds[0].events |= POLLIN;		// reactivate stdin
					pfds[config::script_sock].events |= POLLIN;
				}

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

						// ext_cmd can have been filled by psc->read() only when already STARTTLS happened
						if (ext_cmd.size() > 0) {
							cmd_handler(ext_cmd, fd2state, pfds);
						} else if (tbuf.size() > 0) {
							fd2state[1].time = now;

							// Are we running in a bounce command session?
							if (bcmd_accept_fd >= 0) {
								//usleep(BCMD_PTY_DELAY);
								fd2state[1].obuf += "\r\n< " + trim_bcmd_output(tbuf);

								// do not echo back bcmd inject that happens just after STATE_BCMD_CONNECT
								if (fd2state[bcmd_accept_fd].state == STATE_BCMD_CONNECT) {

									// If we see the newline echoed back, strip off until newline and only forward real potential data.
									// Otherwise the echo was just partial and we need to wait until full echo
									string::size_type nl = string::npos;
									if ((nl = tbuf.find("\n")) != string::npos) {
										fd2state[bcmd_accept_fd].obuf += tbuf.substr(nl + 1);
										fd2state[bcmd_accept_fd].state = STATE_BCMD_CONNECTED;
										pfds[bcmd_accept_fd].events |= POLLIN;
										if (!fd2state[bcmd_accept_fd].obuf.empty())
											pfds[bcmd_accept_fd].events |= POLLOUT;
									}
								} else { // must be STATE_BCMD_CONNECTED, forward as is
									fd2state[bcmd_accept_fd].obuf += tbuf;
									pfds[bcmd_accept_fd].events |= POLLOUT;

								}

							// No -> only forward to stdout as is
							} else {
								fd2state[1].obuf += tbuf;
							}

							pfds[1].events |= POLLOUT;

							// mirror to script sock if opened
							if (script_fd >= 0) {
								fd2state[script_fd].time = now;
								fd2state[script_fd].obuf += tbuf;
								pfds[script_fd].events |= POLLOUT;
							}
						}
					} while (r == 1);

				} else if (fd2state[i].state == STATE_ACCEPT) {
					if ((afd = accept(i, nullptr, nullptr)) < 0)
						continue;

					// append ID part of host/port/id/ header. We use the accepted sock fd
					// as ID, as this is unique and identifies the TCP connection
					char id[16] = {0};
					snprintf(id, sizeof(id) - 1, "%04hx/", afd);

					pfds[afd].fd = afd;
					pfds[afd].events = 0;	// dont accept data until remote peer established proxy conn

					fd2state[afd].fd = afd;
					fd2state[afd].rnode = fd2state[i].rnode + id;
					fd2state[afd].state = STATE_CONNECT;
					fd2state[afd].time = now;
					fd2state[afd].obuf.clear();

					tcp_nodes2sock[fd2state[afd].rnode] = afd;

					pfds[pt.master()].events |= POLLOUT;
					fd2state[pt.master()].obuf += psc->possibly_b64encrypt("C:T:N:", fd2state[afd].rnode);	// trigger tcp_connect() on remote side

				} else if (fd2state[i].state == STATE_BCMD_ACCEPT) {
					if ((afd = accept(i, nullptr, nullptr)) < 0)
						continue;

					// can only handle one bcmd bounce at once
					if (bcmd_accept_fd >= 0) {
						close(afd);
						continue;
					}

					pfds[afd].fd = afd;
					pfds[afd].events = 0;	// dont accept data until bcmd has chance to connect

					fd2state[afd].fd = afd;
					fd2state[afd].rnode = fd2state[i].rnode;
					fd2state[afd].state = STATE_BCMD_CONNECT;	// will change to STATE_BCMD_CONNECTED when reading echo back from PTY
					fd2state[afd].time = now;
					fd2state[afd].obuf.clear();

					pfds[pt.master()].events |= POLLOUT;
					fd2state[pt.master()].obuf += fd2state[i].rnode + "\n";	// trigger connect via command (e.g. `nc example.com 22`) on remote side

					bcmd_accept_fd = afd;
					bcmd = fd2state[i].rnode;
					bcmd_tx = 0;
					bcmd_tx_start = now;

					fd2state[1].obuf += "\r\n> " + bcmd;
					pfds[1].events |= POLLOUT;

				} else if (fd2state[i].state == STATE_SOCKS5_ACCEPT) {
					if ((afd = accept(i, nullptr, nullptr)) < 0)
						continue;

					pfds[afd].fd = afd;
					pfds[afd].events = POLLIN;		// wait for SOCKS5 proto requests
					fd2state[afd].fd = afd;
					fd2state[afd].rnode = "";
					fd2state[afd].state = STATE_SOCKS5_AUTH1;
					fd2state[afd].time = now;
					fd2state[afd].obuf.clear();

				} else if (fd2state[i].state == STATE_SOCKS4_ACCEPT) {
					if ((afd = accept(i, nullptr, nullptr)) < 0)
						continue;

					pfds[afd].fd = afd;
					pfds[afd].events = POLLIN;		// wait for SOCKS4 proto requests
					fd2state[afd].fd = afd;
					fd2state[afd].rnode = "";
					fd2state[afd].state = STATE_SOCKS4_AUTH;
					fd2state[afd].time = now;
					fd2state[afd].obuf.clear();

				} else if (fd2state[i].state == STATE_CONNECTED) {
					if ((r = recv(i, sbuf, sizeof(sbuf), 0)) <= 0) {
						close(i);
						pfds[i].fd = -1;
						pfds[i].events = 0;
						fd2state[i].state = STATE_INVALID;
						fd2state[i].fd = -1;
						fd2state[i].obuf.clear();
						tcp_nodes2sock.erase(fd2state[i].rnode);

						pfds[pt.master()].events |= POLLOUT;
						fd2state[pt.master()].obuf += psc->possibly_b64encrypt("C:T:F:", fd2state[i].rnode);	// signal finished connection via PTY to remote
						continue;
					}
					pfds[pt.master()].events |= POLLOUT;
					fd2state[pt.master()].obuf += psc->possibly_b64encrypt("C:T:S:", fd2state[i].rnode + string(sbuf, r));
					fd2state[i].time = now;

				} else if (fd2state[i].state == STATE_BCMD_CONNECTED) {

					// We need to throttle amount of data/sec so that remote
					// peer do not need to send more than terminal speed (usually 38400bps)
					// to the raw pty or otherwise data will get lost
					if ((now - bcmd_tx_start) == 0 || (bcmd_tx / (now - bcmd_tx_start) > BCMD_PTY_SPEED_BYTES))
						continue;

					//usleep(BCMD_PTY_DELAY);
					if ((r = recv(i, sbuf, sizeof(sbuf), 0)) <= 0) {
						close(i);
						pfds[i].fd = -1;
						pfds[i].events = 0;
						fd2state[i].state = STATE_INVALID;
						fd2state[i].fd = -1;
						fd2state[i].obuf.clear();

						pfds[1].events |= POLLOUT;
						fd2state[1].obuf += "\r\n> Bounce cmd finished, type Ctrl-C.\r\n";
						bcmd = "";
						bcmd_accept_fd = -1;
						continue;
					}
					pfds[pt.master()].events |= POLLOUT;
					fd2state[pt.master()].obuf += string(sbuf, r);
					fd2state[i].time = now;

					fd2state[1].obuf += "\r\n> " + trim_bcmd_output(string(sbuf, r));
					pfds[1].events |= POLLOUT;

					bcmd_tx += r;

				} else if (fd2state[i].state == STATE_SOCKS4_AUTH) {

					socks4_req *s4r = reinterpret_cast<socks4_req *>(sbuf);

					// expect SOCKS4 request and send positive response
					memset(sbuf, 0, sizeof(sbuf));
					if ((r = recv(i, sbuf, sizeof(sbuf), 0)) <= 0 || sbuf[0] != 4) {
						close(i);
						pfds[i].fd = -1;
						pfds[i].events = 0;
						fd2state[i].state = STATE_INVALID;
						fd2state[i].fd = -1;
						fd2state[i].obuf.clear();
						continue;
					}

					s4r->ver = 0;
					s4r->cmd = 0x5a;			// request granted
					fd2state[i].obuf += string(sbuf, 8);	// orig req w/o ID

					char dst[128] = {0};
					uint16_t rport = 0;

					inet_ntop(AF_INET, &s4r->dst, dst, sizeof(dst) - 1);
					rport = ntohs(s4r->dport);

					// Now that we know where connection is going to, we can build
					// IP/port/ID header
					char hdr[256] = {0};
					snprintf(hdr, sizeof(hdr) - 1, "%s/%04hx/%04hx/", dst, rport, i);

					fd2state[i].rnode = hdr;
					fd2state[i].state = STATE_CONNECT;
					fd2state[i].time = now;

					tcp_nodes2sock[fd2state[i].rnode] = i;

					pfds[pt.master()].events |= POLLOUT;
					fd2state[pt.master()].obuf += psc->possibly_b64encrypt("C:T:N:", fd2state[i].rnode);	// trigger tcp_connect() on remote side

					pfds[i].events = POLLOUT;	// don't take data until remote site established connection, so *only* POLLOUT

				} else if (fd2state[i].state == STATE_SOCKS5_AUTH1) {

					// expect SOCKS5 auth request (none) and send positive response
					memset(sbuf, 0, sizeof(sbuf));
					if ((r = recv(i, sbuf, sizeof(sbuf), 0)) <= 0 || sbuf[0] != 5) {
						close(i);
						pfds[i].fd = -1;
						pfds[i].events = 0;
						fd2state[i].state = STATE_INVALID;
						fd2state[i].fd = -1;
						fd2state[i].obuf.clear();
						continue;
					}
					pfds[i].events |= POLLOUT;
					fd2state[i].state = STATE_SOCKS5_AUTH2;
					fd2state[i].obuf += string("\x05\x00", 2);
					fd2state[i].time = now;
				} else if (fd2state[i].state == STATE_SOCKS5_AUTH2) {

					memset(sbuf, 0, sizeof(sbuf));
					socks5_req *s5r = reinterpret_cast<socks5_req *>(sbuf);

					// expect SOCKS5 connect request
					if ((r = recv(i, sbuf, sizeof(sbuf), 0)) < 10 ||
					    s5r->vers != 5 ||						// wrong version?
					    (s5r->atype != 1 && s5r->atype != 3 && s5r->atype != 4) ||	// not or DNS name or IPv4 or IPv6?
					    s5r->cmd != 1 ||						// not a TCP-connect?
					    (s5r->atype == 3 && s5r->name.nlen > MAX_NAME_LEN) ||	// DNS name too long?
					    (s5r->atype == 3 && !config::socks5_dns)) {			// SOCKS5 resolving not enabled?
						s5r->cmd = 0x08;			// atype not supported
						writen(i, sbuf, 2);
						close(i);
						pfds[i].fd = -1;
						pfds[i].events = 0;
						fd2state[i].state = STATE_INVALID;
						fd2state[i].fd = -1;
						fd2state[i].obuf.clear();
						continue;
					}

					char dst[128] = {0};
					uint16_t rport = 0;

					// IPv4
					if (s5r->atype == 1) {
						inet_ntop(AF_INET, &s5r->v4.dst, dst, sizeof(dst) - 1);
						rport = ntohs(s5r->v4.dport);

					// IPv6
					} else if (s5r->atype == 4) {
						inet_ntop(AF_INET6, &s5r->v6.dst, dst, sizeof(dst) - 1);
						rport = ntohs(s5r->v6.dport);

					// DNS name
					} else {
						memcpy(dst, s5r->name.name, s5r->name.nlen);
						uint16_t tmp;
						memcpy(&tmp, s5r->name.name + s5r->name.nlen, sizeof(tmp));
						rport = ntohs(tmp);
					}

					// Now that we know where connection is going to, we can build
					// IP/port/ID header
					char hdr[256] = {0};
					snprintf(hdr, sizeof(hdr) - 1, "%s/%04hx/%04hx/", dst, rport, i);

					fd2state[i].rnode = hdr;
					fd2state[i].state = STATE_CONNECT;
					fd2state[i].time = now;

					tcp_nodes2sock[fd2state[i].rnode] = i;

					pfds[pt.master()].events |= POLLOUT;
					fd2state[pt.master()].obuf += psc->possibly_b64encrypt("C:T:N:", fd2state[i].rnode);	// trigger tcp_connect() on remote side

					s5r->cmd = 0;	// response status to socks5 client
					fd2state[i].obuf += string(sbuf, r);

					pfds[i].events = POLLOUT;	// don't take data until remote site established connection, so *only* POLLOUT

				} else if (fd2state[i].state == STATE_UDPSERVER) {

					char sin[sizeof(sockaddr_in) + sizeof(sockaddr_in6)] = {0};
					socklen_t sinlen = sizeof(sin);
					if ((r = recvfrom(i, sbuf, sizeof(sbuf), 0, reinterpret_cast<sockaddr *>(&sin), &sinlen)) <= 0)
						continue;

					// in UDP case, we need to generate a unique ID based on dgram origin. If the origin was already
					// given an unique ID, put() will find and return it transparently
					char id[16] = {0};
					snprintf(id, sizeof(id) - 1, "%04hx/", udp_nodes2id.put(string(sin, sinlen)));

					// Note here that ID needs to be appended, unlike with TCP.
					fd2state[pt.master()].obuf += psc->possibly_b64encrypt("C:U:S:", fd2state[i].rnode + id + string(sbuf, r));
					pfds[pt.master()].events |= POLLOUT;

					fd2state[i].time = now;

					udp_nodes2sock[fd2state[i].rnode + id] = i;

				} else if (fd2state[i].state == STATE_SCRIPT_ACCEPT) {

					if ((script_fd = accept(i, nullptr, nullptr)) < 0)
						continue;

					pfds[script_fd].fd = script_fd;

					pfds[script_fd].events = POLLIN;
					pfds[i].events = 0;			// block further connects to UNIX script socket
					pfds[0].events = 0;			// block stdin typing during script processing

					fd2state[script_fd].fd = script_fd;
					fd2state[script_fd].rnode = "";
					fd2state[script_fd].state = STATE_SCRIPT_IO;
					fd2state[script_fd].time = now;
					fd2state[script_fd].obuf.clear();

				} else if (fd2state[i].state == STATE_SCRIPT_IO) {	// very similar to STDIN read

					if ((r = read(i, sbuf, sizeof(sbuf))) <= 0) {
						if (errno == EINTR)
							continue;
						close(i);
						script_fd = -1;
						pfds[i].fd = -1;
						pfds[i].events = 0;
						fd2state[i].state = STATE_INVALID;
						fd2state[i].fd = -1;
						fd2state[i].obuf.clear();
						pfds[0].events |= POLLIN;		// reactivate stdin
						pfds[config::script_sock].events |= POLLIN;
						continue;
					}
					fd2state[pt.master()].obuf += psc->possibly_b64encrypt("D:0:", string(sbuf, r));
					pfds[pt.master()].events |= POLLOUT;
				}

			} else if (pfds[i].revents & POLLOUT) {
				pfds[i].revents = 0;
				if (fd2state[i].state == STATE_STDOUT) {

					size_t n = fd2state[i].obuf.size() > CHUNK_SIZE ? CHUNK_SIZE : fd2state[i].obuf.size();

					if ((r = write(1, fd2state[i].obuf.c_str(), n)) <= 0) {
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

					fd2state[i].time = now;
					fd2state[i].obuf.erase(0, r);
				} else if (fd2state[i].state == STATE_CONNECT ||	// for the SOCKS4/5 case: reply with conn success
					   fd2state[i].state == STATE_SOCKS5_AUTH2 ||	// for the SOCKS5 case: reply for auth success
				           fd2state[i].state == STATE_CONNECTED) {
					if ((r = write(i, fd2state[i].obuf.c_str(), fd2state[i].obuf.size())) <= 0) {
						close(i);
						pfds[i].fd = -1;
						pfds[i].events = 0;
						fd2state[i].state = STATE_INVALID;
						fd2state[i].fd = -1;
						fd2state[i].obuf.clear();
						tcp_nodes2sock.erase(fd2state[i].rnode);

						pfds[pt.master()].events |= POLLOUT;
						fd2state[pt.master()].obuf += psc->possibly_b64encrypt("C:T:F:", fd2state[i].rnode);	// signal finished connection via PTY to remote
						continue;
					}

					fd2state[i].time = now;
					fd2state[i].obuf.erase(0, r);
				} else if (fd2state[i].state == STATE_BCMD_CONNECTED) {
					if ((r = write(i, fd2state[i].obuf.c_str(), fd2state[i].obuf.size())) <= 0) {
						close(i);
						pfds[i].fd = -1;
						pfds[i].events = 0;
						fd2state[i].state = STATE_INVALID;
						fd2state[i].fd = -1;
						fd2state[i].obuf.clear();

						pfds[pt.master()].events |= POLLOUT;
						continue;
					}

					fd2state[i].time = now;
					fd2state[i].obuf.erase(0, r);
				} else if (fd2state[i].state == STATE_UDPSERVER) {
					string &dgram = fd2state[i].odgrams.front().second;
					string sin = udp_nodes2id.get(fd2state[i].odgrams.front().first); // map id back to originating sockaddr
					if ((r = sendto(i, dgram.c_str(), dgram.size(), 0, reinterpret_cast<const sockaddr *>(sin.c_str()), sin.size())) <= 0)
						continue;

					fd2state[i].odgrams.pop_front();
					fd2state[i].time = now;

				} else if (fd2state[i].state == STATE_SCRIPT_IO) {

					size_t n = fd2state[i].obuf.size() > CHUNK_SIZE ? CHUNK_SIZE : fd2state[i].obuf.size();

					if ((r = write(i, fd2state[i].obuf.c_str(), n)) <= 0) {
						if (errno == EINTR)
							continue;

						close(i);
						script_fd = -1;
						pfds[i].fd = -1;
						pfds[i].events = 0;
						fd2state[i].state = STATE_INVALID;
						fd2state[i].fd = -1;
						fd2state[i].obuf.clear();
						pfds[0].events |= POLLIN;		// reactivate stdin
						pfds[config::script_sock].events |= POLLIN;
						continue;
					}

					fd2state[i].time = now;
					fd2state[i].obuf.erase(0, r);
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
	printf("\nPortShellCrypter [pscl] v0.67 (C) 2006-2023 stealth -- github.com/stealth/psc\n\n");

	if (!getenv("SHELL")) {
		printf("pscl: No $SHELL set in environment. Exiting.\n");
		exit(1);
	}

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_chld;
	sa.sa_flags = SA_RESTART;

	if (sigaction(SIGCHLD, &sa, nullptr) < 0)
		die("pscl: sigaction");

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = sig_usr1;
	if (sigaction(SIGUSR1, &sa, nullptr) < 0)
		die("pscl: sigaction");

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_win;
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGWINCH, &sa, nullptr) < 0)
		die("pscl: sigaction");

	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGINT, &sa, nullptr) < 0 || sigaction(SIGQUIT, &sa, nullptr) ||
	    sigaction(SIGPIPE, &sa, nullptr))
		die("pscl: sigaction");

	int c = -1;
	char lport[16] = {0}, ip[128] = {0}, port_hex[16] = {0};
	char bounce_cmd[128] = {0};
	uint16_t rport = 0;

	while ((c = getopt(argc, argv, "T:U:X:5:4:S:B:hN")) != -1) {
		switch (c) {
		case 'N':
			config::socks5_dns = 1;
			break;
		case 'T':
			if (sscanf(optarg, "%15[0-9]:[%127[^]]]:%hu", lport, ip, &rport) == 3) {
				snprintf(port_hex, sizeof(port_hex), "%04hx", rport);
				config::tcp_listens[lport] = string(ip) + "/" + string(port_hex) + "/";
				printf("pscl: set up local TCP port %s to proxy to %s:%hu @ remote.\n", lport, ip, rport);
			}
			break;
		case 'U':
			if (sscanf(optarg, "%15[0-9]:[%127[^]]]:%hu", lport, ip, &rport) == 3) {
				snprintf(port_hex, sizeof(port_hex), "%04hx", rport);
				config::udp_listens[lport] = string(ip) + "/" + string(port_hex) + "/";
				printf("pscl: set up local UDP port %s to proxy to %s:%hu @ remote.\n", lport, ip, rport);
			}
			break;
		case 'X':
			config::local_proxy_ip = optarg;
			break;
		case '4':
			if (config::socks4_fd == -1) {
				config::socks4_port = strtoul(optarg, nullptr, 10);
				if ((config::socks4_fd = tcp_listen(config::local_proxy_ip, optarg)) > 0)
					printf("pscl: set up SOCKS4 port on %s\n", optarg);
			}
			break;
		case '5':
			if (config::socks5_fd == -1) {
				config::socks5_port = strtoul(optarg, nullptr, 10);
				if ((config::socks5_fd = tcp_listen(config::local_proxy_ip, optarg)) > 0)
					printf("pscl: set up SOCKS5 port on %s\n", optarg);
			}
			break;
		case 'S':
			if (config::script_sock == -1) {
				if ((config::script_sock = unix_listen(optarg)) > 0)
					printf("pscl: set up script socket on %s\n", optarg);;
			}
			break;
		case 'B':
			if (sscanf(optarg, "%15[0-9]:[%127[^]]]", lport, bounce_cmd) == 2) {
				config::bcmd_tcp_listens[lport] = bounce_cmd;
				printf("pscl: set up local TCP port %s to bounce via %s @ remote.\n", lport, bounce_cmd);
			}
			break;
		case 'h':
		default:
			usage(argv[0]);
			exit(0);
		}
	}

	printf("\npscl: Waiting for [pscr] session to appear ...\n");

	proxy_loop();

	return 0;
}

