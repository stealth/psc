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
#include <string>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>


using namespace std;

int main(int argc, char **argv)
{
	int c = -1;
	string script_socket = "", script_file = "";

	while ((c = getopt(argc, argv, "f:S:")) != -1) {
		switch (c) {
		case 'S':
			script_socket = optarg;
			break;
		case 'f':
			script_file = optarg;
			break;
		default:
			break;
		}
	}

	struct sockaddr_un sun;
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strcpy(sun.sun_path, script_socket.c_str());

	int sfd = -1;
	if ((sfd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0)
		return -1;

	if (connect(sfd, reinterpret_cast<sockaddr *>(&sun), sizeof(sun)) < 0)
		return -1;

	int ifd = 0, n = 0;
	char buf[4096] = {0};
	string sbuf = "", obuf = "";

	if (script_file.size() > 0) {
		if ((ifd = open(script_file.c_str(), O_RDONLY)) < 0)
			return -1;
	}

	pollfd pfd[3] = {{ifd, POLLIN, 0}, {1, 0, 0}, {sfd, POLLIN, 0}};

	for (bool leave = 0; !leave;) {
		if ((n = poll(pfd, 3, -1)) < 0)
			break;
		if (n == 0)
			continue;

		for (int i = 0; i < 3; ++i) {

			if (pfd[i].revents & POLLIN) {

				pfd[i].revents = 0;

				if ((n = read(pfd[i].fd, buf, sizeof(buf))) <= 0) {
					if (pfd[i].fd == ifd)
						pfd[i].events = 0;
					else
						leave = 1;
				}
				if (n > 0 && pfd[i].fd == ifd) {		// read from stdin/script
					sbuf += string(buf, n);
					pfd[2].events |= POLLOUT;		// write to socket
				} else if (n > 0 && pfd[i].fd == sfd) {		// read from socket
					obuf += string(buf, n);
					pfd[1].events |= POLLOUT;		// write to stdout
				}
			}
			if (pfd[i].revents & POLLOUT) {

				pfd[i].revents = 0;

				if (pfd[i].fd == 1) {
					if ((n = write(1, obuf.c_str(), obuf.size())) <= 0) {
						leave = 1;
						break;
					}
					obuf.erase(0, n);
					if (obuf.size() == 0)
						pfd[i].events &= ~POLLOUT;
				} else if (pfd[i].fd == sfd) {
					if ((n = write(sfd, sbuf.c_str(), sbuf.size())) <= 0) {
						leave = 1;
						break;
					}
					sbuf.erase(0, n);
					if (sbuf.size() == 0)
						pfd[i].events &= ~POLLOUT;
				}
			}
		}
	}

	close(sfd);
	return 0;
}

