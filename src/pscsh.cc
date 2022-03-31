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
#include <cstring>
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


void die(const char *msg)
{
	perror(msg);
	exit(errno);
}


int script_loop(const string &script_socket, const string &script_file)
{

	struct sockaddr_un sun;

	if (script_socket.size() >= sizeof(sun.sun_path) - 1) {
		errno = -E2BIG;
		return -1;
	}

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
	string sbuf = "", obuf = "", end_marker = "###everlong###", end_detect = "";

	if (script_file.size() > 0) {
		if ((ifd = open(script_file.c_str(), O_RDONLY)) < 0)
			return -1;
	}

	pollfd pfd[3] = {{ifd, POLLIN, 0}, {1, 0, 0}, {sfd, POLLIN, 0}};

	for (bool leave = 0, end_detected = 0; !leave;) {

		if ((n = poll(pfd, 3, -1)) < 0)
			break;
		if (n == 0)
			continue;

		for (unsigned int i = 0; i < sizeof(pfd)/sizeof(pfd[0]); ++i) {

			if (pfd[i].revents & POLLIN) {

				pfd[i].revents = 0;

				if ((n = read(pfd[i].fd, buf, sizeof(buf))) <= 0) {
					if (pfd[i].fd == ifd) {			// End of script? No more reads.
						sbuf += end_marker + "\n";	// add end-marker to stream and wait for it to appear on remote pty-echo to notice finishing of script
						pfd[2].events |= POLLOUT;
						pfd[i].events = 0;
					} else
						leave = 1;
				}
				if (n > 0 && pfd[i].fd == ifd) {		// read from stdin/script
					sbuf += string(buf, n);
					pfd[2].events |= POLLOUT;		// write to socket
				} else if (n > 0 && pfd[i].fd == sfd) {		// read from socket
					obuf += string(buf, n);
					pfd[1].events |= POLLOUT;		// write to stdout

					end_detect += string(buf, n);
					if (end_detect.find(end_marker) != string::npos) {
						pfd[i].events = 0;
						end_detected = 1;
					}
					if (end_detect.size() > 3*end_marker.size())
						end_detect.erase(0, end_marker.size());
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
					if (obuf.size() == 0) {
						pfd[i].events &= ~POLLOUT;
						if (end_detected)
							leave = 1;
					}
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
	if (script_file.size() > 0)
		close(ifd);

	return 0;
}


void usage(const char *argv0)
{
	printf("\nUsage: %s [-S script socket] [-f script file]\n\n", argv0);
}


int main(int argc, char **argv)
{
	int c = -1;
	string script_socket = "", script_file = "";

	if (getenv("HOME"))
		script_socket = string(getenv("HOME")) + "/psc.script_sock";

	while ((c = getopt(argc, argv, "f:S:h")) != -1) {
		switch (c) {
		case 'S':
			script_socket = optarg;
			break;
		case 'f':
			if (strncmp(optarg, "script_", 7)) {
				fprintf(stderr, "Script file must start with 'script_'.\n");
				exit(1);
			} else
				script_file = optarg;
			break;
		case 'h':
		default:
			usage(argv[0]);
			exit(0);
		}
	}

	if (script_loop(script_socket, script_file) < 0)
		die("script_loop");

	return 0;
}

