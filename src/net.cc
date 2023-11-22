/*
 * This file is part of port shell crypter (psc).
 *
 * (C) 2020-2022 by Sebastian Krahmer,
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

#include <string>
#include <memory>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "misc.h"
#include "net.h"


using namespace std;

namespace ns_psc {


// maps "IP/port/ID/" string to actual socket, so that we know
// which socket the tagged cmd data belongs to, which carries IP/port pair in front
map<string, int> tcp_nodes2sock, udp_nodes2sock;


static int listen(int type, const string &ip, const string &port)
{
	int r = 0, sock_fd = -1;
	addrinfo hint, *tai = nullptr;
	memset(&hint, 0, sizeof(hint));
	hint.ai_socktype = type;

	if ((r = getaddrinfo(ip.c_str(), port.c_str(), &hint, &tai)) < 0)
		return -1;

	unique_ptr<addrinfo, decltype(&freeaddrinfo)> ai(tai, freeaddrinfo);

	if ((sock_fd = socket(ai->ai_family, type, 0)) < 0)
		return -1;

	int flags = fcntl(sock_fd, F_GETFL);
	fcntl(sock_fd, F_SETFL, flags|O_NONBLOCK);

	int one = 1;
#ifdef SO_REUSEPORT
	setsockopt(sock_fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
	one = 1;
#endif
	setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	if (::bind(sock_fd, ai->ai_addr, ai->ai_addrlen) < 0)
		return -1;
	if (type == SOCK_STREAM) {
		if (::listen(sock_fd, 12) < 0)
			return -1;
	}

	return sock_fd;
}


int udp_listen(const string &ip, const string &port)
{
	return listen(SOCK_DGRAM, ip, port);
}


int tcp_listen(const string &ip, const string &port)
{
	return listen(SOCK_STREAM, ip, port);
}


int unix_listen(const string &path)
{
	sockaddr_un sun;
	if (path.size() >= sizeof(sun.sun_path))
		return -1;

	unlink(path.c_str());

	int sfd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sfd < 0)
		return -1;


	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strcpy(sun.sun_path, path.c_str());

	mode_t um = umask(077);
	if (::bind(sfd, reinterpret_cast<sockaddr *>(&sun), sizeof(sun)) < 0) {
		umask(um);
		close(sfd);
		return -1;
	}
	if (::listen(sfd, 1) < 0) {
		umask(um);
		close(sfd);
		return -1;
	}
	umask(um);
	return sfd;
}


static map<string, struct addrinfo *> resolv_cache;


static int connect(int type, const string &name, const string &port)
{

	// if cache has grown largely, drop it and make new
	if (resolv_cache.size() > 1024) {
		for (const auto &it : resolv_cache)
			freeaddrinfo(it.second);
		resolv_cache.clear();
	}

	int r = 0, sock_fd = -1, one = 1;
	socklen_t len = sizeof(one);

	addrinfo hint, *tai = nullptr;
	memset(&hint, 0, sizeof(hint));
	hint.ai_socktype = type;
	hint.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;

	bool can_free = 1;

	if ((r = getaddrinfo(name.c_str(), port.c_str(), &hint, &tai)) != 0) {

		can_free = 0;

		string key = name + ":" + port;

		auto it = resolv_cache.find(key);

		if (it == resolv_cache.end()) {

			hint.ai_flags = AI_NUMERICSERV;
			if ((r = getaddrinfo(name.c_str(), port.c_str(), &hint, &tai)) != 0)
				return -1;

			resolv_cache[key] = tai;

		} else
			tai = it->second;
	}

	if ((sock_fd = socket(tai->ai_family, type, 0)) < 0) {
		if (can_free)
			freeaddrinfo(tai);
		return -1;
	}

	if (type == SOCK_STREAM)
		setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY, &one, len);

	int flags = fcntl(sock_fd, F_GETFL);
	fcntl(sock_fd, F_SETFL, flags|O_NONBLOCK);

	if (::connect(sock_fd, tai->ai_addr, tai->ai_addrlen) < 0 && errno != EINPROGRESS) {
		close(sock_fd);
		if (can_free)
			freeaddrinfo(tai);
		return -1;
	}

	return sock_fd;
}



static int udp_connect(const string &ip, const string &port)
{
	return connect(SOCK_DGRAM, ip, port);
}


static int tcp_connect(const string &ip, const string &port)
{
	return connect(SOCK_STREAM, ip, port);
}


/*
 * C:T:N:IP/port/ID/		-> open new TCP connection to IP:port
 * C:T:C:IP/port/ID/	  	-> connection to IP:port is estabished on remote side
 * C:T:S:IP/port/ID/data	-> send data to IP:port
 * C:T:R:IP/port/ID/data	-> data received from IP:port on remote side
 * C:T:F:IP/port/ID/		-> close connection belonging to IP:port
 *
 * C:U:S:IP/port/ID/		-> send UDP datagram to IP:port
 * C:U:R:IP/port/ID/		-> received UDP datagram from IP:port on remote side
 *
 */

int cmd_handler(const string &cmd, state *fd2state, pollfd *pfds, uint32_t flags)
{
	char C[16] = {0}, proto[16] = {0}, op[16] = {0}, host[128] = {0};
	uint16_t port = 0, id = 0;
	int sock = -1;

	// ID is the logical channel to distinguish between multiple same host:port connections.
	// The accepted socket fd of the local psc part is unique and good for it.
	if (sscanf(cmd.c_str(), "%15[^:]:%15[^:]:%15[^:]:%127[^/]/%04hx/%04hx/", C, proto, op, host, &port, &id) != 6)
		return -1;

	auto slash = cmd.find("/");
	const string node = string(host) + cmd.substr(slash, 11);

	if (C[0] != 'C' || (proto[0] != 'T' && proto[0] != 'U'))
		return -1;

	// open new non-blocking connection
	if (cmd.find("C:T:N:") == 0 && (flags & NETCMD_SEND_ALLOW)) {
		if ((sock = tcp_connect(host, to_string(port))) < 0)
			return -1;

		pfds[sock].revents = 0;
		pfds[sock].events = POLLOUT;
		pfds[sock].fd = sock;

		fd2state[sock].fd = sock;
		fd2state[sock].state = STATE_CONNECT;
		fd2state[sock].obuf.clear();
		fd2state[sock].odgrams.clear();
		fd2state[sock].rnode = node;
		fd2state[sock].time = time(nullptr);

		tcp_nodes2sock[node] = sock;

	// non-blocking connect() got ready
	} else if (cmd.find("C:T:C:") == 0) {
		auto it = tcp_nodes2sock.find(node);
		if (it == tcp_nodes2sock.end())
			return -1;
		sock = it->second;

		pfds[sock].events = POLLIN;

		fd2state[sock].fd = sock;
		fd2state[sock].state = STATE_CONNECTED;
		fd2state[sock].obuf.clear();
		fd2state[sock].odgrams.clear();
		fd2state[sock].time = time(nullptr);

	// finish connection
	} else if (cmd.find("C:T:F:") == 0) {
		auto it = tcp_nodes2sock.find(node);
		if (it == tcp_nodes2sock.end())
			return -1;
		sock = it->second;
		tcp_nodes2sock.erase(it);

		// flush remaining data
		if (fd2state[sock].obuf.size() > 0)
			writen(sock, fd2state[sock].obuf.c_str(), fd2state[sock].obuf.size());

		// sock will be closed in main poll() loop via timeout
		shutdown(sock, SHUT_RDWR);
		pfds[sock].fd = -1;
		pfds[sock].events = 0;

		fd2state[sock].state = STATE_CLOSING;
		fd2state[sock].obuf.clear();
		fd2state[sock].odgrams.clear();
		fd2state[sock].time = time(nullptr);

	// Send or receive data. No NETCMD_SEND_ALLOW check, since the node will not be in
	// the tcp_nodes2sock map in the first place, as there was no tcp_connect() and no map
	// insertion.
	} else if (cmd.find("C:T:S:") == 0 || cmd.find("C:T:R:") == 0) {
		auto it = tcp_nodes2sock.find(node);
		if (it == tcp_nodes2sock.end())
			return -1;
		sock = it->second;
		pfds[sock].events |= POLLOUT;

		fd2state[sock].obuf += cmd.substr(6 + node.size());	// strip off data part
		fd2state[sock].time = time(nullptr);

	} else if (cmd.find("C:U:S:") == 0 || cmd.find("C:U:R:") == 0) {
		auto it = udp_nodes2sock.find(node);
		if (it == udp_nodes2sock.end()) {
			if (!(flags & NETCMD_SEND_ALLOW))
				return 0;
			if ((sock = udp_connect(host, to_string(port))) < 0)
				return -1;
			udp_nodes2sock[node] = sock;

			// Just fill rnode part in server side. client main loop expects ID/ part not to be
			// appended
			fd2state[sock].rnode = node;
			fd2state[sock].state = STATE_UDPCLIENT;
			fd2state[sock].fd = sock;
		} else
			sock = it->second;

		pfds[sock].revents = 0;
		pfds[sock].fd = sock;
		pfds[sock].events = POLLIN;

		if (cmd.size() > 6 + node.size()) {
			fd2state[sock].odgrams.push_back({id, cmd.substr(6 + node.size())});	// strip off data part
			pfds[sock].events |= POLLOUT;
		}
		fd2state[sock].time = time(nullptr);
	}

	return 0;
}

}

