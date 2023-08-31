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

#ifndef psc_misc_h
#define psc_misc_h

#include <cstdint>
#include <map>
#include <string>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <deque>
#include <time.h>

namespace ns_psc {

void die(const char *);

void fix_size(int);

int writen(int, const char *, size_t);

size_t b64_decode(const char *, unsigned char *);

char *b64_encode(const char *, size_t, unsigned char *);

int RAND_bytes(unsigned char *, int);

enum {

	STATE_INVALID		=	0,
	STATE_PTY		=	1,
	STATE_STDIN		=	2,
	STATE_STDOUT		=	3,
	STATE_ACCEPT		=	4,
	STATE_CONNECT		=	5,
	STATE_CONNECTED		=	6,
	STATE_CLOSING		=	7,
	STATE_UDPCLIENT		=	8,
	STATE_UDPSERVER		=	9,
	STATE_SOCKS5_ACCEPT	=	10,
	STATE_SOCKS5_AUTH1	=	11,
	STATE_SOCKS5_AUTH2	=	12,
	STATE_SOCKS4_ACCEPT	=	13,
	STATE_SOCKS4_AUTH	=	14,
	STATE_SCRIPT_ACCEPT	=	15,
	STATE_SCRIPT_IO		=	16,

	CLOSING_TIME		=	10,
	CONNECT_TIME		=	30,
	UDP_CLOSING_TIME	=	120,

	MTU			=	1500,
	BLOCK_SIZE		=	2*MTU,

	NETCMD_SEND_ALLOW	=	1,

	FDID_MAX		=	65535	// id field of net cmds encoded as %04hx, so socket fds must not be larger
};

struct state {
	time_t time{0};
	int fd{-1};
	int state{STATE_INVALID};
	std::string obuf{""}, rnode{""};

	// deque of { UDP id, data } of UDP datagrams in out queue
	std::deque<std::pair<uint16_t, std::string>> odgrams;
};

}

namespace config {

extern std::map<std::string, std::string> tcp_listens, udp_listens;

extern int socks5_port, socks5_fd, socks4_port, socks4_fd, script_sock;

extern std::string local_proxy_ip;

}

#endif


