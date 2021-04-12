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

#ifndef psc_net_h
#define psc_net_h

#include <map>
#include <string>
#include <cstdint>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "misc.h"


namespace ns_psc {


extern std::map<std::string, int> tcp_nodes2sock, udp_nodes2sock;

int tcp_listen(const std::string &, const std::string &);

int udp_listen(const std::string &, const std::string &);

int cmd_handler(const std::string &, state *, pollfd *, uint32_t flags = 0);

struct socks5_req {
	uint8_t vers, cmd, mbz, atype;
	union alignas(4) {
		struct alignas(4) {
			in_addr dst;
			uint16_t dport;
		} v4;
		struct alignas(4) {
			in6_addr dst;
			uint16_t dport;
		} v6;
	};
};	// no __attribute__((packed)) needed, as its properly aligned


struct socks4_req {
	uint8_t ver, cmd;
	uint16_t dport;
	uint32_t dst;
	uint8_t id;
};

}

#endif

