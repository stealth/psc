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

int unix_listen(const std::string &);

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


// TCP connections can use the socket fd as id, as it uniquely identifies the connection.
// UDP sockets receive all datagrams on the same fd, so we cannot use the fd as an connection-id and therefore
// need to map the dgram's originating struct sockaddr {} (implemented as string blob) to an unqiue id,
// so that we know where to send replies to when we receive data for that id.
class udp_node2id {

	std::map<uint16_t, std::string> d_id2node;
	std::map<std::string, uint16_t> d_node2id;

	enum { max_id = 0xffff };

	uint16_t d_next_id{0};

public:

	uint16_t put(const std::string &addr)
	{
		// if origin already exists, take this ID
		auto it = d_node2id.find(addr);
		if (it != d_node2id.end())
			return it->second;

		// if there are free IDs, pick a new one
		if (d_node2id.size() <= max_id) {
			d_node2id[addr] = d_next_id;
			d_id2node[d_next_id] = addr;
			return d_next_id++;
		}

		// otherwise flush all mappings (possibly corrupt outstanding UDP sessions)
		d_node2id.clear();
		d_id2node.clear();
		d_next_id = 0;

		d_node2id[addr] = d_next_id;
		d_id2node[d_next_id] = addr;
		return d_next_id++;
	}

	std::string get(uint16_t id)
	{
		std::string ret = "";
		auto it = d_id2node.find(id);
		if (it != d_id2node.end())
			ret = it->second;

		return ret;
	}

	void del(uint16_t id)
	{
		auto it = d_id2node.find(id);
		if (it != d_id2node.end()) {
			auto it2 = d_node2id.find(it->second);	// must exist
			d_node2id.erase(it2);
			d_id2node.erase(it);
		}
	}
};


extern std::map<std::string, int> tcp_nodes2sock, udp_nodes2sock;

}

#endif

