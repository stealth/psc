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

	CLOSING_TIME		=	10,
	CONNECT_TIME		=	30,
	UDP_CLOSING_TIME	=	120,

	MTU			=	1500,
	BLOCK_SIZE		=	2*MTU
};

struct state {
	time_t time{0};
	int fd{-1};
	int state{STATE_INVALID};
	std::string obuf{""}, rnode{""};

	// must only be pushed/popped in pairs. Each reply datagram needs a port on 127.0.0.1
	// where it is sent to
	std::deque<std::string> odgrams;
	std::deque<uint16_t> ulports;
};

}

namespace config {

extern std::map<std::string, std::string> tcp_listens, udp_listens;

}

#endif


