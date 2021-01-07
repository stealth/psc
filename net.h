#ifndef psc_net_h
#define psc_net_h

#include <map>
#include <string>
#include <poll.h>

#include "misc.h"


namespace ns_psc {


extern std::map<std::string, int> nodes2sock;

int tcp_listen(const std::string &, const std::string &);

int udp_listen(const std::string &, const std::string &);

int cmd_handler(const std::string &, state *, pollfd *);

}

#endif

