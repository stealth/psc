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

#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#endif
#include "pty.h"
#include <sys/types.h>
#include <cstdio>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <string>
#include <cstring>

#ifdef __sun__
#include <sys/ioctl.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#endif

namespace ns_psc {


pty98::pty98(const pty98 &rhs)
	: pty(rhs)
{
}

pty98 &pty98::operator=(const pty98 &rhs)
{
	pty::operator=(rhs);
	return *this;
}

int pty98::open()
{
#ifdef HAVE_UNIX98
	m = "/dev/ptmx";

	if ((_master = ::open(m.c_str(), O_RDWR|O_NOCTTY)) < 0) {
		serr = strerror(errno);
		return -1;
	}
	if (grantpt(_master) < 0) {
		::close(_master);
		serr = strerror(errno);
		return -1;
	}

	unlockpt(_master);
#ifdef __linux__
	char buf[1024];
	memset(buf, 0, sizeof(buf));
	ptsname_r(_master, buf, sizeof(buf));
	s = buf;
#else
	s = ptsname(_master);
#endif

	if ((_slave = ::open(s.c_str(), O_RDWR|O_NOCTTY)) < 0) {
		::close(_master);
		serr = strerror(errno);
		return -1;
	}
#ifdef __sun__
	ioctl(_slave, I_PUSH, "ptem");
	ioctl(_slave, I_PUSH, "ldterm");
	ioctl(_slave, I_PUSH, "ttcompat");
#endif

	fchmod(_slave, 0600);
#endif
	return 0;
}

}

