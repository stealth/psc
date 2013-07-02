/*
 * This file is part of port shell crypter (psc).
 *
 * (C) 2006-2013 by Sebastian Krahmer,
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

#ifndef __pty_h__
#define __pty_h__

#include <sys/types.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <unistd.h>
#include <string>

using namespace std;

// A BSD 4.3+ PTY API.
class pty {
protected:
	// file-descriptors for terminal
	int _master, _slave;

	// names of device-files
	string m, s, serr;
public:
	pty() : _master(-1), _slave(-1), m(""), s(""), serr("") {}


	virtual ~pty() { close(); }

	// Copy-constructor
	pty(const pty &rhs);

	// Assign-operator
	pty &operator=(const pty &rhs);

	// open master+slave terminal
	virtual int open();

	// close both
	int close();

	int master() { return _master; }

	int slave() { return _slave; }

	string mname() { return m; }

	string sname() { return s; }

	// do chown
	int grant(uid_t, gid_t, mode_t);

	const char* why();
};

class pty98 : public pty {
public:
	pty98() : pty() {}

	virtual ~pty98() {}


	pty98(const pty98 &);

	pty98 &operator=(const pty98 &);

	virtual int open();
};


#endif
