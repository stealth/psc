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

#include <sys/types.h>
#include <stdio.h>
#include <sys/time.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <termios.h>
#include <sys/ioctl.h>


extern struct termios exit_tattr;


namespace ns_psc {


void die(const char *s)
{
	char s_errno[256] = {0};
	if (errno)
		snprintf(s_errno, sizeof(s_errno) - 1, ":%s", strerror(errno));

	fprintf(stderr, "[%d] %s%s\n", getpid(), s, s_errno);
	tcsetattr(0, TCSANOW, &exit_tattr);
	exit(errno);
}



void fix_size(int fd)
{
	struct winsize win;

	if (ioctl(0, TIOCGWINSZ, (char*)&win) >= 0)
		ioctl(fd, TIOCSWINSZ, (char*)&win);
}

}

