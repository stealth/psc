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


void die(const char *s)
{
	fprintf(stderr, "[%d] %s: %s\n", getpid(), s, strerror(errno));
	tcsetattr(0, TCSANOW, &exit_tattr);
	exit(errno);
}



void fix_size(int fd)
{
	struct winsize win;

	if (ioctl(0, TIOCGWINSZ, (char*)&win) >= 0)
		ioctl(fd, TIOCSWINSZ, (char*)&win);
}

static const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


/* The base64 routines have been taken from the Samba 3 source (GPL)
 * and have been slightly modified */
/* expects enough space in buf */
size_t b64_decode(const char *s, unsigned char *buf)
{
	int bit_offset, byte_offset, idx, i, n;
	unsigned char *d = buf;
	const char *p;

	n=i=0;

	while (*s && (p=strchr(b64,*s))) {
		idx = (int)(p - b64);
		byte_offset = (i*6)/8;
		bit_offset = (i*6)%8;
		d[byte_offset] &= ~((1<<(8-bit_offset))-1);
		if (bit_offset < 3) {
			d[byte_offset] |= (idx << (2-bit_offset));
			n = byte_offset+1;
		} else {
			d[byte_offset] |= (idx >> (bit_offset-2));
			d[byte_offset+1] = 0;
			d[byte_offset+1] |= (idx << (8-(bit_offset-2))) & 0xFF;
			n = byte_offset+2;
		}
		s++; i++;
	}

	if (*s == '=') n -= 1;

	return n;
}


char *b64_encode(const char *s, size_t len, unsigned char *buf)
{
	int bits = 0;
	int char_count = 0;
	size_t out_cnt = 0;
	unsigned char *result = buf;

	while (len--) {
		int c = (unsigned char) *(s++);
		bits += c;
		char_count++;
		if (char_count == 3) {
			result[out_cnt++] = b64[bits >> 18];
			result[out_cnt++] = b64[(bits >> 12) & 0x3f];
			result[out_cnt++] = b64[(bits >> 6) & 0x3f];
	    		result[out_cnt++] = b64[bits & 0x3f];
		    	bits = 0;
		    	char_count = 0;
		} else	{
	    		bits <<= 8;
		}
    	}
	if (char_count != 0) {
		bits <<= 16 - (8 * char_count);
		result[out_cnt++] = b64[bits >> 18];
		result[out_cnt++] = b64[(bits >> 12) & 0x3f];
		if (char_count == 1) {
			result[out_cnt++] = '=';
			result[out_cnt++] = '=';
		} else {
			result[out_cnt++] = b64[(bits >> 6) & 0x3f];
			result[out_cnt++] = '=';
		}
	}
	result[out_cnt] = '\0';	/* terminate */
	return reinterpret_cast<char *>(result);
}


