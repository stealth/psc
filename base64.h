/*
 * This file is part of the number framework.
 *
 * (C) 2018 by Sebastian Krahmer,
 *             sebastian [dot] krahmer [at] gmail [dot] com
 *
 * number is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * number is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with number.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef psc_base64_h
#define psc_base64_h

#include <sys/types.h>
#include <string>

namespace ns_psc {

std::string &b64_encode(const std::string&, std::string&);

std::string &b64_decode(const std::string&, std::string&);

std::string &b64_encode(const char *, size_t, std::string&);

std::string &b64_decode(const char *, size_t, std::string&);


}

#endif

