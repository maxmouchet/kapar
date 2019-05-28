/* 
 * Copyright (C) 2011-2018 The Regents of the University of California.
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 * IPv4 address.
 */

#ifndef IP4ADDR_H
#define IP4ADDR_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <iostream>
#include <stdexcept>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// IPv4 address, in host byte order
class ip4addr_t {
    uint32_t addr;
public:
    explicit ip4addr_t(uint32_t i = 0) : addr(i) { }
    explicit ip4addr_t(struct in_addr i) : addr(ntohl(i.s_addr)) { }
    ip4addr_t(uint32_t a, uint32_t b, uint32_t c, uint32_t d) :
	addr(((a)<<24) | ((b)<<16) | ((c)<<8) | (d)) { }
    explicit ip4addr_t(const std::string &str) {
	struct in_addr i;
	if (inet_pton(AF_INET, str.c_str(), &i) != 1)
	    throw std::runtime_error("invalid address \"" + str + "\"");
	addr = ntohl(i.s_addr);
    }
    operator uint32_t() const { return addr; }
    operator std::string() const {
	struct in_addr inaddr;
	inaddr.s_addr = htonl(addr);
	return std::string(inet_ntoa(inaddr));
    }
};

static std::ostream& operator<< (std::ostream& out, const ip4addr_t & addr) {
    struct in_addr inaddr;
    inaddr.s_addr = htonl(addr);
    out << inet_ntoa(inaddr);
    return out;
}

// return the len-bit prefix of addr
static inline ip4addr_t netPrefix(const ip4addr_t &addr, const uint8_t &len) {
    return ip4addr_t(addr & (0xFFFFFFFF << (32 - len)));
}

// return the maximum address in addr/len subnet (i.e., the broadcast addr)
static inline ip4addr_t maxAddr(const ip4addr_t &addr, const uint8_t &len) {
    return ip4addr_t(addr | (0xFFFFFFFF >> len));
}

#endif // IP4ADDR_H
