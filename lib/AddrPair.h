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
 * UNORDERED pair (i.e., set of size 2) of IPv4 addresses.
 */

#ifndef ADDRPAIR_H
#define ADDRPAIR_H

#include "ip4addr.h"

struct AddrPair {
    ip4addr_t addr[2];
    AddrPair(ip4addr_t a, ip4addr_t b) {
        if (a < b) {
            addr[0] = a;
            addr[1] = b;
        } else {
            addr[0] = b;
            addr[1] = a;
        }
    }
    bool operator< (const AddrPair &b) const {
        return (this->addr[0] != b.addr[0]) ? (this->addr[0] < b.addr[0]) :
            (this->addr[1] < b.addr[1]);
    }
};

std::ostream& operator<< (std::ostream& out, const AddrPair& ap) {
    return out << ap.addr[0] << " " << ap.addr[1];
}

#endif // ADDRPAIR_H
