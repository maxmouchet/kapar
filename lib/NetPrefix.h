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

// $Id: NetPrefix.h,v 1.12 2015/09/18 19:20:08 kkeys Exp $

#ifndef NETPREFIX_H
#define NETPREFIX_H

// A network prefix
struct NetPrefix {
    ip4addr_t addr;
    uint8_t len;
    NetPrefix(ip4addr_t a, uint8_t l) : addr(netPrefix(a, l)), len(l) { }
    NetPrefix(const NetPrefix &s) : addr(s.addr), len(s.len) { }
    NetPrefix &enlarge(int n = 1) {
	len -= n;
	addr = netPrefix(addr, len);
	return *this;
    }
    bool operator== (const NetPrefix &b) const {
	return addr == b.addr && len == b.len;
    }
    bool contains(ip4addr_t _addr) const { return netPrefix(_addr, len) == addr; }
};

inline std::ostream& operator<< (std::ostream &out, const NetPrefix &s) {
    return out << s.addr << '/' << int(s.len);
}

namespace std {
template<> struct less<NetPrefix> {
    bool operator()(const NetPrefix &a, const NetPrefix &b) const {
	return (a.addr != b.addr) ? (a.addr < b.addr) : (a.len < b.len);
    }
};
}

struct NetPrefixSet : public std::set<NetPrefix> {
    void install(const std::string &str, uint8_t l) {
	insert(NetPrefix(ip4addr_t(str), l));
    }
    void installStdBogons() {
	// initialize standard bogons.  See RFC 5735.
	install("0.0.0.0",       8); // this network (RFC1122)
	install("10.0.0.0",      8); // private (RFC1918)
	install("127.0.0.0",     8); // loopback (RFC1122)
	install("169.254.0.0",  16); // link local (RFC3330)
	install("172.16.0.0",   12); // private (RFC1918)
	install("192.0.0.0",    24); // protocols (RFC5736)
	install("192.0.2.0",    24); // TEST-NET-1(RFC1166)
	install("192.168.0.0",  16); // private (RFC1918)
	install("198.18.0.0",   15); // benchmark (RFC2544)
	install("198.51.100.0", 24); // TEST-NET-2 (RFC5737)
	install("203.0.113.0",  24); // TEST-NET-3 (RFC5737)
	install("224.0.0.0",     4); // 224/8 - 239/8 multicast (RFC3171)
	install("240.0.0.0",     4); // 240/8 - 255/8 reserved (RFC1112)
    }

    void load(const char *filename)
    {
	char buf[8192];
	const char *addrStr, *lenStr;
	char *tail;

	InFile in(filename);
	while (in.gets(buf, sizeof(buf))) {
	    try {
		if (buf[0] == '#' || buf[0] == '\n') continue; // comment or empty
		addrStr = strtok(buf, "/");
		lenStr = strtok(NULL, "\n");
		if (!addrStr || !lenStr) {
		    throw std::runtime_error("syntax error; expected \"<IPaddr>/<len>\"");
		}
		int len = strtol(lenStr, &tail, 10);
		if (tail == lenStr || *tail || len < 0 || len > 32) {
		    throw std::runtime_error(std::string("invalid prefix length \"") +
			lenStr + "\"");
		}

		NetPrefix key(ip4addr_t(addrStr), len);
		const_iterator it = this->upper_bound(key);
		if (it != this->begin() && (*--it).contains(key.addr)) {
		    // std::cerr << "## prefix " << key << " already contained by " << (*it) << std::endl; // XXX
		    continue;
		}

		std::pair<NetPrefixSet::iterator, bool> result;
		NetPrefixSet::iterator next;
		result = this->insert(NetPrefix(ip4addr_t(addrStr), len));
		// std::cerr << "## inserted prefix " << (*result.first) << std::endl; // XXX
		// delete smaller prefixes contained by the new prefix
		while (true) {
		    next = result.first;
		    ++next;
		    if (next == this->end()) break;
		    if (!(*result.first).contains((*next).addr)) break;
		    // std::cerr << "## erasing smaller prefix " << (*next) << std::endl; // XXX
		    this->erase(next);
		}
	    } catch (const std::runtime_error &e) { throw InFile::Error(in, e); }
	}
	in.close();
    }
};

#endif // NETPREFIX_H
