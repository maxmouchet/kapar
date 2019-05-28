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

// $Id: ScamperInput.h,v 1.6 2015/09/11 21:34:51 kkeys Exp $

#ifndef SCAMPERINPUT_H
#define SCAMPERINPUT_H
#ifdef HAVE_SCAMPER

extern "C" {
#include "scamper_addr.h"
// #include "scamper_list.h"
// #include "scamper_trace.h"
// #include "scamper_ping.h"
#include "scamper_file.h"
}

static inline ip4addr_t scamper_to_ip4addr(const scamper_addr_t * const addr) {
    return ip4addr_t(*(struct in_addr*)addr->addr);
}

static inline ostream& operator<< (ostream& out, const scamper_addr_t * const addr) {
    out << inet_ntoa(*(struct in_addr*)addr->addr);
    return out;
}

class ScamperInput {
    scamper_file_t *sfile;
    scamper_file_filter_t *filter;
public:
    ScamperInput(InFile &in, const uint16_t *type) {
	int fd;
	if ((fd = dup(in.fd())) < 0) {
	    std::cerr << "can't dup " << in.name << ": " << strerror(errno) << std::endl;
	    exit(1);
	}
	if (!(sfile = scamper_file_openfd(fd, const_cast<char*>(in.name), 'r',
	    const_cast<char*>("warts"))))
	{
	    std::cerr << "can't read " << in.name << ": " << strerror(errno) << std::endl;
	    exit(1);
	}
	if (!(filter = scamper_file_filter_alloc(const_cast<uint16_t*>(type), 1))) {
	    std::cerr << "could not allocate scamper filter" << std::endl;
	    exit(1);
	}
    }
    ~ScamperInput() {
	scamper_file_close(sfile);  sfile = 0;
	scamper_file_filter_free(filter);  filter = 0;
    }
    int read(uint16_t *type, void** obj) {
	return scamper_file_read(sfile, filter, type, obj);
    }
};

#endif

#endif // SCAMPERINPUT_H
