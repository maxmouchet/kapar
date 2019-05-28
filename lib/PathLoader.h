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

// $Id: PathLoader.h,v 1.11 2017/09/11 18:21:21 kkeys Exp $

#ifndef PATHLOADER_H
#define PATHLOADER_H
static const int MAXHOPS = 90;

#ifdef HAVE_SCAMPER
extern "C" {
#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_trace.h"
}
#endif

class PathLoaderHandler {
public:
    ostream &warn;
    bool debug;
    int linenum;
    int badHead, badTail; // hack to send info from processTrace to processHops
    virtual void preprocessHops(const ip4addr_t *hops, int n_hops, void *strace) { }
    virtual int processHops(const ip4addr_t *hops, int n_hops, ip4addr_t src, ip4addr_t dst, void *strace) = 0;
    virtual bool isBadHop(const ip4addr_t *hops, int n_hops, int i) { return false; }
    virtual bool hopsAreEqual(const ip4addr_t *hops, int n_hops, int i, int j) {
	return hops[i] == hops[j];
    }
    PathLoaderHandler(ostream &warn_, bool debug_ = false) :
	warn(warn_), debug(debug_) {}
    virtual ~PathLoaderHandler() {}
};

class MultiTrace;

class PathLoader {
    int linenum;
    const char *filename;
public:
    static const char *cvsID;
    static const int MAXHOPS = 90;
    // config
    PathLoaderHandler *handler;
    bool raw; // if true, don't look for loops or bad hops
    bool loop_discard; // if true (and !raw), discard traces with loops
    bool loop_after; // if true (and !raw and !discard), keep segment after loop
    bool include_src; // include src addr? (always false for iplane input)
    bool include_dst; // include dst addr?
    ip4addr_t grep_dst;
    // stats
    int n_loops;
    int n_branches;		// number of branches in current raw trace
    int n_raw_traces;		// number of raw traces
    unsigned n_good_traces;	// number of traces (paths)
    int n_discarded_traces;
    // methods
    int load(const char *filename_);
private:
    int processTrace(const ip4addr_t *hops, int n_hops, ip4addr_t src, ip4addr_t dst, void *strace);
    int processMultiTraceTail(const MultiTrace *mtrace, ip4addr_t *hops,
	int hoff, int moff, void *strace);
    int processMultiTrace(MultiTrace *mtrace, void *strace);
#ifdef HAVE_SCAMPER
    int processScamperTrace(scamper_trace_t *strace);
#endif
};

#endif // PATHLOADER_H
