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

#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <stdlib.h>
#include <cstdio>
#include <string.h>
#include <unistd.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include <vector>
#include <set>
#include <algorithm>
#include <new>
#include <string>
#include <exception>
#include <stdexcept>
#include <cstdarg>

#include "infile.h"
#include "ip4addr.h"

#ifdef HAVE_SCAMPER
extern "C" {
#include "scamper_addr.h"
// #include "scamper_list.h"
// #include "scamper_trace.h"
// #include "scamper_ping.h"
#include "scamper_file.h"
}
#endif

using namespace std;

#include "ScamperInput.h"
#include "PathLoader.h"

const char *PathLoader::cvsID = "$Id: PathLoader.cc,v 1.29 2017/09/13 17:11:14 kkeys Exp $";

int PathLoader::processTrace(const ip4addr_t *hops, int n_hops, ip4addr_t src, ip4addr_t dst, void *strace)
{
    if (grep_dst != 0 && dst != grep_dst)
	return 0;

    ++n_branches;

    if (handler->debug) {
	handler->warn << "### " << n_good_traces << " hops:";
	for (int j = 0; j < n_hops; ++j)
	    handler->warn << " " << hops[j];
	handler->warn << "\n";
    }

    if (n_hops <= 0 || n_hops > MAXHOPS) {
	handler->warn << "#" << filename << ':' << linenum <<
	    ": hop count " << n_hops << " outside range [1," << MAXHOPS << "]" << endl;
	++n_discarded_traces;
	return 0;
    }

    handler->badHead = handler->badTail = 0;
    if (!raw) {
	// discard trailing bad hops
	while (n_hops > 1 && handler->isBadHop(hops, n_hops, n_hops-1)) {
	    ++handler->badTail;
	    --n_hops;
	}
	// discard leading bad hops
	while (n_hops > 1 && handler->isBadHop(hops, n_hops, 0)) {
	    ++handler->badHead;
	    ++hops;
	    --n_hops;
	}

#if 0
	if (n_hops < 3) {
	    handler->warn << "# " << src << " -> " << dst <<
		": only " << n_hops << " remain after discarding bad hops" << endl;
	    ++n_discarded_traces;
	    return 0;
	}
#endif
    }

    handler->preprocessHops(hops, n_hops, strace);

    // check for loops
    if (!raw) {
	for (int i = 0; i < n_hops - 1; i++) {
	    for (int j = n_hops - 1; j > i; j--) {
		if (hops[i] != ip4addr_t(0) && handler->hopsAreEqual(hops, n_hops, i, j)) {
		    if (handler->debug) handler->warn << "# trace " << n_raw_traces << ": hops " << i << " (" << hops[i] << ") and " << j << " (" << hops[j] << ") form a loop\n";
		    ++n_loops;
		    if (loop_discard) {
			++n_discarded_traces;
			return 0;
		    } else if (loop_after) {
			// split trace into segment before loop and segment after loop
			return handler->processHops(hops, i+1, src, dst, strace) +
			    handler->processHops(hops+j, n_hops-j, src, dst, strace);
		    } else {
			// truncate trace at loop
			n_hops = i+1;
			goto end_loop_check;
		    }
		}
	    }
	}
    }
    end_loop_check:

    return handler->processHops(hops, n_hops, src, dst, strace);
}

// Trace that can contain multiple responses at each hop
class MultiTrace {
public:
    int n_hops;
    ip4addr_t src;
    ip4addr_t dst;
    vector<ip4addr_t> hops[MAXHOPS];
    void truncate(int n = 0) {
	while (n_hops > n)
	    hops[--n_hops].clear();
    }
};

int PathLoader::processMultiTraceTail(const MultiTrace *mtrace, ip4addr_t *hops,
    int hoff, // offset into hops[]
    int moff, // offset into mtrace->hops[]
    void *strace) // scamper trace
{
    int n_traces = 0;

tailRecurse:
    if (moff == mtrace->n_hops) {
	// end of trace
	return n_traces + processTrace(hops, hoff, mtrace->src, mtrace->dst, strace);
    }

    // Because MultiTraces may contain multiple responses at the same hop,
    // we try every address at this hop combined with the remaining tail.
    // (This is not very efficient, but the case is not very common.)
    for (size_t hi = 0; hi < mtrace->hops[moff].size(); hi++) {
	const ip4addr_t &hop = mtrace->hops[moff][hi];
	if (hop == mtrace->dst) {
	    hops[hoff] = hop;
	    if (handler->debug) handler->warn << "### k.hop " << hoff+1 << ": " << hops[hoff] << "\n";
	    n_traces += processTrace(hops, include_dst ? hoff+1 : hoff,
		mtrace->src, mtrace->dst, strace);
	    if (handler->debug) handler->warn << "### REACHED DESTINATION " << mtrace->dst << "\n";
	    continue;
	} else {
	    hops[hoff] = hop;
	    if (handler->debug) handler->warn << "### k.hop " << hoff+1 << ": " << hops[hoff] << "\n";
	}
	if (hi == mtrace->hops[moff].size() - 1) {
	    ++moff;
	    ++hoff;
	    goto tailRecurse; // optimization
	} else {
	    n_traces += processMultiTraceTail(mtrace, hops, hoff+1, moff+1, strace);
	}
    }
    return n_traces;
}

int PathLoader::processMultiTrace(MultiTrace *mtrace, void *strace)
{
    uint64_t comb = 1;
    size_t maxuniq = 0;
    const int uniqLimit = 3;
    for (int i = 0; i < mtrace->n_hops; i++) {
	if (mtrace->hops[i].size() > uniqLimit) {
	    handler->warn << "# multiresponse at " << mtrace->src << " -> " <<
		mtrace->dst << ": ";
	    handler->warn << mtrace->hops[i].size() << " unique responses at hop " << i+1 <<
		", truncating" << endl;
	    mtrace->truncate(i);
	    break; // can't trust this or later hops; truncate here
	}
	if (maxuniq < mtrace->hops[i].size())
	    maxuniq = mtrace->hops[i].size();
	comb *= mtrace->hops[i].size();
    }

    if (maxuniq > 1) {
	handler->warn << "# multiresponse at " << mtrace->src << " -> ";
	handler->warn << mtrace->dst << ": ";
	handler->warn << maxuniq << " max unique responses, ";
	handler->warn << comb << " combinatorial paths." << endl;
    }
    if (comb > 10) {
	handler->warn << "# ignoring multiresponse path" << endl;
	return 0;
    }

    ip4addr_t hops[MAXHOPS]; // temp array of hop addresses
    int hoff = 0;
    if (include_src)
	hops[hoff++] = mtrace->src;
    return processMultiTraceTail(mtrace, hops, hoff, 0, strace);
}

#ifdef HAVE_SCAMPER
#include "ScamperInput.h"

int PathLoader::processScamperTrace(scamper_trace_t *strace)
{
    if (strace->hop_count > MAXHOPS) {
	++n_discarded_traces;
	handler->warn << "#" << filename << ':' << linenum << ": too many hops (" <<
	    strace->hop_count << ")" << endl;
	return 0;
    }

    if (handler->debug) {
	handler->warn << "### scamper path to " << strace->dst << ":\n";
	for (int j = 0; j < strace->hop_count; ++j) {
	    handler->warn << "### s.hop " << j+1 << ":";
	    for (scamper_trace_hop_t *h = strace->hops[j]; h; h = h->hop_next)
		handler->warn << " " << h->hop_addr;
	    handler->warn << "\n";
	}
    }

    // First check for:
    // * duplicate reponses at same hop, and delete the duplicates
    // * any different responses at same attempt at same hop, and truncate trace
    int hop_count = strace->hop_count;
    for (int i = 0; i < strace->hop_count; ++i) {
	scamper_trace_hop_t *hi, **hjp;
	for (hi = strace->hops[i]; hi; hi = hi->hop_next) {
	    if (!hi->hop_addr) continue;
	    for (hjp = &hi->hop_next; *hjp; ) {
		if (scamper_addr_cmp(hi->hop_addr, (*hjp)->hop_addr) == 0) {
		    // duplicate address; drop it
		    scamper_trace_hop_t *dead = *hjp;
		    *hjp = (*hjp)->hop_next;
		    scamper_trace_hop_free(dead);
		} else if (hi->hop_probe_id == (*hjp)->hop_probe_id) {
		    // different responses for same attempt; can't be trusted
		    handler->warn << "# multiresponse at " << strace->src << " -> " <<
			strace->dst << ": ";
		    handler->warn << "different responses at hop " << i+1 << " attempt "
			<< int(hi->hop_probe_id) << ", truncating" << endl;
		    hop_count = i;
		    goto end_scan;
		} else {
		    hjp = &(*hjp)->hop_next;
		}
	    }
	}
    }
  end_scan:

    // if (handler->debug) handler->warn << "### kapar path to " << strace->dst << ":\n";

    {
	scamper_trace_hop_t *hi;
	int soff; // offset into strace->hops[]

	static MultiTrace mtrace;
	mtrace.truncate();
	mtrace.src = scamper_to_ip4addr(strace->src);
	mtrace.dst = scamper_to_ip4addr(strace->dst);
	mtrace.n_hops = hop_count;

	for (soff = 0; soff < hop_count; soff++) {
	    mtrace.hops[soff].clear();
	    if (!strace->hops[soff]) {
		// no responses at this hop; create an anonymous interface
		mtrace.hops[soff].push_back(ip4addr_t(0)); // anonymous
		if (handler->debug) handler->warn << "### hop " << soff+1 << ": " << mtrace.hops[soff].back() << "\n";
	    } else {
		for (hi = strace->hops[soff]; hi; hi = hi->hop_next) {
		    if (scamper_addr_cmp(hi->hop_addr, strace->dst) == 0 || (SCAMPER_TRACE_HOP_IS_ICMP_TTL_EXP(hi))) {
			mtrace.hops[soff].push_back(scamper_to_ip4addr(hi->hop_addr));
		    } else {
			mtrace.hops[soff].push_back(ip4addr_t(0)); // anonymous
		    }
		    if (handler->debug) handler->warn << "### hop " << soff+1 << ": " << mtrace.hops[soff].back() << "\n";
		}
	    }
	}

	return processMultiTrace(&mtrace, strace);
    }
}
#endif

int PathLoader::load(const char *filename_)
{
    char buf[8192];
    ip4addr_t hops[MAXHOPS]; // temp array of hop addresses
    int n_hops = 0;
    int n_traces = 0; // number of traces in this file

    filename = filename_;
    linenum = 0;
    InFile in(filename);

    if (in.nameEndsWith(".warts")) {
#ifdef HAVE_SCAMPER
	// scamper file
	uint16_t type = SCAMPER_FILE_OBJ_TRACE;
	ScamperInput sin(in, &type);
	scamper_trace_t *strace;
	while (sin.read(&type, (void **)&strace) == 0) {
	    if (!strace) break; /* EOF */
	    handler->linenum++; // not actually a "line", but close enough
	    ++n_raw_traces;
	    n_branches = 0;
	    n_traces += processScamperTrace(strace);
	    scamper_trace_free(strace);
	}
#else
	handler->warn << "# error: " << in.name <<
	    ": this program was not compiled with the scamper library.\n";
	exit(1);

#endif

    } else
    if (strncmp(in.basename, "trace.out.", 10) == 0) {
	// iPlane file (http://iplane.cs.washington.edu/data/readoutfile.cc)
	int clientId, uniqueId, sz, len;
	while (1) {
	    if (in.read(&clientId, sizeof(int), 1) != 1) {
		break;
	    }
	    if (in.read(&uniqueId, sizeof(int), 1) != 1) {
		handler->warn << "# warning: " << in.name << ": incomplete\n";
		break;
	    }
	    if (in.read(&sz, sizeof(int), 1) != 1) {
		handler->warn << "# warning: " << in.name << ": incomplete\n";
		break;
	    }
	    if (in.read(&len, sizeof(int), 1) != 1) {
		handler->warn << "# warning: " << in.name << ": incomplete\n";
		break;
	    }

	    /* printf("read %d records (%d bytes) from %d %d\n", sz, len, clientId, uniqueId); */
	    for (int i=0; i<sz; i++) {
		struct in_addr dst;
		int ttl;
		if (in.read(&dst, sizeof(struct in_addr), 1) != 1) {
		    handler->warn << "# warning: " << in.name << ": incomplete\n";
		    goto done_iplane;
		}
		if (in.read(&n_hops, sizeof(int), 1) != 1) {
		    handler->warn << "# warning: " << in.name << ": incomplete\n";
		    goto done_iplane;
		}
		if (handler->debug) handler->warn << "# iPlane destination: " << inet_ntoa(dst) << ", hops: " << n_hops << '\n';
		for (int j=0; j<n_hops; j++) {
		    struct in_addr ip;
		    float rtt;
		    if (in.read(&ip, sizeof(struct in_addr), 1) != 1) {
			handler->warn << "# warning: " << in.name << ": incomplete\n";
			goto done_iplane;
		    }
		    hops[j] = ip4addr_t(ip);
		    if (in.read(&rtt, sizeof(float), 1) != 1) {
			handler->warn << "# warning: " << in.name << ": incomplete\n";
			goto done_iplane;
		    }
		    if (in.read(&ttl, sizeof(int), 1) != 1) {
			handler->warn << "# warning: " << in.name << ": incomplete\n";
			goto done_iplane;
		    }
		    if (ttl > 512) {
			handler->warn << "# error: " << in.name << " possibly corrupted\n";
			exit(1);
		    } else if (ttl > 512) {
			handler->warn << "# warning: trace " << n_traces << ", hop " << j << ": MPLS?\n";
		    }
		}
		++n_raw_traces;
		n_branches = 0;
		if (!include_dst && hops[n_hops-1] == ip4addr_t(dst))
		    n_hops--;
		n_traces += processTrace(hops, n_hops, ip4addr_t(0), ip4addr_t(dst), 0);
	    }
	}
done_iplane: ;

    } else {
	// text file
	static MultiTrace mtrace;
	char srcbuf[16], dstbuf[16];
	while (in.gets(buf, sizeof(buf))) {
	  try {
	    handler->linenum++;
	    if (buf[0] == '#') {
		++n_raw_traces;
		n_branches = 0;
		// process previous trace
		if (mtrace.n_hops > 0)
		    n_traces += processMultiTrace(&mtrace, 0);
		mtrace.truncate();
		// format example: "# trace 1.0: 129.186.1.240 -> 80.236.223.170"
		if (sscanf(buf, "# %*[^:]: %15[0-9.] -> %15[0-9.]", srcbuf, dstbuf) == 2) {
		    mtrace.src = ip4addr_t(srcbuf);
		    mtrace.dst = ip4addr_t(dstbuf);
		} else {
		    mtrace.src = mtrace.dst = ip4addr_t(0);
		}
	    } else {
		char *line = buf;
		char *token;
		if (mtrace.n_hops < MAXHOPS) {
		    while ((token = strtok(line, " \n"))) {
			ip4addr_t addr(token);
			auto &hop = mtrace.hops[mtrace.n_hops];
			if (std::find(hop.begin(), hop.end(), addr) == hop.end())
			    mtrace.hops[mtrace.n_hops].push_back(addr); // append, if not a duplicate
			line = NULL;
		    }
		}
		mtrace.n_hops++;
	    }
	  } catch (const std::runtime_error &e) { throw InFile::Error(in, e); }
	}
	// process last trace
	if (mtrace.n_hops > 0)
	    n_traces += processMultiTrace(&mtrace, 0);
    }

    in.close();
    return n_traces;
}
