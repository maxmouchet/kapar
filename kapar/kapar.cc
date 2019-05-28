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
 * Run "kapar -?" for help.
 *
 * Resolves router interface aliases using a highly modified version of the
 * APAR algorithm described by Mehmet H. Gunes and Kamil Sarac, "Resolving IP
 * Aliases in Building Traceroute-Based Internet Maps".
 *
 * Changes/improvments:
 * - massive optimizations, including not storing complete paths in memory,
 *   make this implementation practical to use on entire Internet scales.
 * - address extraction mode
 * - many behavior options
 * - can output complete (hyper)graph, i.e. (hyperedge) links and nodes
 */

static const char *cvsID = "$Id: kapar.cc,v 1.175 2017/08/31 17:24:33 kkeys Exp $";

#include "../lib/config.h"
#include "config.h"

#define debugpath sink
// #define debugpath out_log

#define debugsubnet sink
// #define debugsubnet out_log

#define debugalias sink
// #define debugalias out_log

#define debuglink sink
// #define debuglink out_log

#define debuganon sink
// #define debuganon out_log

#define debugttl sink
// #define debugttl out_log

// #define debugbrief sink
#define debugbrief out_log

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
#include <cstdarg>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include <vector>
#include <set>
#include <map>

#include "../lib/unordered_set.h"

#include <algorithm>
#include <new>
#include <string>
#include <exception>
#include <stdexcept>

#include "../lib/infile.h"
#include "../lib/ip4addr.h"
#include "../lib/ivector.h"
#include "../lib/Pool.h"
#include "../lib/NetPrefix.h"

#ifdef HAVE_SCAMPER
extern "C" {
#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_trace.h"
#include "scamper_file.h"
}
#endif

using namespace std;

#define NO_DEBUG_MEMORY 0
#include "../lib/MemoryInfo.h"
MemoryInfo memoryInfo;

ofstream out_log;
ofstream out_aliases;
ofstream out_links;
ofstream out_ifaces;
ofstream out_subnets;
ofstream out_addrs;
ofstream out_missing;
#if 0
ofstream out_ptp;
#endif

const class Sink : public ostream { public: Sink() {} } sink;
template<class T>
inline const Sink& operator<< (const Sink& out, const T&) { return out; }


struct Cfg {
    time_t start_time;
    vector<const char*> bogonFiles;
    vector<const char*> aliasFiles;
#ifdef ENABLE_TTL
    vector<const char*> ttlFiles;
#endif
    vector<const char*> ifaceFiles;
    vector<const char*> traceFiles;
    char filetype;
    int n_ttls;			// number of TTL vantage points
    int min_subnet_middle_required; // min pfx len for which middles are req'd
    int minsubnetlen;           // minimum length of subnet prefix
    bool s30_beats_s31;		// when ranking subnets, /30 is higher than /31
    bool ttl_beats_subnet;
    bool ttl_beats_inferred_alias;
    bool ttl_beats_loaded_alias;
    bool alias_subnet_verify;
    bool markNonP2P;
    bool negativeAlias;
    bool subnet_verify;
    bool subnet_inference;
    bool subnet_len;
    bool subnet_rank;
    bool oneloop_anon;
    bool bug_rev_anondup;
    bool bug_pprev;
    bool bug_rank;
    bool bug_broadcast;
    bool bug_BE_link;
    bool bug_anon_BE_link;
    bool bug_swap_dstlink;
    bool anon_ignore;
    bool anon_dups;
    bool anon_match;
    bool anon_shared_nodelink;
    bool mode_extract;
    bool infer_aliases;
    bool infer_links;
    bool output_aliases;
    bool output_links;
    bool output_ifaces;
    bool output_subnets;
    bool include_dst;
    bool include_dst_explicit;
    bool need_traceids;
    bool dump_ptp_mates;
    char *output_basename;
    bool setFile(const char *filename);
    int pfxlen;
    float mincompleteness;
private:
    void setOneFile(const char *filename);
} cfg;

void Cfg::setOneFile(const char *filename)
{
    switch (this->filetype) {
    case 'B':
	this->bogonFiles.push_back(filename);
	break;
#ifdef ENABLE_TTL
    case 'D':
	this->ttlFiles.push_back(filename);
	++this->n_ttls;
	break;
#endif
    case 'A':
	this->aliasFiles.push_back(filename);
	break;
    case 'I':
	this->ifaceFiles.push_back(filename);
	break;
    case 'P':
	this->traceFiles.push_back(filename);
	break;
    default:
	break;
    }
}

bool Cfg::setFile(const char *filename)
{
    if (!this->filetype) return false;
    if (filename[0] == '@') {
	InFile filelist(filename+1);
	char buf[PATH_MAX];
	while (filelist.gets(buf, sizeof(buf))) {
	    strtok(buf, "\n");
	    setOneFile(strdup(buf));
	}
	filelist.close();
    } else {
	setOneFile(filename);
    }
    return true;
}

static const int MINSUBNETLEN = 24;
static const float MINCOMPLETENESS = 0.5;
static const int MAX_DISTANCE = 1;

typedef uint32_t TraceID;

struct Iface; // forward declaration

static inline bool isAnon(const ip4addr_t &addr); // forward declaration
bool addr_less_than(const ip4addr_t &a, const ip4addr_t &b) {
    // An anon addr is always less than a named addr (for easier comparison of
    // code that uses different AnonIface::PREFIX)
    return (isAnon(a) == isAnon(b)) ? (a < b) : isAnon(a);
}

// an N-hop segment of a path (trace)
template <int N>
class PathSeg {
public:
    ip4addr_t hops[N];		// N sequential interface addrs seen in a path
    PathSeg(const ip4addr_t &a, const ip4addr_t &b) { hops[0]=a; hops[1]=b; }
    explicit PathSeg(const ip4addr_t &a) { hops[0]=a; }
    ip4addr_t const &hop(int i) const { return hops[i]; }
    bool operator== (const PathSeg& b) const {
	if (this->hop(0) != b.hop(0)) return false;
	if (N > 1)
	    if (this->hop(1) != b.hop(1)) return false;
	return true;
    }
    bool operator!= (const PathSeg& b) const { return !(*this == b); }
};

template <int N>
struct pathseg_less_than {
    bool operator()(const PathSeg<N> &a, const PathSeg<N> &b) const {
	return (a.hop(0) != b.hop(0)) ? addr_less_than(a.hop(0), b.hop(0)) :
	    (N>1 && a.hop(1) != b.hop(1)) ? addr_less_than(a.hop(1), b.hop(1)) :
	    false;
    }
};

template <int N>
class PathSegVec : public ivector<uint32_t, PathSeg<N> > { };

#ifdef ENABLE_TTL
// an array of TTL values
class ttlVec {
    // The first <n_ttls> BYTES in <data> are (possibly unset) TTL values.
    // The next <n_ttls> PAIRS OF BITS in <data> indicate which TTLs are
    // actually set and valid.
    static const uint8_t SET = 0x1, VALID = 0x2;
    uint8_t *data;
    int flagssize() const { return (cfg.n_ttls*2+7)/8; }
    uint8_t &flagdata(const int &i) const { return data[cfg.n_ttls + i/4]; }
    uint8_t mask(int i, uint8_t value) const { return (value << ((i%4)*2)); }
    int datasize() const { return cfg.n_ttls + flagssize(); }
    ttlVec(const ttlVec &that); // copy ctor - private to prevent accidental use
public:
    ttlVec() : data(0) {}
    ~ttlVec() { if (data) delete[] data; }
    void clear()
	{ for (int i = cfg.n_ttls; i < datasize(); ++i) data[i] = 0; }
    void free() { if (data) delete[] data; data = 0; }
    bool empty() const { return !data; }
    void alloc() { data = new uint8_t[datasize()](); clear(); }
    void alloc_if_needed() { if (!data) alloc(); }
    bool isSet(int i) const { return data && (flagdata(i) & mask(i, SET)); }
    bool isValid(int i) const { return data && (flagdata(i) & mask(i, VALID)); }
    short get(int i, short unset = -1, short invalid = -2) const
	{ return !isSet(i) ? unset : !isValid(i) ? invalid : data[i]; }
    short set(int i, uint8_t ttl) {
	alloc_if_needed();
	flagdata(i) |= mask(i, SET|VALID);
	return data[i] = ttl;
    }
    void invalidate(int i) {
	alloc_if_needed();
	flagdata(i) &= ~mask(i, VALID);
    }
    ttlVec &operator= (const ttlVec &that) {
	if (data) delete[] data;
	data = new uint8_t[datasize()]();
	copy(that.data, that.data + datasize(), this->data);
	return *this;
    }
    void mergeMin(const ttlVec &b) {
	for (int i = 0; i < cfg.n_ttls; ++i) { // set TTLs
	    if (this->isValid(i) && b.isValid(i)) {
		if (b.data[i] < this->data[i]) this->data[i] = b.data[i];
	    } else if (b.isValid(i)) {
		this->data[i] = b.data[i];
	    }
	}
	for (int i = cfg.n_ttls; i < datasize(); ++i) // set flags
	    this->data[i] |= b.data[i];
    }
    void mergeMax(const ttlVec &b) {
	for (int i = 0; i < cfg.n_ttls; ++i) { // set TTLs
	    if (this->isValid(i) && b.isValid(i)) {
		if (b.data[i] > this->data[i]) this->data[i] = b.data[i];
	    } else if (b.isValid(i)) {
		this->data[i] = b.data[i];
	    }
	}
	for (int i = cfg.n_ttls; i < datasize(); ++i) // set flags
	    this->data[i] |= b.data[i];
    }
    void swap(ttlVec &that) { std::swap(this->data, that.data); debugttl << "# swap ttls\n"; }
};

inline void swap(ttlVec &a, ttlVec &b) { a.swap(b); }

ostream& operator<< (ostream& out, const ttlVec& ttlvec) { // for debugging
    if (ttlvec.empty()) {
	out << "\t(empty)";
    } else {
	for (int i = 0; i < cfg.n_ttls; ++i) { out << "\t" << ttlvec.get(i); }
    }
    return out;
}
#endif

// A set of nonnegative integers with a vector-like interface, but more
// compact storage of clusters of nearby values.
#define TEST_TRACEIDSET 0
class CompactIDSet {
    // Storage is basically a vector of integers, but if an element has FLAG
    // set, it is a bitvector of 31 possible values following the previous
    // element.  There can be up to MAX bitvectors in a row.
    typedef ivector<uint32_t, TraceID> idvector;
    idvector data;
#if TEST_TRACEIDSET
    vector<TraceID> backup;
#endif
    static int64_t _totalSize;
    static int64_t _totalSlots;
    static const uint32_t FLAG = 0x80000000;
    static const uint32_t MASK = 0x7fffffff;
    static const int MAX = 33;
public:
    CompactIDSet() : data(0) {}
    static int64_t totalSize() { return _totalSize; }
    static int64_t totalSlots() { return _totalSlots; }
    void append(TraceID id) {
#if TEST_TRACEIDSET
	backup.push_back(id);
#endif
	++_totalSize;
	int sz = data.size();
	if (sz > 1) {
	    int dist;
	    if (data[sz-1] & FLAG) {
		int start = sz-2;
		// search back for initial integer element
		while (data[start] & FLAG)
		    --start;
		dist = id - data[start];
		if (dist <= 31 * (sz - start - 1)) {
		    // add id to existing bitvector
		    data[sz-1] |= 1 << ((dist-1) % 31);
		    return;
		} else if ((sz - start < MAX) && (dist < 31 * (sz - start))) {
		    // add id to new bitvector
		    data.push_back(FLAG | (1 << ((dist-1) % 31)));
		    ++_totalSlots;
		    return;
		}
	    } else if (!(data[sz-2] & FLAG)) {
		// last two entries are not bitvectors
		dist = id - data[sz-2];
		if (dist <= 31) {
		    // convert last element to bitvector and add id
		    uint32_t bits = 1 << (dist-1);
		    dist = data[sz-1] - data[sz-2];
		    bits |= 1 << (dist-1);
		    data[sz-1] = FLAG | bits;
		    return;
		}
	    }
	}
	data.push_back(id);
	++_totalSlots;
#if TEST_TRACEIDSET
	{
	    int val = 0, start = 0;
	    size_t bi = 0;
	    TraceID n;
	    static int call = 0;
	    call++;
	    for (size_t i = 0; i < data.size(); ++i) {
		if (!(data[i] & FLAG)) {
		    start = i;
		    val = data[i];
		    n = data[i];
		    if (backup[bi++] != n)
			out_log << "# ERROR mismatch in call " << call << endl;
		} else {
		    uint32_t bits = data[i] & MASK;
		    for (int j = 0; bits; ++j, bits = bits>>1) {
			if (bits & 0x1) {
			    n = (val + (i-start-1) * 31 + j + 1);
			    if (backup[bi++] != n)
				out_log << "# ERROR mismatch in call " << call << endl;
			}
		    }
		}
	    }
	    if (bi != backup.size())
		out_log << "# ERROR mismatch in call " << call << endl;
	}
#endif
    }
    uint32_t rawsize() const {
	return data.size();
    }
    bool empty() const {
	return data.empty();
    }
    uint32_t size() const {
	if (data.empty()) return 0;
	idvector::const_iterator i;
	uint32_t n = 0;
	for (i = data.begin(); i != data.end(); ++i) {
	    if (*i & FLAG) {
		for (uint32_t bits = *i & MASK; bits; bits = bits >> 1) {
		    n += (bits & 0x1);
		}
	    } else {
		++n;
	    }
	}
	return n;
    }
    bool overlaps(const CompactIDSet &b) const;
    void free(bool corrupt = false) {
	data.free(corrupt);
    }

    struct IdvectorWalker {
	const idvector &vec;
	size_t i; // position of current element
	size_t start; // position of last integer element
	TraceID val; // value of last integer element
	bool is_int;
	IdvectorWalker(const idvector &_vec) : vec(_vec), i(0), start(0), val(_vec[0]), is_int(true) {}
	void increment() {
	    i++;
	    if (i < vec.size() && (is_int = !(vec[i] & FLAG))) {
		start = i;
		val = vec[i];
	    }
	}
    };
};
int64_t CompactIDSet::_totalSize = 0;
int64_t CompactIDSet::_totalSlots = 0;

bool CompactIDSet::overlaps(const CompactIDSet &that) const
{
    bool result = false;
#if TEST_TRACEIDSET
    static int call = 0;
    bool backup_result = false;
    call++;
    {
	const vector<TraceID> &a = this->backup, &b = that.backup;
	size_t ai = 0, bi = 0;
	while (ai < a.size() && bi < b.size()) {
	    if (a[ai] < b[bi]) {
		ai++;
	    } else if (b[bi] < a[ai]) {
		bi++;
	    } else {
		backup_result = true;
		break;
	    }
	}
    }
#endif

    IdvectorWalker a(this->data);
    IdvectorWalker b(that.data);
    while (a.i < a.vec.size() && b.i < b.vec.size()) {
	if (a.val == b.val) { result = true; break; }
	if (a.is_int && b.is_int) {
	    // neither is a bitvector
	    if (a.val < b.val) a.increment();
	    else /* b.val < a.val */ b.increment();
	} else if (a.is_int) {
	    // b is a bitvector
	    if (a.val < b.val) {
		a.increment();
	    } else /* a.val > b.val */ {
		size_t dist = a.val - b.val;
		if (dist-1 < 31 * (b.i - b.start - 1)) {
		    // a.val is before b.vec[b.i]'s range
		    a.increment();
		} else if (dist-1 >= 31 * (b.i - b.start)) {
		    // a.val is after b.vec[b.i]'s range
		    b.increment();
		} else {
		    // a.val is in b.vec[b.i]'s range
		    if (b.vec[b.i] & (1 << ((dist-1)%31))) { result = true; break; }
		    a.increment();
		}
	    }
	} else if (b.is_int) {
	    // a is a bitvector
	    if (b.val < a.val) {
		b.increment();
	    } else /* b.val > a.val */ {
		size_t dist = b.val - a.val;
		if (dist-1 < 31 * (a.i - a.start - 1)) {
		    // b.val is before a.vec[a.i]'s range
		    b.increment();
		} else if (dist-1 >= 31 * (a.i - a.start)) {
		    // b.val is after a.vec[a.i]'s range
		    a.increment();
		} else {
		    // b.val is in a.vec[a.i]'s range
		    if (a.vec[a.i] & (1 << ((dist-1)%31))) { result = true; break; }
		    b.increment();
		}
	    }
	} else {
	    // both are bitvectors
	    int dist = (b.val + 31*(b.i-b.start)) - (a.val + 31*(a.i-a.start));
	    if (dist >= 0) {
		// a's range starts before b's range
		if (dist <= 31) { // the ranges overlap
		    if (a.vec[a.i] & (b.vec[b.i] << dist) & MASK) { result = true; break; }
		}
		a.increment();
	    } else {
		// b's range starts before a's range
		if (-dist <= 31) { // the ranges overlap
		    if (b.vec[b.i] & (a.vec[a.i] << -dist) & MASK) { result = true; break; }
		}
		b.increment();
	    }
	}
    }

#if TEST_TRACEIDSET
    if (result != backup_result) {
	out_log << "# ERROR in call #" << call << ";" <<
	    " ai=" << a.i << " astart=" << a.start << " aval=" << a.val << " a[ai]=" << hex << a.vec[a.i] << dec <<
	    " bi=" << b.i << " bstart=" << b.start << " bval=" << b.val << " b[bi]=" << hex << b.vec[b.i] << dec <<
	    endl;
	exit(1);
    }
#endif
    return result;
}

// a network interface
struct Iface {
    const ip4addr_t addr;	// interface's address
    uint32_t nodeid;		// id of node (router) to which interface belongs
    uint32_t linkid;		// id of link to which interface belongs
    explicit Iface(ip4addr_t a) : addr(a), nodeid(0), linkid(0) {}
};

// an interface corresponding to a hop in a trace, or a loaded interface
struct ExplicitIface : public Iface {
    bool seen_as_transit;
    bool seen_as_dest;
protected:
    union {			// 2 bytes that can be used by subclasses, that
	uint16_t s;		//   would otherwise be wasted padding between
	bool b;			//   seen_as_dest and traces
    } scratch;
public:
    CompactIDSet traces;	// set of traces in which interface appeared
    explicit ExplicitIface(ip4addr_t a = ip4addr_t(0)) :
	Iface(a), seen_as_transit(false), seen_as_dest(false), traces() {}
};

// an interface with a known routable address
struct NamedIface : public ExplicitIface {
    PathSegVec<2> prev;	// list of (previous 2 hop)s
    PathSegVec<1> next;	// list of next hops
#ifdef ENABLE_TTL
    ttlVec ttl;			// array of TTLs from different vantage points
#endif
    bool &preAliased() { return scratch.b; }  // included in loadAliases?
    explicit NamedIface(ip4addr_t a) :
	ExplicitIface(a), prev(), next()
#ifdef ENABLE_TTL
	, ttl()
#endif
	{ preAliased() = false; }
    static void * operator new(size_t size) { return pool.alloc(size); }
    static void operator delete(void *p, size_t size) { pool.free(p, size); }
private:
    static Pool<NamedIface> pool;
};
Pool<NamedIface> NamedIface::pool;

// an interface without a known routable address (e.g., a non-responding hop
// in a trace)
struct AnonIface : public ExplicitIface {
    // steal addresses from multicast space 224.0.0.0/4
    static const uint32_t PREFIX  = 0xE0000000;
    static const uint32_t MASKLEN = 4;
    static const uint32_t NETMASK = 0xFFFFFFFF << (32-MASKLEN);
    static uint32_t maxid;
    ip4addr_t redundant; // another iface that is equivalent to this one
    PathSegVec<1> prev;	// list of previous hops
    AnonIface() : ExplicitIface(ip4addr_t(++maxid | PREFIX))
    {
	if (maxid & NETMASK) {
	    cerr << "ERROR: anonymous addresses exceed " <<
		ip4addr_t(PREFIX) << "/" << MASKLEN << endl;
	    abort();
	}
	redundant = ip4addr_t(0);
    }
    explicit AnonIface(ip4addr_t a) : ExplicitIface(a) {}
    static void * operator new(size_t size) { return pool.alloc(size); }
    static void operator delete(void *p, size_t size) { pool.free(p, size); }
private:
    static Pool<AnonIface> pool;
};
Pool<AnonIface> AnonIface::pool;
uint32_t AnonIface::maxid = 0;

ostream& operator<< (ostream& out, const Iface& iface) {
    return out << iface.addr; 
}

struct iface_less_than {
    bool operator()(const Iface * const &a, const Iface * const &b) const {
	return addr_less_than(a->addr, b->addr);
    }
};

static inline bool isAnon(const ip4addr_t &addr)
    { return (!addr || ((addr & AnonIface::NETMASK) == AnonIface::PREFIX)); }
static inline bool isAnon(const Iface *const i)
    { return isAnon(i->addr); }

static inline bool isNamed(const ip4addr_t &addr) { return !isAnon(addr); }
static inline bool isNamed(const Iface *const i) { return !isAnon(i); }

typedef ivector<uint32_t, Iface*> IfaceVector;

// an alias set / network node / router
class Node {
public:
    IfaceVector ifaces;		// interfaces belonging to this node
#ifdef ENABLE_TTL
    ttlVec min_ttl, max_ttl;	// arrays of min & max TTLs of interfaces
#endif
    Node() : ifaces() {}
};

struct NodeSet : public map<uint32_t, Node> {
    static uint32_t nextid;
    iterator get(uint32_t nodeid) { return this->find(nodeid); }
    iterator add() { return insert(value_type(nextid++, Node())).first; }
    uint32_t n_ifaces;
    uint32_t n_anon_ifaces;
    uint32_t n_redundant_ifaces;
    uint32_t n_named_ifaces;
    void calculateStats() {
	NodeSet::const_iterator n;
	IfaceVector::const_iterator i;
	n_ifaces = 0;
	n_anon_ifaces = 0;
	n_redundant_ifaces = 0;
	n_named_ifaces = 0;
	for (n = this->begin(); n != this->end(); ++n) {
	    n_ifaces += n->second.ifaces.size();
	    for (i = n->second.ifaces.begin(); i != n->second.ifaces.end(); ++i) {
		if (isNamed(*i))
		    n_named_ifaces++;
		else if (static_cast<AnonIface*>(*i)->redundant != 0)
		    n_redundant_ifaces++;
		else
		    n_anon_ifaces++;
	    }
	}
    }
};
uint32_t NodeSet::nextid = 1;

ostream& operator<< (ostream& out, const NodeSet::value_type& node) {
    IfaceVector::const_iterator i;
    out << "node N" << node.first << ":  ";
    for (i = node.second.ifaces.begin(); i != node.second.ifaces.end(); ++i) {
	if (isNamed(*i) || (isAnon(*i) && static_cast<AnonIface*>(*i)->redundant == 0))
	    out << *(*i) << " "; 
    }
    return out;
}

typedef ivector<uint32_t, uint32_t> IdVector;

// a link (set of connected ifaces)
class Link {
public:
    IfaceVector ifaces;	// named or anonymous interfaces belonging to this link
    IdVector nodes;	// ids of nodes with implicit interfaces belonging to this link
    Link() : ifaces(), nodes() {}
};

struct LinkSet : public map<uint32_t, Link> {
    static uint32_t nextid;
    iterator get(uint32_t linkid) { return this->find(linkid); }
    iterator add() { return insert(value_type(nextid++, Link())).first; }
    uint32_t n_ifaces;
    uint32_t n_implicit_ifaces;
    uint32_t n_anon_ifaces;
    uint32_t n_redundant_ifaces;
    uint32_t n_named_ifaces;
    void calculateStats() {
	LinkSet::const_iterator l;
	IfaceVector::const_iterator i;
	n_ifaces = 0;
	n_implicit_ifaces = 0;
	n_anon_ifaces = 0;
	n_redundant_ifaces = 0;
	n_named_ifaces = 0;
	for (l = this->begin(); l != this->end(); ++l) {
	    n_ifaces += l->second.ifaces.size() + l->second.nodes.size();
	    for (i = l->second.ifaces.begin(); i != l->second.ifaces.end(); ++i) {
		if (isNamed(*i))
		    n_named_ifaces++;
		else if (static_cast<AnonIface*>(*i)->redundant != 0)
		    n_redundant_ifaces++;
		else
		    n_anon_ifaces++;
	    }
	    n_implicit_ifaces += l->second.nodes.size();
	}
    }
};
uint32_t LinkSet::nextid = 1;

struct AnonIfaceSet : public vector<AnonIface*> {
    uint32_t n_redundant_ifaces;
    uint32_t n_kept_ifaces;
    void calculateStats();
};

ostream& operator<< (ostream& out, const LinkSet::value_type& link) {
    IfaceVector::const_iterator i;
    out << "link L" << link.first << ":  ";
    for (i = link.second.ifaces.begin(); i != link.second.ifaces.end(); ++i) {
	if (isAnon(*i) && static_cast<AnonIface*>(*i)->redundant != 0)
	    continue; // omit redundant anonymous iface
	out << "N" << (*i)->nodeid << ":" << *(*i) << " "; 
    }
    IdVector::const_iterator n;
    for (n = link.second.nodes.begin(); n != link.second.nodes.end(); ++n) {
	out << "N" << (*n) << " "; 
    }
    return out;
}

typedef set<NamedIface*, iface_less_than> NamedIfaceSet;

static NamedIfaceSet namedIfaces;	// set of observed named interfaces
static NodeSet nodes;
static LinkSet links;
static AnonIfaceSet anonIfaces;		// set of observed anonymous interfaces

struct OrderedAddrPair {
    ip4addr_t addr[2];
    OrderedAddrPair(ip4addr_t a, ip4addr_t b) {
	if (!cfg.bug_swap_dstlink || a < b) {
	    addr[0] = a; addr[1] = b;
	} else {
	    addr[0] = b; addr[1] = a;
	}
    }
    bool operator< (const OrderedAddrPair &b) const {
	return this->addr[0] != b.addr[0] ? addr_less_than(this->addr[0], b.addr[0]) :
	    addr_less_than(this->addr[1], b.addr[1]);
    }
};

typedef set<OrderedAddrPair> OrderedAddrPairSet;
static OrderedAddrPairSet dstlinks;	// set of hop pairs where 2nd is dest

// An inferred subnet, with its range of observed addresses
struct InfSubnet {
private:
    const ip4addr_t prefix;
public:
    const uint8_t len;
    bool pointToPoint; // true if this subnet could be point-to-point
    bool used_right; // true if this was used to make an alias inference
    bool used_left; // true if this was used to make an alias inference
    NamedIfaceSet::const_iterator begin;
    unsigned n_traces;
    float cmpltness; // completeness
    InfSubnet(ip4addr_t _addr, uint8_t _len) :
	prefix(netPrefix(_addr, _len)), len(_len), pointToPoint(_len>=30), n_traces(0) { }
    InfSubnet(NamedIfaceSet::const_iterator _begin, NamedIfaceSet::const_iterator _end,
	uint8_t _len, float _cmpltness);
    ip4addr_t addr() const { return prefix; }
    bool contains(ip4addr_t _addr) const { return netPrefix(_addr, len) == prefix; }
    bool contains(NamedIfaceSet::const_iterator next) const {
	return next != namedIfaces.end() && this->contains((*next)->addr);
    }
    NamedIfaceSet::const_iterator last() const {
	NamedIfaceSet::const_iterator i = begin;
	for (i = begin; this->contains(i); ++i) { }
	return --i;
    }
};

ostream& operator<< (ostream &out, const InfSubnet &s) {
    out << s.addr() << '/' << int(s.len);
    out << " (" << *(*s.begin);
    out << " - " << *(*s.last()) << "; ";
    out << s.cmpltness << "; ";
    out << s.n_traces << ")";
    return out;
}

inline InfSubnet::InfSubnet(NamedIfaceSet::const_iterator _begin,
    NamedIfaceSet::const_iterator _end, uint8_t _len, float _cmpltness) :
    prefix(netPrefix((*_begin)->addr, _len)), len(_len), pointToPoint(_len>=30),
    begin(_begin), n_traces(0), cmpltness(_cmpltness)
{
    debugsubnet << "# found subnet at " << *this << '\n';
}

struct infsubnet_less_than {
    bool operator()(const InfSubnet * const &a, const InfSubnet * const &b)
    const {
	return (a->addr() != b->addr()) ? (a->addr() < b->addr()) :
	    (a->len < b->len);
    }
};

struct infsubnet_rank {
    bool operator()(const InfSubnet * const &a, const InfSubnet * const &b)
    const {
	if (a->len == 31 && b->len == 31) {
	    // both subnets are /31's, with completeness 1.0
	    return a->n_traces != b->n_traces ? a->n_traces > b->n_traces :
		a->addr() < b->addr(); // just to make this a total ordering
	} else if (a->len < 31 && b->len < 31) {
	    // neither subnet is a /31
	    return a->cmpltness != b->cmpltness ? a->cmpltness > b->cmpltness :
		a->n_traces != b->n_traces ? a->n_traces > b->n_traces :
		a->len != b->len ? a->len > b->len :
		a->addr() < b->addr(); // just to make this a total ordering
	} else if (cfg.s30_beats_s31 && (a->len == 30 || b->len == 30)) {
	    // one subnet is a /31 and the other is /30
	    return a->len == 30;
	} else {
	    // one subnet is a /31 and the other is shorter
	    return a->len > b->len;
	}
    }
};

typedef set<InfSubnet*, infsubnet_less_than> SubnetSet;
typedef vector<InfSubnet*> SubnetVec;

struct AnonSeg {	// anonymous trace segment
    const ip4addr_t lo;	// addr of lower neighboring named iface
    const ip4addr_t hi;	// addr of higher neighboring named iface
    const short length;	// number of anonymous hops
    const uint32_t loAnon;	// index of anonIfaces entry of anonymous hop next to lo
    AnonSeg(ip4addr_t lo_, ip4addr_t hi_, int length_, uint32_t idx = 0xFFFFFFFF) :
	lo(lo_), hi(hi_), length(length_), loAnon(idx) { }
    static void * operator new(size_t size) { return pool.alloc(size); }
    static void operator delete(void *p, size_t size) { pool.free(p, size); }
    static void freeall() { pool.freeall(); }
private:
    static Pool<AnonSeg> pool;
};
Pool<AnonSeg> AnonSeg::pool;

struct AnonSegHash {
    size_t operator()(const AnonSeg * const s) const {
	return ((s->lo >> 16) | (s->lo << 16)) ^ s->hi ^ s->length;
    }
};

struct AnonSegEqual {
    bool operator()(const AnonSeg * const a, const AnonSeg * const b) const {
	return a->lo == b->lo && a->hi == b->hi && a->length == b->length;
    }
};

typedef UNORDERED_NAMESPACE::unordered_set<AnonSeg*, AnonSegHash, AnonSegEqual> AnonSegSet;


static NetPrefixSet *badSubnets = 0;	// set of subnets that can't exist
static NetPrefixSet bogons;		// set of nonroutable prefixes
static SubnetSet *subnets = 0;		// set of inferred subnets
static SubnetVec *rankedSubnets = 0;	// inferred subnets, ranked
static AnonSegSet anonSegs;		// anonymous trace segments
static vector<ip4addr_t> subnetMids;	// missing addrs in middle of subnets
static unsigned n_anon = 0;		// number of anonymous hops
static unsigned n_total_hops = 0;
static unsigned n_bad_31_traces = 0;
static unsigned n_not_min_mask = 0;
static unsigned n_not_min_net = 0;
static unsigned n_same_min_net = 0;
static unsigned n_named_prev = 0;	// number of objects in NamedIface.prev
static unsigned n_named_next = 0;	// number of objects in NamedIface.next
static unsigned n_anon_prev = 0;	// number of objects in AnonIface.prev

static void addIfaceToNode(NodeSet::iterator node, Iface *iface);

static inline bool samePrefix(const ip4addr_t &a, const ip4addr_t &b, const int &len)
{
    return !((a ^ b) >> (32 - len));
}


static bool isBogus(const ip4addr_t addr)
{
    // assumes that bogons contains only the largest prefixes
    NetPrefix key(addr, 32);
    NetPrefixSet::const_iterator it = bogons.upper_bound(key);
    return (it != bogons.begin() && (*--it).contains(addr));
}

static inline int commonPrefixLen(const ip4addr_t &a, const ip4addr_t &b)
{
    int len = 32;
    for (uint32_t diff = a ^ b; diff; diff = diff >> 1)
	len--;
    return len;
}

// Find longest subnet prefix length that holds a and b.
// Addresses will have a common prefix AND not be broadcast addresses.
static int maxSubnetLen(ip4addr_t a, ip4addr_t b)
{
    int len = commonPrefixLen(a, b);
    if (len < 31) {
	if (a > b)
	    swap(a, b);
	b = ip4addr_t(b + 1); // bump from x.111... to (x+1).000...
	// while either host part is all 0's, shorten the prefix
	while (len > 0 && (!(a << len) || !(b << len))) {
	    len--;
	}
    }
    return len;
}

static ExplicitIface *findIface(ip4addr_t addr)
{
    if (isAnon(addr))
	return anonIfaces[(addr & ~AnonIface::NETMASK) - 1];
    NamedIface key(addr);
    NamedIfaceSet::const_iterator iit = namedIfaces.find(&key);
    if (iit != namedIfaces.end())
	return (*iit);
    // impossible
    out_log << "ERROR: no match for " << addr << "\n";
    abort();
    return 0; // not reached
}

void AnonIfaceSet::calculateStats() {
    AnonIfaceSet::const_iterator l;
    n_redundant_ifaces = 0;
    n_kept_ifaces = 0;
    for (AnonIfaceSet::const_iterator i = begin(); i != end(); ++i) {
	if ((*i)->redundant != 0) {
	    n_redundant_ifaces++;
	} else {
	    n_kept_ifaces++;
	}
    }
}

static void dump(ostream &out, const ExplicitIface *iface)
{
    out << iface->addr;
    if (iface->nodeid)
	out << " N" << iface->nodeid;
    if (iface->linkid)
	out << " L" << iface->linkid;
    if (iface->seen_as_transit)
	out << " T";
    if (iface->seen_as_dest)
	out << " D";
    out << endl;
}

static NamedIface *findOrInsertNamedIface(ip4addr_t addr)
{
    NamedIface key(addr);
    NamedIface *iface;

    NamedIfaceSet::const_iterator iit = namedIfaces.lower_bound(&key);
    if (iit == namedIfaces.end() || (*iit)->addr != key.addr) {
	iface = new NamedIface(addr); // new interface
	namedIfaces.insert(iit, iface);
    } else {
	iface = (*iit); // known interface
    }
    return iface;
}

static inline bool areKnownAliases(const Iface *a, const Iface *b)
{
    if (a == b || (a->nodeid != 0 && a->nodeid == b->nodeid)) {
	return true;
    }
    return false;
}

static inline bool areKnownAliases(const Iface *a, ip4addr_t b)
{
    if (a->addr == b) {
	return true;
    } else if (a->nodeid) {
	IfaceVector::const_iterator i;
	NodeSet::const_iterator node = nodes.get(a->nodeid);
	for (i = node->second.ifaces.begin(); i != node->second.ifaces.end(); ++i) {
	    if ((*i)->addr == b) {
		return true;
	    }
	}
    }
    return false;
}

// If an anonymous interface shares a link and a node with another (anonymous
// or named) interface, we can assume that the interfaces are equivalent.  
static void markRedundantAnon()
{
    NodeSet::const_iterator n;
    IfaceVector::const_iterator i, j;
    for (n = nodes.begin(); n != nodes.end(); ++n) {
	for (i = n->second.ifaces.begin(); i != n->second.ifaces.end(); ++i) {
	    if (!isAnon(*i)) continue;
	    for (j = n->second.ifaces.begin(); j != n->second.ifaces.end(); ++j) {
		if (*i == *j) continue;
		if ((*i)->linkid != (*j)->linkid) continue;
		if ((isNamed(*j) || (isAnon(*j) && static_cast<AnonIface*>(*j)->redundant == 0))) {
		    static_cast<AnonIface*>(*i)->redundant = (*j)->addr;
		    break;
		}
	    }
	}
    }
}

#include "../lib/ScamperInput.h"
#include "../lib/PathLoader.h"

PathLoader pathLoader;

AnonIface anonIface(ip4addr_t(0));	// dummy anonymous interface

class MyPathLoaderHandler : public PathLoaderHandler {
    const ip4addr_t *cached_hops; // hops in prev iteration of preprocessHops
    int n_cached_hops; // # of hops in prev iteration of preprocessHops
    int n_repeated_hops; // # of repeated hops from prev preprocessHops
    int n_stored_hops; // # of hops with stored pathsegs in prev processHops
    int firstAnon;
    ExplicitIface *ihops[MAXHOPS];
public:
    MyPathLoaderHandler() :
	PathLoaderHandler(out_log, debugpath != sink), cached_hops(0),
	n_cached_hops(0), n_repeated_hops(0), n_stored_hops(0) {};

    bool isBadHop(const ip4addr_t *hops, int n_hops, int i)
    {
	// Any bogus addr is treated as anonymous.
	// Also, any addr followed by itself (i.e., a loop of length 1), if
	// oneloop_anon is true. (This is assumed to be a case of a router at
	// hop i who does not respond correctly with TTL expired, but instead
	// forwards the packet to the router at hop i+1, which responds with
	// TTL expired.  Then at TTL=i+1, the router at i+1 responds
	// correctly.  So the real router at i+1 appears at both i and i+1.)
	return isBogus(hops[i]) ||
	    (cfg.oneloop_anon && i < n_hops - 1 && hops[i] == hops[i+1]);
    }

    bool hopsAreEqual(const ip4addr_t *hops, int n_hops, int i, int j)
    {
	return (areKnownAliases(ihops[i], ihops[j]) && ihops[i] != &anonIface);
    }

    void preprocessHops(const ip4addr_t *hops, int n_hops, void *strace)
    {
	firstAnon = -1;

	// out_log << "# creating ifaces" << endl;
	n_repeated_hops = 0;
	if (hops != cached_hops) n_cached_hops = 0;
	for (int i = 0; i < n_hops; ++i) {
	    // note: first & last were already checked
	    if (i > 0 && i < n_hops - 1 && isBadHop(hops, n_hops, i)) {
		n_anon++;
		ihops[i] = &anonIface;
		if (firstAnon < 0)
		    firstAnon = i;
		continue;
	    }
	    if (i < n_cached_hops && ihops[i]->addr == hops[i]) {
		if (n_repeated_hops == i) n_repeated_hops = i+1;
		// Optimization: We can skip the lookup if the hop's address
		// is the same as in the previous trace (which is common for
		// the first few hops from the same monitor).
		continue;
	    }
	    ihops[i] = findOrInsertNamedIface(hops[i]);
	}
	cached_hops = hops;
	n_cached_hops = n_hops;
    }

    int processHops(const ip4addr_t *hops, int n_hops, ip4addr_t src, ip4addr_t dst, void *strace)
    {
	if (debugpath != sink) {
	    debugpath << "### " << pathLoader.n_good_traces << " ihops:";
	    for (int j = 0; j < n_hops; ++j)
		debugpath << " " << *ihops[j];
	    debugpath << "\n";
	}

	// check for non-neighboring hops with the same /31 prefix
	for (int i = 0; i < n_hops - 2; i++) {
	    if (ihops[i] == &anonIface) continue; // anonymous
	    const ip4addr_t mask31(0xFFFFFFFE);
	    ip4addr_t prefix31(hops[i] & mask31);
	    for (int j = i + 2; j < n_hops; ++j) {
		if (ihops[j] == &anonIface) continue; // anonymous
		if ((hops[j] & mask31) == prefix31) {
		    // shouldn't happen
		    ++n_bad_31_traces;
		    return 0;
		}
	    }
	}

	// test /MIN - /30 subnets
	if (!cfg.mode_extract || cfg.min_subnet_middle_required < 30) {
	    static const ip4addr_t mask_min(netPrefix(ip4addr_t(0xFFFFFFFF), cfg.minsubnetlen));
	    for (int i = 0; i < n_hops; ++i) {
		if (ihops[i] == &anonIface) continue; // anonymous
		ip4addr_t prefix_min(hops[i] & mask_min);
		for (int j = i + 2; j < n_hops; ++j) {
		    if (ihops[j] == &anonIface) continue; // anonymous
		    // quick test: addrs don't have same first MIN bits?
		    if ((hops[j] & mask_min) != prefix_min) {
			++n_not_min_mask;
			continue; // can't be in same /MIN
		    }
		    // slower test: either addr would be a broadcast addr in a /MIN?
		    int len = maxSubnetLen(hops[i], hops[j]);
		    if (len < cfg.minsubnetlen) {
			++n_not_min_net; // development
			continue; // not in same /MIN
		    }
		    ++n_same_min_net; // development

		    NetPrefix key(hops[i], len);
		    NetPrefixSet::const_iterator it = badSubnets->upper_bound(key);
		    // Mark this and all larger subnets (up to /MIN) as bad, for use
		    // in subnet accuracy condition.
		    do {
			NetPrefixSet::const_iterator hint = it;
			if (it != badSubnets->begin() && (*(--it)) == key) {
			    debugsubnet << "#     "<< key << " already known bad\n";
			    break; // this subnet and larger are already known bad
			}
			debugsubnet << "#     " << key << " marked as bad\n";
			// insert-with-hint runs in O(1) time
			it = badSubnets->insert(hint, key);
			key.enlarge();
		    } while (key.len >= cfg.minsubnetlen);
		}
	    }
	}

	// Analysis mode
	if (!cfg.mode_extract) {
	    // merge duplicate anonymous ifaces
	    if (cfg.anon_dups && firstAnon >= 0) {
		// For each sequence of anonymous interfaces with the same length
		// and neighbors, assume the corresponding interfaces are aliases
		// for each other, and give each a unique anonymous id.  E.g.,
		// given two identical sequences (A,*,*,*,B), label them both as
		// (A,anon1,anon2,anon3,B).
		// Additionally, if cfg.bug_rev_anondup, then sequences
		// (A,*,*,*,B) and (B,*,*,*,A) will be labeled
		// (A,anon1,anon2,anon3,B) and (B,anon3,anon2,anon1,A).
		// XXX TODO: also do this when the left neighbors are aliases,
		// e.g., (W,*,Z) and (X,*,Z) if W and X are aliases
		// (but not (X,*,Y) and (X,*,Z) if Y and Z are aliases).
		for (int i = firstAnon; i < n_hops; ) {
		    int len;
		    for (len = 1; ihops[i+len] == &anonIface; ++len);
		    bool reversed = cfg.bug_rev_anondup && (ihops[i-1]->addr > ihops[i+len]->addr);
		    debuganon << "# anon seg: " << *ihops[i-1] <<
			" (" << len << ") " << *ihops[i+len];
		    ip4addr_t lo, hi;
		    int start, inc, stop;
		    if (reversed) {
			// Canonical order avoids need for a second lookup.
			lo = ihops[i+len]->addr;  hi = ihops[i-1]->addr;
			start = i+len-1;  inc = -1;  stop = i-1;
		    } else {
			lo = ihops[i-1]->addr;  hi = ihops[i+len]->addr;
			start = i;  inc = +1;  stop = i+len;
		    }
		    AnonSeg key(lo, hi, len);
		    AnonSegSet::iterator sit = anonSegs.find(&key);
		    if (sit != anonSegs.end()) {
			debuganon << " (repeat)\n";
			// found existing matching segment.
			// anonIfaces are allocated and numbered sequentially.
			uint32_t idx = (*sit)->loAnon;
			for (int j = start; j != stop; j += inc) {
			    ihops[j] = anonIfaces[idx++];
			}
		    } else {
			// This is a new anonymous segment
			uint32_t total_anon = AnonIface::maxid + len;
			if (total_anon & AnonIface::NETMASK) {
			    cerr << "Error: too many anonymous hops (" <<
				total_anon << ")" << endl;
			    exit(1);
			}
			AnonSeg *seg = new AnonSeg(lo, hi, len, AnonIface::maxid);
			AnonIface *anon = new AnonIface();
			debuganon << " (new) " << *anon << "\n";
			ihops[start] = anon;
			anonIfaces.push_back(anon);
			if (len > 1) {
			    for (int j = start + inc; j != stop; j += inc) {
				ihops[j] = anon = new AnonIface();
				anonIfaces.push_back(anon);
			    }
			}
			anonSegs.insert(seg);
		    }
		    // find next anonymous segment in this trace
		    for (i += len + 1; i < n_hops && ihops[i] != &anonIface; ++i);
		}
	    }

	    int firstTransit = (pathLoader.include_src && hops[0] == src) ? 1 : 0;
	    for (int i = firstTransit; i < n_hops - (badTail==0); i++) {
		ihops[i]->seen_as_transit = true;
	    }

	    // if last hop is the destination...
	    if (n_hops > 0 && badTail == 0 && hops[n_hops-1] == dst) {
		ihops[n_hops-1]->seen_as_dest = true;
		if (!cfg.infer_links) {
		    // create Node now
		    if (ihops[n_hops-1]->nodeid == 0)
			addIfaceToNode(nodes.add(), ihops[n_hops-1]);
		} else if (n_hops > 1 /*&& ihops[n_hops-2] != &anonIface*/) {
		    // Store info needed to create Link and Node in findLinks().
		    // This is more compact than actually creating Links and Nodes
		    // now, leaving more memory free for findAliases().
		    dstlinks.insert(OrderedAddrPair(ihops[n_hops-2]->addr, ihops[n_hops-1]->addr));
		}
		// Don't use destination in normal alias/link inference,
		// because destinations are not necessarily on the interface
		// on the route back to the monitor, so would create a false
		// B->C link, which could lead to a false BCD alias inference
		// and other false topology.
		--n_hops;
	    }

	    // Store path segments for each hop.  (Optimization: skip storage
	    // for segments that were stored by the previous iteration.)
	    int n_repeated_stores = (hops != cached_hops) ? 0 :
		min(n_stored_hops, n_repeated_hops);
	    int start_i = max(n_repeated_stores - 1, 0);
	    for (int i = start_i; i < n_hops; i++) {
		if (isAnon(ihops[i])) {
		    // Anon hops can never be in a subnet, so we don't need their prev 2 and
		    // next 1 for findAliases, but we do need its prev 1 for findLinks.
		    AnonIface *iface = static_cast<AnonIface*>(ihops[i]);
		    if (i > 0) {
			// store previous hop in ihops[i].prev, if not already stored
			PathSegVec<1>::iterator it;
			PathSeg<1> psKey(ihops[i-1]->addr);
			it = lower_bound(iface->prev.begin(), iface->prev.end(),
			    psKey, pathseg_less_than<1>());
			if (it == iface->prev.end() || (*it) != psKey) {
			    // if (iface->prev.capacity() == 0) iface->prev.reserve(2);
			    iface->prev.insert(it, psKey);
			    ++n_anon_prev;
			}
		    }
		    continue;
		}
		NamedIface *iface = static_cast<NamedIface*>(ihops[i]);
		if (i > 0 && i >= n_repeated_stores) {
		    // store previous 2 hops in ihops[i].prev, if not already stored
		    PathSegVec<2>::iterator it;
		    PathSeg<2> psKey(ihops[i-1]->addr, i>1 && cfg.infer_aliases ? ihops[i-2]->addr : ip4addr_t(0));
		    it = lower_bound(iface->prev.begin(), iface->prev.end(),
			psKey, pathseg_less_than<2>());
		    if (it == iface->prev.end() || (*it) != psKey) {
			// if (iface->prev.capacity() == 0) iface->prev.reserve(2);
			iface->prev.insert(it, psKey);
			++n_named_prev;
		    }
		}
		if (i < n_hops - 1 && i >= n_repeated_stores - 1 && cfg.infer_aliases) {
		    // store next hop in iface.next, if not already stored
		    PathSegVec<1>::iterator it;
		    PathSeg<1> psKey(ihops[i+1]->addr);
		    it = lower_bound(iface->next.begin(), iface->next.end(),
			psKey, pathseg_less_than<1>());
		    if (it == iface->next.end() || (*it) != psKey) {
			// if (iface->next.capacity() == 0) iface->next.reserve(2);
			iface->next.insert(it, psKey);
			++n_named_next;
		    }
		}
	    }
	    n_stored_hops = (hops == cached_hops) ? n_hops : 0;
	}

	++pathLoader.n_good_traces;
	if (cfg.need_traceids) {
	    for (int i = 0; i < n_hops; i++) {
		if (ihops[i]->addr == 0) continue; // dummy
		ihops[i]->traces.append(pathLoader.n_good_traces);
	    }
	}

	n_total_hops += n_hops;
	return 1;
    }
};

static void loadTraces(const char *filename)
{
    out_log << "# loadTraces: " << filename << endl;
    int n_traces = pathLoader.load(filename);

    out_log << "# traces=" << n_traces <<
	"/" << pathLoader.n_good_traces <<
	"/" << pathLoader.n_raw_traces <<
	" loops=" << pathLoader.n_loops <<
	" discarded=" << pathLoader.n_discarded_traces <<
	" namedIfaces=" << namedIfaces.size() <<
	" anon=" << n_anon <<
	" uniq_anon=" << AnonIface::maxid <<
	" hops=" << n_total_hops <<
	" anonSegs=" << anonSegs.size() <<
	endl;
#if 1
    uint64_t mem_named_prev = 0, mem_named_next = 0, mem_anon_prev = 0;
    uint64_t idsetsize[5] = {0,0,0,0,0};
    for (NamedIfaceSet::iterator it = namedIfaces.begin(); it != namedIfaces.end(); ++it) {
	mem_named_next += (*it)->next.memory();
	mem_named_prev += (*it)->prev.memory();
	if ((*it)->traces.rawsize() < 4)
	    idsetsize[(*it)->traces.rawsize()]++;
	else
	    idsetsize[4]++;
    }
    for (AnonIfaceSet::iterator it = anonIfaces.begin(); it != anonIfaces.end(); ++it) {
	mem_anon_prev += (*it)->prev.memory();
	if ((*it)->traces.rawsize() < 4)
	    idsetsize[(*it)->traces.rawsize()]++;
	else
	    idsetsize[4]++;
    }
    out_log << "# named_prev: n=" << n_named_prev << " mem=" << mem_named_prev << " eff=" << double(n_named_prev) * sizeof(PathSeg<2>) / mem_named_prev << endl;
    out_log << "# named_next: n=" << n_named_next << " mem=" << mem_named_next << " eff=" << double(n_named_next) * sizeof(PathSeg<1>) / mem_named_next << endl;
    out_log << "# anon_prev: n=" << n_anon_prev << " mem=" << mem_anon_prev << " eff=" << double(n_anon_prev) * sizeof(PathSeg<1>) / mem_anon_prev << endl;
    out_log << "# TraceIDSet totalSize=" << CompactIDSet::totalSize() <<
	" totalSlots=" << CompactIDSet::totalSlots() << endl;
    out_log << "# TraceIDSets: " <<
	" 0:" << idsetsize[0] <<
	" 1:" << idsetsize[1] <<
	" 2:" << idsetsize[2] <<
	" 3:" << idsetsize[3] <<
	" >3:" << idsetsize[4] << endl;
#endif
    out_log << "# bad_31_traces=" << n_bad_31_traces <<
	" not_min_mask=" << n_not_min_mask <<
	" not_min_net=" << n_not_min_net <<
	" same_min_net=" << n_same_min_net <<
	" badSubnets=" << (badSubnets ? badSubnets->size() : 0) <<
	endl;

    memoryInfo.print("loaded paths");
}

// Clear the contents of a vector, and free its storage space.
template<class T, class Alloc>
void freevec(vector<T, Alloc> &v)
{
    vector<T, Alloc> tmp;
    tmp.swap(v);
    tmp.clear();
}

static void setAlias(Iface * const a, Iface * const b);

// For each path sequence A,*,C where the middle iface is anonymous, if there
// are any sequences A,X,C or A,Y,C with matching endpoints, assume that * is
// an alias for X or Y, and is thus redundant.
// This could theoretically also be applied to longer sequences, but would
// require much more memory and computation time, and would provide
// diminishing returns.  (This 3-hop version can use the NamedIface.prev structures
// that are already needed by findAliases().)
static void matchAnonymousIfaces()
{
    int matches = 0;
    NamedIfaceSet::iterator iit;
    // for each iface C
    for (iit = namedIfaces.begin(); iit != namedIfaces.end(); ++iit) {
	NamedIface *ifaceC = (*iit);
	PathSegVec<2>::iterator pit1, pit2;
	// for each 3-hop sequence ending with C
	for (pit1 = ifaceC->prev.begin(); pit1 != ifaceC->prev.end(); ++pit1) {
	    if (isAnon((*pit1).hop(0)) && !isAnon((*pit1).hop(1))) {
		// found an A,*,C sequence
		ip4addr_t anon = (*pit1).hop(0);
		ip4addr_t addrA = (*pit1).hop(1);
		// for each 3-hop sequence ending with C
		// TODO: check sequences ending with any apriori aliases of C
		for (pit2 = ifaceC->prev.begin(); pit2 != ifaceC->prev.end(); ++pit2) {
		    ip4addr_t addrB = (*pit2).hop(0);
		    // TODO: check equality with any apriori aliases of A
		    if ((*pit2).hop(1) == addrA && !isAnon(addrB)) {
			// found a matching A,B,C sequence
			debuganon << "# anon match for " << anon << ": " <<
			    addrA << " " << addrB << " " << *ifaceC << "\n";
			// We can't easily find all references to anon to
			// remove them.
			matches++;
#if 0
			AnonIface *anonIface = static_cast<AnonIface*>(findIface(anon));
			anonIface->redundant = addrB;
			Iface *ifaceB = findIface(addrB);
			setAlias(ifaceB, anonIface);
#endif
			break;
		    }
		}
	    }
	}
    }
    out_log << "# found " << matches << " redundant anonymous matches" << endl;
}

static bool verifySubnet(NamedIfaceSet::const_iterator begin, int len)
{
    // Accuracy condition
    // Fail if any two addrs in subnet appear as non-neighbors in any trace.
    NetPrefix key((*begin)->addr, len);
    if (badSubnets->find(key) != badSubnets->end()) {
	debugsubnet << "# bad subnet " << key << '\n';
	return false;
    }

    ip4addr_t maxaddr = maxAddr((*begin)->addr, len);

#ifdef ENABLE_TTL
    // Distance condition
    // Fail if TTLs of any two addrs in subnet differ by more than 1.
    if (cfg.ttl_beats_subnet && cfg.n_ttls > 0) {
	static ttlVec subnet_min_ttl, subnet_max_ttl;
	subnet_min_ttl.alloc_if_needed(); // allocate once, use many times
	subnet_max_ttl.alloc_if_needed(); // allocate once, use many times
	subnet_min_ttl.clear();
	subnet_max_ttl.clear();
	NamedIfaceSet::iterator it;
	for (it = begin; it != namedIfaces.end() && (*it)->addr < maxaddr; ++it) {
	    ttlVec *iface_min_ttl, *iface_max_ttl;
	    NodeSet::const_iterator node = nodes.get((*it)->nodeid);
	    if (node) {
		iface_min_ttl = &node->min_ttl;
		iface_max_ttl = &node->max_ttl;
	    } else {
		iface_min_ttl = iface_max_ttl = &(*it)->ttl;
	    }
	    if (iface_min_ttl->empty()) continue; // nothing to compare

	    for (int i = 0; i < cfg.n_ttls; ++i) {
		if (!iface_min_ttl->isValid(i)) continue;
		if (iface_min_ttl->get(i) < subnet_min_ttl.get(i, 256, 257))
		    subnet_min_ttl.set(i, iface_min_ttl->get(i));
		if (iface_max_ttl->get(i) > subnet_max_ttl.get(i, -1, -2))
		    subnet_max_ttl.set(i, iface_max_ttl->get(i));
		if (subnet_max_ttl.get(i) - subnet_min_ttl.get(i) >MAX_DISTANCE)
		{
		    debugsubnet << "# subnet " << key <<
			" TTLs too far apart: " << subnet_min_ttl.get(i) <<
			" " << subnet_max_ttl.get(i) << "\n";
		    return false;
		}
	    }
	}
    }
#endif

    // Two interfaces can't be in the same subnet if they're already aliases.
    NamedIfaceSet::iterator i, j;
    i = begin;
    for (++i; i != namedIfaces.end() && (*i)->addr < maxaddr; ++i) {
	for (j = begin; j != i; ++j) {
	    if (areKnownAliases((*i), (*j))) {
		debugsubnet << "# subnet " << key <<
		    " addrs are already aliases: " <<
		    **i << ", " << **j << "\n";
		return false;
	    }
	}
    }

    return true;
}

static void findSmallerSubnets(
    NamedIfaceSet::const_iterator begin, NamedIfaceSet::const_iterator end,
    int len, bool verified)
{
    NamedIfaceSet::const_iterator i, j, k, m;
    int sublen;
    int n;
    float complt;

    for (i = begin; i != end; i = j) {
	debugsubnet << "# checking subnets at " << *(*i) << '\n';
	j = i;
	++j;
	n = 1;
	// find set of addrs starting at i that share a /len prefix
	ip4addr_t maxaddr = maxAddr((*i)->addr, len);
	while (j != end && (*j)->addr <= maxaddr) {
	    ++j; ++n;
	}
	if (n > 1) {
	    k = j; --k;
	    debugsubnet << "# possible /" << int(len) << " subnets at " << *(*i) << " - " << *(*k) << '\n';
	    // subnet len may be longer than common prefix len if suffix is
	    // all 0's or all 1's
	    sublen = maxSubnetLen((*i)->addr, (*k)->addr);
	    ip4addr_t prefix = netPrefix((*i)->addr, sublen);
	    if (sublen >= len) {
		// prefix matched AND subnet isn't ruled out by a broadcast addr
		bool good = true;
		if (sublen < 30) {
		    complt = float(n) / ((1 << (32-sublen)) - 2);
		    good = (complt >= cfg.mincompleteness);
		} else {
		    complt = 1.0;
		}

		if (good && sublen < 30 && sublen >= cfg.min_subnet_middle_required) {
		    // don't use this subnet if the middle two
		    // addrs are missing; but do try the two half subnets.
		    ip4addr_t mid1(maxAddr(prefix, sublen+1));
		    ip4addr_t mid2(mid1 + 1);
		    good = false;
		    for (m = i; m != end && (*m)->addr <= mid2; ++m) {
			if ((*m)->addr == mid1 || (*m)->addr == mid2) {
			    good = true; // we found a middle address
			    break;
			}
		    }
		    if (!good) {
			debugsubnet << "# subnet missing middle addresses "
			    << mid1 << " and " << mid2 << "\n";
			if (cfg.mode_extract) {
			    subnetMids.push_back(mid1);
			    subnetMids.push_back(mid2);
			}
		    }
		}

		if (good) {
		    // don't need to verify if parent was already verified
		    if (verified) debugsubnet << "# parent already verified\n";
		    if (verified || verifySubnet(i, sublen))
			subnets->insert(new InfSubnet(i, j, sublen, complt));
		} else {
		    debugsubnet << "# /" << sublen << " incomplete (" << complt << ")\n";
		}
	    }
	    if (n > 2) // might contain smaller subnets
		findSmallerSubnets(i, j, max(sublen,len) + 1, verified);
	}
    }
}

static void findSubnets()
{
    findSmallerSubnets(namedIfaces.begin(), namedIfaces.end(), cfg.minsubnetlen, false);

    out_log << "# found " << subnets->size() << " subnets" << endl;

    // count n_traces for each subnet
    SubnetSet::const_iterator sit;
    NamedIfaceSet::const_iterator iit;
    for (sit = subnets->begin(); sit != subnets->end(); ++sit) {
	(*sit)->n_traces = 0;
	for (iit = (*sit)->begin; (*sit)->contains(iit); ++iit) {
	    (*sit)->n_traces += (*iit)->traces.size();
	}
    }

    // rank subnets
    rankedSubnets = new SubnetVec(subnets->begin(), subnets->end());
    sort(rankedSubnets->begin(), rankedSubnets->end(), infsubnet_rank());

    if (debugsubnet != sink) {
	debugsubnet << "# sorted rankedSubnets\n";
	SubnetVec::const_iterator rit;
	for (rit = rankedSubnets->begin(); rit != rankedSubnets->end(); ++rit) {
	    debugsubnet << "# subnet: " << *(*rit) << '\n';
	}
    }
}

#ifdef ENABLE_TTL
static inline void getTTLArrays(const NamedIface *iface,
    const ttlVec **min_ttl, const ttlVec **max_ttl)
{
    NodeSet::iterator node = nodes.get(iface->nodeid);
    if (node) {
	*min_ttl = &node->min_ttl;
	*max_ttl = &node->max_ttl;
    } else {
	*min_ttl = *max_ttl = &iface->ttl;
    }
}

// False if interface a or any of its aliases is too far from interface
// b or any of its aliases.
static bool aliasDistanceCondition(const Iface * const a, const Iface * const b)
{
    if (cfg.ttl_beats_inferred_alias && cfg.n_ttls > 0) {
	if (!isNamed(a) || !isNamed(b)) return true;
	const ttlVec *a_min_ttl, *a_max_ttl, *b_min_ttl, *b_max_ttl;
	getTTLArrays(static_cast<const NamedIface*>(a), &a_min_ttl, &a_max_ttl);
	getTTLArrays(static_cast<const NamedIface*>(b), &b_min_ttl, &b_max_ttl);
	if (a_min_ttl->empty() || b_min_ttl->empty())
	    return true; // nothing to compare

	// Aliases with a TTL range greater than MAX_DISTANCE may have been
	// created during loadAliases().  New alias candidates are allowed
	// anywhere in that range.
	for (int i = 0; i < cfg.n_ttls; ++i) {
	    if (!a_min_ttl->isValid(i) || !b_min_ttl->isValid(i)) continue;
	    int a_dist = a_max_ttl->get(i) - a_min_ttl->get(i);
	    int b_dist = b_max_ttl->get(i) - b_min_ttl->get(i);
	    int combo_max = max(a_max_ttl->get(i), b_max_ttl->get(i));
	    int combo_min = min(a_min_ttl->get(i), b_min_ttl->get(i));
	    int combo_dist = combo_max - combo_min;
	    if (combo_dist > MAX_DISTANCE &&
		combo_dist > a_dist && combo_dist > b_dist)
	    {
		debugalias << "# alias TTLs too far apart: [" <<
		    a_min_ttl->get(i) << "," << a_max_ttl->get(i) << "], [" <<
		    b_min_ttl->get(i) << "," << b_max_ttl->get(i) << "]\n";
		return false;
	    }
	}
    }
    return true;
}
#endif

static inline void getAliasArrays(const ExplicitIface * const &iface,
    const Iface *const * &aliases, int &size)
{
    NodeSet::iterator node = nodes.get(iface->nodeid);
    if (node != nodes.end()) {
	aliases = &*node->second.ifaces.begin();
	size = node->second.ifaces.size();
    } else {
	// iface's only alias is itself
	aliases = reinterpret_cast<const Iface *const *>(&iface);
	size = 1;
    }
}

// False if interface a or any of its aliases ever appears in the same
// trace as interface b or any of its aliases.
static bool aliasNoLoopCondition(const ExplicitIface * const a, const ExplicitIface * const b)
{
    const Iface *const *a_aliases;
    const Iface *const *b_aliases;
    const Iface *const *ai;
    const Iface *const *bi;
    int a_size, b_size;

    getAliasArrays(a, a_aliases, a_size);
    getAliasArrays(b, b_aliases, b_size);

    // Search traces for members of a_aliases and b_aliases.
    // Possible speed optimization: store trace id lists on each node, merging
    // the lists when aliases are found.  Then the ai and bi loops wouldn't be
    // needed here; we'd need only a->node->traces.overlaps(b->node->traces).
    // Experiments show that this only reduces cpu time by about 6% (when
    // compiled with -O2), but also increases memory use by about 8%.
    for (ai = a_aliases; ai < a_aliases + a_size; ++ai) {
	for (bi = b_aliases; bi < b_aliases + b_size; ++bi) {
	    if (static_cast<const ExplicitIface*>(*ai)->traces.overlaps(static_cast<const ExplicitIface*>(*bi)->traces)) {
		debugalias << "#### " << *a << " and " << *b << " would cause loop\n";
		return false;
	    }
	}
    }
    return true;
}

#if 0
static inline bool sameSubnet(const Iface *a, const Iface *b,
    const InfSubnet * const base)
{
    return sameSubnet(a->addr, b->addr);
}
#endif

static InfSubnet *commonSubnet(ip4addr_t a, ip4addr_t b,
    InfSubnet * const base)
{
    int minLen = cfg.subnet_len ? base->len : cfg.minsubnetlen;
    if (!isNamed(a) || !isNamed(b)) {
	debugalias << "##### sameSubnet " << a << ", " << b << ": no (anonymous)\n";
	return 0;
    }
    // quick test that weeds out most cases
    if (!samePrefix(a, b, minLen)) {
	debugalias << "##### sameSubnet " << a << ", " << b << ": quick reject 1\n";
	return 0;
    }
    // slower test for remaining cases

    int len = maxSubnetLen(a, b);
    if (len < minLen) {
	debugalias << "##### sameSubnet " << a << ", " << b << ": quick reject 2\n";
	return 0;
    }

    if (cfg.subnet_verify) {
	NamedIface ikey(netPrefix(a, len));
	NamedIfaceSet::const_iterator begin = namedIfaces.lower_bound(&ikey); // can't fail
	if (!verifySubnet(begin, len)) {
	    debugalias << "##### sameSubnet " << a << ", " << b << ": no (verify failed)\n";
	    return 0;
	}
    }

    if (!cfg.subnet_inference) {
	debugalias << "##### sameSubnet " << a << ", " << b << ": yes\n";
	return base; // hack
    }

    // Find the smallest subnet that contains a and b.
    InfSubnet key(a, len);
    SubnetSet::iterator s = subnets->lower_bound(&key);
    ip4addr_t minAddr = netPrefix(a, minLen);

    if (s == subnets->end()) {
	if (s == subnets->begin()) {
	    debugalias << "##### sameSubnet " << a << ", " << b << ": no match\n";
	    return 0;
	}
	--s;
    }

    while ((*s)->addr() >= minAddr) {
	if ((*s)->contains(a) && (*s)->contains(b)) {
	    // This could be the one.
	    if (cfg.subnet_len && (*s)->len < base->len) {
		debugalias << "##### sameSubnet " << a << ", " << b << ": no (" << *(*s) << " larger than " << int(base->len) << ")\n";
	    } else if (!cfg.bug_rank && cfg.subnet_rank && infsubnet_rank()(base, *s)) {
		debugalias << "##### sameSubnet " << a << ", " << b << ": no (" << *(*s) << " worse than " << *base << ")\n";
	    } else if (cfg.bug_rank && cfg.subnet_rank && infsubnet_less_than()(base, *s)) {
		debugalias << "##### sameSubnet " << a << ", " << b << ": no (BUG " << *(*s) << " worse than " << *base << ")\n";
	    } else {
		debugalias << "##### sameSubnet " << a << ", " << b << ": yes (" << *(*s) << ")\n";
		return *s;
	    }
	}
	if (s == subnets->begin()) break;
	--s;
    }

    debugalias << "##### sameSubnet " << a << ", " << b << ": no\n";
    return 0;
}

inline static bool sameSubnet(ip4addr_t a, ip4addr_t b,
    InfSubnet * base)
{
    return !!commonSubnet(a, b, base);
}

static void addIfaceToNode(NodeSet::iterator node, Iface *iface)
{
    node->second.ifaces.push_back(iface);
    iface->nodeid = node->first;
    if (!isNamed(iface)) return;
#ifdef ENABLE_TTL
    NamedIface *niface = static_cast<NamedIface*>(iface);
    if (!node->second.min_ttl.empty() && !niface->ttl.empty()) {
	debugttl << "# node min_ttl:   " << node->second.min_ttl << "\n";
	debugttl << "# node max_ttl:   " << node->second.min_ttl << "\n";
	debugttl << "# iface ttl:      " << niface->ttl << "\n";
	node->second.min_ttl.mergeMin(niface->ttl);
	node->second.max_ttl.mergeMax(niface->ttl);
	debugttl << "# merged min_ttl: " << node->second.min_ttl << "\n";
	debugttl << "# merged max_ttl: " << node->second.min_ttl << "\n";
	niface->ttl.free();  // no longer needed
    } else if (!niface->ttl.empty()) {
	swap(node->second.min_ttl, niface->ttl); // move array
	node->second.max_ttl = node->second.min_ttl; // copy array
    }
#endif
}

static void setAlias(Iface * const a, Iface * const b)
{
    debugalias << "##### setAlias(" << *a << ", " << *b << "):  ";
    if (a->nodeid && b->nodeid) {
	if (a->nodeid == b->nodeid) {
	    debugalias << "already aliases\n";
	    return; // already aliases
	}
	// merge existing nodes
	NodeSet::iterator keep = nodes.get(a->nodeid);
	NodeSet::iterator dead = nodes.get(b->nodeid);
	debugalias << "merging " << *dead << " into " << *keep << "\n";
	IfaceVector::iterator i, j;
	// warn when ifaces share link AND node (unless they're anonymous)
	for (i = dead->second.ifaces.begin(); i != dead->second.ifaces.end(); ++i) {
	    if (cfg.anon_shared_nodelink && !isNamed(*i)) continue;
	    for (j = keep->second.ifaces.begin(); j != keep->second.ifaces.end(); ++j) {
		if (cfg.anon_shared_nodelink && !isNamed(*j)) continue;
		if ((*i)->linkid != 0 && (*i)->linkid == (*j)->linkid) {
		    out_log << "# WARNING: merging nodes N" << keep->first << " and N" <<
			dead->first << " with shared link L" << (*i)->linkid <<
			" (" << *(*i) << ", " << *(*j) << ")" << endl;
		}
	    }
	}
	for (i = dead->second.ifaces.begin(); i != dead->second.ifaces.end(); ++i)
	    (*i)->nodeid = keep->first;
	keep->second.ifaces.insert(keep->second.ifaces.end(),
	    dead->second.ifaces.begin(), dead->second.ifaces.end());
#ifdef ENABLE_TTL
	if (!keep->second.min_ttl.empty() && !dead->second.min_ttl.empty()) {
	    debugttl << "# keep min ttl:   " << keep->second.min_ttl << "\n";
	    debugttl << "# dead min ttl:   " << dead->second.min_ttl << "\n";
	    keep->second.min_ttl.mergeMin(dead->second.min_ttl);
	    debugttl << "# merged min ttl: " << keep->second.min_ttl << "\n";
	    debugttl << "# keep max ttl:   " << keep->second.max_ttl << "\n";
	    debugttl << "# dead max ttl:   " << dead->second.max_ttl << "\n";
	    keep->second.max_ttl.mergeMax(dead->second.max_ttl);
	    debugttl << "# merged max ttl: " << keep->second.max_ttl << "\n";
	} else if (!dead->second.min_ttl.empty()) {
	    swap(keep->second.min_ttl, dead->second.min_ttl); // move array
	    swap(keep->second.max_ttl, dead->second.max_ttl); // move array
	}
#endif
	nodes.erase(dead);
    } else if (a->nodeid) {
	// add b to a's node
	NodeSet::iterator node = nodes.get(a->nodeid);
	debugalias << "adding " << *b << " to " << *node << "\n";
	addIfaceToNode(node, b);
    } else if (b->nodeid) {
	// add a to b's node
	NodeSet::iterator node = nodes.get(b->nodeid);
	debugalias << "adding " << *a << " to " << *node << "\n";
	addIfaceToNode(node, a);
    } else {
	// new node
	NodeSet::iterator node = nodes.add();
	addIfaceToNode(node, a);
	addIfaceToNode(node, b);
	debugalias << "new " << *node << "\n";
    }
}

static void addIfaceToLink(LinkSet::iterator &link, Iface *iface)
{
    link->second.ifaces.push_back(iface);
    iface->linkid = link->first;
}

static void setLink(Iface * const a, Iface * const b)
{
    debuglink << "# setLink(" << *a << ", " << *b << "):  ";
    if (a->linkid && b->linkid) {
	if (a->linkid == b->linkid) {
	    debuglink << "already linked\n";
	    return; // already linked
	}
	// merge existing links
	LinkSet::iterator keep = links.get(a->linkid);
	LinkSet::iterator dead = links.get(b->linkid);
	debuglink << "merging " << *dead << " into " << *keep << "\n";
	IfaceVector::iterator i, j;
	for (i = dead->second.ifaces.begin(); i != dead->second.ifaces.end(); ++i) {
	    // warn if ifaces share link AND node (unless they're anonymous)
	    if (cfg.anon_shared_nodelink && !isNamed(*i)) continue;
	    for (j = keep->second.ifaces.begin(); j != keep->second.ifaces.end(); ++j) {
		if (cfg.anon_shared_nodelink && !isNamed(*j)) continue;
		if ((*i)->nodeid != 0 && (*i)->nodeid == (*j)->nodeid) {
		    out_log << "# WARNING: merging links L" << keep->first << " and L" <<
			dead->first << " with shared node N" << (*i)->nodeid <<
			" (" << *(*i) << ", " << *(*j) << ")" << endl;
		}
	    }
	}
	for (i = dead->second.ifaces.begin(); i != dead->second.ifaces.end(); ++i) {
	    // move iface to new link
	    (*i)->linkid = keep->first;
	}
	keep->second.ifaces.insert(keep->second.ifaces.end(),
	    dead->second.ifaces.begin(), dead->second.ifaces.end());
	links.erase(dead);
    } else if (a->linkid) {
	// add b to a's link
	LinkSet::iterator link = links.get(a->linkid);
	debuglink << "adding " << *b << " to " << *link << "\n";
	addIfaceToLink(link, b);
    } else if (b->linkid) {
	// add a to b's link
	LinkSet::iterator link = links.get(b->linkid);
	debuglink << "adding " << *a << " to " << *link << "\n";
	addIfaceToLink(link, a);
    } else {
	// new link
	LinkSet::iterator link = links.add();
	addIfaceToLink(link, a);
	addIfaceToLink(link, b);
	debuglink << "new " << *link << "\n";
    }
}

// Link all interfaces on the inferred subnet
static void setLink(InfSubnet *s)
{
    NamedIfaceSet::const_iterator i1, i2;

    debuglink << "# setLink(" << *s << ")\n";
    i1 = s->begin;
    if (!s->contains(i1)) {
	out_log << "# ERROR: empty subnet in setLink\n";
	abort();
    }
    i2 = i1;
    for (++i2; s->contains(i2); ++i2) {
	setLink(*i1, *i2);
    }
}

static void setLink(Iface * const a, const NodeSet::const_iterator &n)
{
    debuglink << "# setLink(" << *a << ", " << *n << "):  ";
    if (a->linkid) {
	// add b to a's link
	LinkSet::iterator link = links.get(a->linkid);
	debuglink << "adding " << *n << " to " << *link << "\n";
	link->second.nodes.push_back(n->first);
    } else {
	// new link
	LinkSet::iterator link = links.add();
	addIfaceToLink(link, a);
	link->second.nodes.push_back(n->first);
	debuglink << "new " << *link << "\n";
    }
}

// Mark all subnets of an InfSubnet as NON-point-to-point
static void markNonP2P(InfSubnet *s)
{
    if (!cfg.markNonP2P) return;
    ip4addr_t maxaddr = maxAddr(s->addr(), s->len);
    SubnetSet::iterator subnet = subnets->find(s);
    while (subnet != subnets->end() && (*subnet)->addr() < maxaddr) {
	(*subnet)->pointToPoint = false;
	++subnet;
    }
}

// Variable names and debugging output use letters from this diagram:
//
//   A > B > C  (forward)
//     /   /
//   E < D      (reversed)
//
// (C,D) are in the anchor subnet; (B,D) are the alias candidates.
// Neighbor condition is either (B,E) in a subnet, or (A,E) are aliases.
//
static void findAliases(bool pointToPoint)
{
    SubnetVec::const_iterator s;
    NamedIfaceSet::const_iterator i1, i2;
    PathSegVec<2>::iterator prv1;
    PathSegVec<1>::iterator nxt2;

    for (s = rankedSubnets->begin(); s != rankedSubnets->end(); ++s) {

	if (pointToPoint && !(*s)->pointToPoint) {
	    continue; // this is not p2p, but there may be others
	}

	debugalias << "# findAliases(" << pointToPoint << ") for " << *(*s) << '\n';
	for (i1 = (*s)->begin; (*s)->contains(i1); ++i1) {
	    if (!isNamed(*i1)) { cerr << "ERROR: unnamed ifaceC: " << *i1 << endl; abort(); };
	    NamedIface *ifaceC = static_cast<NamedIface*>(*i1);

	    ExplicitIface *ifaceB = 0;
	    for (i2 = (*s)->begin; (*s)->contains(i2); ++i2) {
		if (i1 == i2) continue;
		if (!isNamed(*i2)) { cerr << "ERROR: unnamed ifaceD: " << *i2 << endl; abort(); };
		NamedIface *ifaceD = static_cast<NamedIface*>(*i2);

		debugalias << "## subnet members: C=" << *ifaceC <<
		    ", D=" << *ifaceD << '\n';

		ip4addr_t repeatB = ip4addr_t(0);
		for (prv1 = ifaceC->prev.begin(); prv1 != ifaceC->prev.end();
		    ++prv1)
		{
		    if (repeatB == (*prv1).hop(0)) {
			// optimization: previous iteration used the same B,C,D,
			// and did not use A,E, so we can skip this iteration.
			debugalias << "### skipping repeated B\n";
			continue;
		    }
		    repeatB = (*prv1).hop(0); // remember for next loop

		    debugalias << "### A=" << (*prv1).hop(1) << " -> B=" <<
			(*prv1).hop(0) << " -> C=" << *ifaceC << '\n';
		    if ((*prv1).hop(0) == ip4addr_t(0)) continue;
		    // debugalias << "### prv1: " << (*prv1) << '\n';
		    debugalias << "### alias candidates: B=" <<
			(*prv1).hop(0) << ", D=" << *ifaceD << '\n';
		    if (areKnownAliases(ifaceD, (*prv1).hop(0))) {
			debugalias << "#### already known aliases\n";
			// If D is not already linked to something, assume it
			// should be linked to C.  This way, the highest
			// ranked subnet forms the link; when we iterate to
			// lower ranks, the link will have already been made.
			// XXX Maybe we should do this only if (*s)->len >= 30
			if (!ifaceD->linkid) setLink(*s);
			continue;
		    }
		    if ((*s)->contains((*prv1).hop(0))) {
			debugalias << "#### same subnet, can't be aliases\n";
			continue;
		    }

		    // optimization: skip lookup of B if it's a repeat
		    if (!ifaceB || ifaceB->addr != (*prv1).hop(0)) {
			ifaceB = findIface((*prv1).hop(0));
		    }

		    if (
#ifdef ENABLE_TTL
			!aliasDistanceCondition(ifaceB, ifaceD) ||
#endif
			!aliasNoLoopCondition(ifaceB, ifaceD))
			    continue;
		    if (cfg.negativeAlias && isNamed(ifaceB) &&
			static_cast<NamedIface*>(ifaceB)->preAliased() && ifaceD->preAliased())
		    {
			debugalias << "#### both preAliased\n";
			continue;
		    }

		    if (pointToPoint) {
			// XXX False positive if this inferred ptp
			// link is really part of a larger subnet.
			debugbrief << "B=" << *ifaceB <<
			    " C=" << *ifaceC <<
			    " D=" << *ifaceD << "/" << int((*s)->len) << endl;
			setAlias(ifaceD, ifaceB);
			setLink(ifaceC, ifaceD);
			continue;
		    }

		    if (cfg.bug_pprev) {
			repeatB = ip4addr_t(0); // we're about to look at A and E, so next loop will not be a repeat
			for (nxt2 = ifaceD->next.begin();
			    nxt2 != ifaceD->next.end(); ++nxt2)
			{
			    debugalias << "### D=" << *ifaceD << " <- E=" << (*nxt2).hop(0) << '\n';
			    if (sameSubnet(ifaceB->addr, (*nxt2).hop(0), *s)) {
				setAlias(ifaceD, ifaceB);
				setLink(*s);
				if ((*s)->len < 30) markNonP2P(*s);
				goto end_nxt2;
			    }
			    PathSegVec<2>::iterator pprv1;
			    // Mehmet's code erroneously iterated over
			    // previous-previous hops disassociated from the
			    // previous hop.
			    debugalias << "### bug_pprev: A=" << (*prv1).hop(1) << '\n';
			    for (pprv1 = ifaceC->prev.begin(); pprv1 != ifaceC->prev.end(); ++pprv1) {
				ExplicitIface *ifaceA = findIface((*pprv1).hop(1));
				if ((*pprv1).hop(1) == (*nxt2).hop(0) ||
				    areKnownAliases(ifaceA, (*nxt2).hop(0)))
				{
				    (*s)->used_right = true;
				    setAlias(ifaceD, ifaceB);
				    setLink(*s);
				    if ((*s)->len < 30) markNonP2P(*s);
				    goto end_nxt2;
				}
			    }
			}
			end_nxt2: /* do nothing*/;
		    } else {
			InfSubnet *bestleftnet = 0;
			// Find an E for which there is a B-E subnet that
			// ranks better than the C-D subnet.
			// If there are multiple matches, choose the E that
			// results in the smallest B-E subnet.
			ip4addr_t bestE = ip4addr_t(0);
			for (nxt2 = ifaceD->next.begin();
			    nxt2 != ifaceD->next.end(); ++nxt2)
			{
			    ip4addr_t addrE = (*nxt2).hop(0);
			    debugalias << "### E=" << addrE << " <- D=" << *ifaceD << '\n';
			    InfSubnet *leftnet = commonSubnet(ifaceB->addr, addrE, *s);
			    if (!leftnet) continue;
			    if (!bestleftnet || leftnet->len > bestleftnet->len) {
				bestE = addrE;
				bestleftnet = leftnet;
			    }
			}
			if (bestleftnet) {
			    // We found B-E subnet(s); infer B,D alias.
			    (*s)->used_right = true;
			    bestleftnet->used_left = true;
			    debugbrief << "B=" << *ifaceB <<
				" C=" << *ifaceC <<
				" D=" << *ifaceD << "/" << int((*s)->len) <<
				" E=" << bestE << "/" << int(bestleftnet->len) << endl;
			    setAlias(ifaceD, ifaceB);
			    setLink(*s);
			    if ((*s)->len < 30) markNonP2P(*s);
			    setLink(bestleftnet);
			    continue; // no need to check for A=E aliases.
			}
			repeatB = ip4addr_t(0); // we're about to look at A, so next loop will not be a repeat
			// Find an E that is equal to or a known alias of A.
			// If multiple E's are found, pick the one that
			// results in the smallest B-E subnet.
			ip4addr_t addrA = (*prv1).hop(1);
			if (addrA == 0) continue; // there was no A
			ExplicitIface *ifaceA = findIface(addrA);
			bestE = ip4addr_t(0);
			int bestlen = -1;
			for (nxt2 = ifaceD->next.begin();
			    nxt2 != ifaceD->next.end(); ++nxt2)
			{
			    ip4addr_t addrE = (*nxt2).hop(0);
			    debugalias << "### E=" << addrE << " <- D=" << *ifaceD << '\n';
			    if (areKnownAliases(ifaceA, addrE)) {
				debugalias << "# A and E are known aliases" << '\n';
				if (!isNamed(ifaceB) || !isNamed(addrE)) {
				    // We can't do anything with the B-E subnet;
				    // just accept the alias.
				    if (bestlen < 0) {
					bestE = addrE;
					bestlen = 0;
				    }
				} else {
				    // Verify the B-E subnet implied by the (A,E) alias.
				    int len = maxSubnetLen(ifaceB->addr, addrE);
				    NamedIfaceSet::const_iterator begin;
				    ip4addr_t pfx;
				    while (len >= cfg.minsubnetlen) {
					pfx = netPrefix(addrE, len);
					uint32_t mask = 0xFFFFFFFF >> len;
					NamedIface lokey(pfx);
					begin = namedIfaces.lower_bound(&lokey); // can't fail
					if (len == 31) break; // don't check for broadcast addrs
					if (cfg.bug_broadcast) break;
					if (((*begin)->addr & mask) == 0) {
					    // all-0 broadcast address exists
					    len--;
					    continue;
					}
					NamedIface hikey(ip4addr_t(pfx | mask));
					if (namedIfaces.find(&hikey) != namedIfaces.end()) {
					    // all-1 broadcast address exists
					    len--;
					    continue;
					}
					break; // neither broadcast addr exists
				    }
				    if (len < cfg.minsubnetlen || !verifySubnet(begin, len)) {
					// The B,E subnet looks bad.
					// Either C-D is not a valid subnet, or
					// (A,E) are not valid aliases, or
					// some router responded from the "wrong" iface.
					debugalias << "# bad left subnet: " <<
					    pfx << "/" << len << '\n';
				    } else {
					// The B,E subnet looks good
					if (len > bestlen) {
					    bestE = addrE;
					    bestlen = len;
					}
				    }
				}
				// Try all E's to find all B-E links.
			    }
			}
			if (!cfg.alias_subnet_verify || bestlen >= 0) {
			    debugbrief << "A=" << *ifaceA <<
				" B=" << *ifaceB <<
				" C=" << *ifaceC <<
				" D=" << *ifaceD << "/" << int((*s)->len) <<
				" E=" << bestE << "/" << bestlen << endl;
			    (*s)->used_right = true;
			    setAlias(ifaceD, ifaceB);
			    setLink(*s);
			    if ((*s)->len < 30) markNonP2P(*s);
			    if (bestlen == 0 && !cfg.bug_anon_BE_link) {
				// B or E was anonymous; we can link them to
				// each other, but can't link a whole subnet.
				ExplicitIface *ifaceE = findIface(bestE);
				setLink(ifaceB, ifaceE);
			    } else {
				// Infer all B-E links within minimum subnet size
				for (nxt2 = ifaceD->next.begin();
				    nxt2 != ifaceD->next.end(); ++nxt2)
				{
				    ip4addr_t addrE = (*nxt2).hop(0);
				    if (samePrefix(ifaceB->addr, addrE, bestlen)) {
					ExplicitIface *ifaceE = findIface(addrE);
					setLink(ifaceB, ifaceE);
				    }
				}
			    }
			}
		    }
		}
	    }
	}
    }
}

// Make a link between iface i1 and an implicit iface on i2's node, unless a
// link already exists between i1 and some iface on i2's node.
static void link_i1_to_n2(Iface *i1, Iface *i2)
{
    NodeSet::iterator n2 = nodes.get(i2->nodeid);
    if (n2 == nodes.end()) {
	// create a node for i1 to link to
	n2 = nodes.add();
	addIfaceToNode(n2, i2);
	// note: i1 can be linked to n2 already, if i2 is linked directly to i2
    }
    if (i1->linkid != 0) {
	LinkSet::iterator link = links.get(i1->linkid);
	for (IfaceVector::iterator liit = link->second.ifaces.begin(); liit != link->second.ifaces.end(); ++liit) {
	    if ((*liit)->nodeid == n2->first) // already linked to explicit iface on n2
		return;
	}
	for (IdVector::iterator lnit = link->second.nodes.begin(); lnit != link->second.nodes.end(); ++lnit) {
	    if (*lnit == n2->first) // already linked to implicit iface on n2
		return;
	}
    }
    // link i1 to node
    setLink(i1, n2);
}

// create links that exist in paths but were missed by findAliases()
static void findLinks(void)
{
    // Create B->C links for each named iface C.
    for (NamedIfaceSet::iterator iit = namedIfaces.begin(); iit != namedIfaces.end();
	++iit)
    {
	NamedIface *i1 = (*iit);
	PathSegVec<2>::iterator p;
	ip4addr_t repeat = ip4addr_t(0);
	for (p = i1->prev.begin(); p != i1->prev.end(); ++p) {
	    if (repeat == (*p).hop(0)) continue;
	    repeat = (*p).hop(0);
	    Iface *i2 = findIface((*p).hop(0));
	    link_i1_to_n2(i1, i2);
	}
    }

    // Create B->C links for each anonymous iface C.
    for (AnonIfaceSet::iterator iit = anonIfaces.begin(); iit != anonIfaces.end(); ++iit) {
	AnonIface *i1 = (*iit);
	PathSegVec<1>::iterator p;
	for (p = i1->prev.begin(); p != i1->prev.end(); ++p) {
	    Iface *i2 = findIface((*p).hop(0));
	    link_i1_to_n2(i1, i2);
	}
    }

    // Create links for destination hops (which were omitted from iface->prev).
    if (!dstlinks.empty()) {
	// create map: nodeid -> set of link ids the node is already on
	map<uint32_t, CompactIDSet> node2linkset;
	LinkSet::iterator lit;
	for (lit = links.begin(); lit != links.end(); ++lit) {
	    uint32_t linkid = lit->first;
	    Link *link = &lit->second;
	    for (size_t i = 0; i < link->ifaces.size(); ++i) {
		// first, make sure iface has a node
		Iface *iface = link->ifaces[i];
		if (iface->nodeid == 0) addIfaceToNode(nodes.add(), iface);
		node2linkset[iface->nodeid].append(linkid);
	    }
	    for (size_t i = 0; i < link->nodes.size(); ++i) {
		node2linkset[link->nodes[i]].append(linkid);
	    }
	}
	// for each dest hop pair, create nodes and implicit links if needed
	OrderedAddrPairSet::iterator dlit;
	for (dlit = dstlinks.begin(); dlit != dstlinks.end(); ++dlit) {
	    // iface0 can be named or anonymous, but must already exist
	    Iface *iface0 = findIface(dlit->addr[0]);
	    // iface1 (the destination) must be named, but may not exist yet
	    Iface *iface1 = findOrInsertNamedIface(dlit->addr[1]);
	    if (iface0->nodeid == 0) addIfaceToNode(nodes.add(), iface0);
	    if (iface1->nodeid == 0) addIfaceToNode(nodes.add(), iface1);
	    CompactIDSet &linkset0 = node2linkset[iface0->nodeid];
	    CompactIDSet &linkset1 = node2linkset[iface1->nodeid];
	    if (!linkset0.overlaps(linkset1)) {
		// create implicit link between nodes
		LinkSet::iterator link = links.add();
		link->second.nodes.push_back(iface0->nodeid);
		link->second.nodes.push_back(iface1->nodeid);
		linkset0.append(link->first);
		linkset1.append(link->first);
	    }
	}
	node2linkset.clear();
    }
}

static void fixOrphans(void)
{
    // make sure all linked interfaces have a node
    Iface *iface;
    for (NamedIfaceSet::iterator iit = namedIfaces.begin(); iit != namedIfaces.end();
	++iit)
    {
	iface = (*iit);
	if (iface->linkid && !iface->nodeid) {
	    NodeSet::iterator node = nodes.add();
	    addIfaceToNode(node, iface);
	}
    }
    for (AnonIfaceSet::iterator iit = anonIfaces.begin(); iit != anonIfaces.end(); ++iit) {
	iface = (*iit);
	if (iface->linkid && !iface->nodeid) {
	    NodeSet::iterator node = nodes.add();
	    addIfaceToNode(node, iface);
	}
    }
}

static void printNodeLinkCounts(const char *label)
{
    nodes.calculateStats();
    links.calculateStats();
    out_log << "# after " << label << ": found " <<
	nodes.size() << " nodes (max id " << (NodeSet::nextid - 1) <<
	"), containing " << nodes.n_ifaces - nodes.n_redundant_ifaces << " interfaces (" <<
	nodes.n_redundant_ifaces << " redundant (omitted), " <<
	nodes.n_anon_ifaces << " anonymous, " <<
	nodes.n_named_ifaces << " named); and " <<
	links.size() << " links (max id " << (LinkSet::nextid - 1) <<
	"), containing " << links.n_ifaces - links.n_redundant_ifaces << " interfaces (" <<
	links.n_implicit_ifaces << " implicit, " <<
	links.n_redundant_ifaces << " redundant (omitted), " <<
	links.n_anon_ifaces << " anonymous, " <<
	links.n_named_ifaces << " named)." <<
	endl;
}

static void loadIfaces(const char *filename)
{
    out_log << "# loadIfaces: " << filename << endl;
    char buf[8192];
    const char *ifstr;

    InFile in(filename);
    while (in.gets(buf, sizeof(buf))) {
	try {
	    if (buf[0] == '#' || buf[0] == '\n') continue; // comment or empty
	    ifstr = strtok(buf, " \t\n");
	    if (!ifstr || strtok(NULL, "")) {
		throw std::runtime_error("syntax error; expected \"<IPaddr>\"");
	    }
	    ip4addr_t addr(ifstr);
	    if (isBogus(addr)) continue;
	    findOrInsertNamedIface(addr);
	} catch (const std::runtime_error &e) { throw InFile::Error(in, e); }
    }
    in.close();

    out_log << "# loaded " << namedIfaces.size() << " ifaces" << endl;
    memoryInfo.print("loaded ifaces");
}

static void loadAliases(const char *filename)
{
    out_log << "# loadAliases: " << filename << endl;
    char buf[8192];
    const char *ifstr[2];
    NamedIface *iface[2];

    size_t old_nodes = nodes.size();
    size_t old_ifaces = namedIfaces.size();
    unsigned n_fail_distance = 0;
    unsigned n_fail_noloop = 0;

    InFile in(filename);
    while (in.gets(buf, sizeof(buf))) {
	try {
	    if (buf[0] == '#' || buf[0] == '\n') continue; // comment or empty
	    ifstr[0] = strtok(buf, " \t");
	    ifstr[1] = strtok(NULL, " \t\n");
	    char *end = strtok(NULL, "");
	    if (end) while (isspace(*end)) ++end;
	    if (!ifstr[0] || !ifstr[1] || (end && *end)) {
		throw std::runtime_error("syntax error; expected \"<IPaddr> <IPaddr>\"");
	    }
	    for (int i = 0; i < 2; ++i) {
		ip4addr_t addr(ifstr[i]);
		if (isBogus(addr)) goto nextline;
		iface[i] = findOrInsertNamedIface(addr);
		iface[i]->preAliased() = true;
	    }
#ifdef ENABLE_TTL
	    if (cfg.ttl_beats_loaded_alias && !aliasDistanceCondition(iface[0],iface[1])) {
		n_fail_distance++;
	    } else
#endif
	    if (pathLoader.n_good_traces > 0 && !aliasNoLoopCondition(iface[0], iface[1])) {
		n_fail_noloop++;
	    } else if (cfg.pfxlen == 0 || samePrefix(iface[0]->addr, iface[1]->addr, cfg.pfxlen)) {
		setAlias(iface[0], iface[1]);
	    }
	    nextline: continue;
	} catch (const std::runtime_error &e) { throw InFile::Error(in, e); }
    }
    in.close();

    out_log << "# loaded aliases: sets=" << (nodes.size() - old_nodes) << "/" << nodes.size() <<
	", good ifaces=" << (namedIfaces.size() - old_ifaces) << "/" << namedIfaces.size() <<
	", failed distance=" << n_fail_distance <<
	", failed noLoop=" << n_fail_noloop <<
	endl;
    memoryInfo.print("loaded aliases");
}

#ifdef ENABLE_TTL
void updateTTL(int srcId, ip4addr_t addr, short ttl)
{
    if (isBogus(addr)) return;
    NamedIface *iface = findOrInsertNamedIface(addr);
    if (iface->ttl.isSet(srcId) && !iface->ttl.isValid(srcId)) {
	out_log << "# warning: ignoring TTL " << short(ttl) <<
	    " for " << *iface << "\n";
    } else if (iface->ttl.isSet(srcId) && iface->ttl.get(srcId) != ttl) {
	out_log << "# warning: invalidating TTL for " << *iface << " (" <<
	    iface->ttl.get(srcId) << " != " << short(ttl) << ")\n";
	iface->ttl.invalidate(srcId);
    } else {
	iface->ttl.set(srcId, ttl);
	debugttl << "# stored TTL " << int(ttl) << " for " << *iface << "\n";
    }
}

static void loadTTLs(int srcId, const char *filename)
{
    out_log << "# loadTTLs " << srcId << " " << filename << endl;

    InFile in(filename);

#ifdef HAVE_SCAMPER
    if (in.nameEndsWith(".warts")) {
	// scamper file
	uint16_t type = SCAMPER_FILE_OBJ_PING;
	ScamperInput sin(in, &type);
	scamper_ping_t *sping;
	while (sin.read(&type, (void **)&sping) == 0) {
	    if (!sping) break; /* EOF */
	    ip4addr_t dst = scamper_to_ip4addr(sping->dst);
	    if (isBogus(dst)) continue;
	    debugttl << "# " << sping->ping_sent << " ping from " << sping->src << " to " << sping->dst << "\n";
	    scamper_ping_reply_t *reply;
	    for (int i = 0; i < sping->ping_sent; ++i) {
		int j = 0;
		for (reply = sping->ping_replies[i]; reply; reply = reply->next) {
		    if (SCAMPER_PING_REPLY_IS_ICMP_ECHO_REPLY(reply) &&
			scamper_addr_cmp(reply->addr, sping->dst) == 0 &&
			(reply->flags & SCAMPER_PING_REPLY_FLAG_REPLY_TTL))
		    {
			updateTTL(srcId, dst, reply->reply_ttl);
		    }
		    ++j;
		}
	    }
	    scamper_ping_free(sping);
	}

    } else
#endif

    {
	// text file
	char buf[8192];
	const char *addrStr, *ttlStr;
	char *end;
	long ttl;
	while (in.gets(buf, sizeof(buf))) {
	  try {
	    if (buf[0] == '#' || buf[0] == '\n') continue; // comment or empty
	    addrStr = strtok(buf, " \t");
	    ttlStr = strtok(NULL, " \t\n");
	    if (!addrStr || !ttlStr) {
		throw std::runtime_error("syntax error; expected \"<IPaddr> <TTL>\"");
	    }
	    ip4addr_t dst(addrStr);
	    ttl = strtol(ttlStr, &end, 10);
	    if (end == ttlStr || *end || ttl < 0 || ttl > 255) {
		throw std::runtime_error("invalid TTL \"" + ttlStr + "\"");
	    }
	    updateTTL(srcId, dst, ttl);
	  } catch (const std::runtime_error &e) { throw InFile::Error(in, e); }
	}
    }
    in.close();

    out_log << "# loaded distances: ifaces=" << namedIfaces.size() << endl;
    memoryInfo.print("loaded TTLs");
}
#endif

static void outOfMemory()
{
    memoryInfo.print("OUT OF MEMORY");
    out_log << "# OUT OF MEMORY" << endl;
    out_log << "# traces=" << pathLoader.n_good_traces << "/" << pathLoader.n_raw_traces <<
	" loops=" << pathLoader.n_loops <<
	" discarded=" << pathLoader.n_discarded_traces <<
	" namedIfaces=" << namedIfaces.size() <<
	" anon=" << n_anon <<
	" uniq_anon=" << AnonIface::maxid <<
	" hops=" << n_total_hops <<
	endl;
    out_log << "# bad_31_traces=" << n_bad_31_traces <<
	" not_min_mask=" << n_not_min_mask <<
	" not_min_net=" << n_not_min_net <<
	" same_min_net=" << n_same_min_net <<
	" badSubnets=" << (badSubnets ? badSubnets->size() : 0) <<
	endl;
    abort();
}

static void usageExit(const char *name, const char *badoption, int status) {
    if (badoption)
	cerr << "invalid option " << badoption << endl;
    cerr << endl;
    cerr << "Alias resolution usage:" << endl;
    cerr << name << " [behavior-options] [file-options] -P <pathfile>..." << endl;
    cerr << "Resolve IPv4 interface aliases using a modified APAR algorithm." << endl;
    cerr << endl;
    cerr << "Behavior options:" << endl;
    cerr << "-i<arg>  which inferences to make (default \"al\").  Any combination of:" << endl;
    cerr << "    a    aliases" << endl;
    cerr << "    l    links" << endl;
    cerr << "    Note, omitting 'a' can still be useful if other aliases are loaded with -A" << endl;
    cerr << "-s<arg>  how to check neighboring subnet during alias inference:" << endl;
    cerr << "    l    length only (like APAR.c)" << endl;
    cerr << "    vl   verification (accuracy + distance) and length" << endl; // like APAR5.cc
    cerr << "    il   inference (verification + completeness) and length" << endl;
    cerr << "    ir   inference and rank (default)" << endl;
    cerr << "-c<n>    minimum completeness for subnet inference (default " << MINCOMPLETENESS << ")" << endl;
    cerr << "-n<arg>  how to check subnet of neighboring alias during alias inference:" << endl;
    cerr << "    n    no check (like APAR.c)" << endl;
    cerr << "    v    verification (accuracy + distance) (default)" << endl;
    cerr << "-r<arg>  how to rank inferred subnets:" << endl;
    cerr << "    30   /30 is more reliable than /31" << endl;
    cerr << "    31   /31 is more reliable than /30 (default, like APAR.c)" << endl;
    cerr << "-a<arg>  how to handle anonymous interfaces:" << endl;
    cerr << "    i    ignore" << endl;
    cerr << "    d    equal when in duplicate sequences of any length." << endl;
    cerr << "         E.g.,  A,*,*,D == A,*,*,D.  (like APAR.c)" << endl;
    cerr << "    dm   like -ad, plus equal when in matching non-anonymous sequence" << endl;
    cerr << "         of length 1.  E.g., A,*,C == A,B,C." << endl;
    cerr << "    s    equal when on shared link and shared node after analysis" << endl;
    cerr << "    dms  combination of -adm and -as (default)" << endl;
    cerr << "-m<arg>  when inferring subnets, at least one middle address is:" << endl;
    cerr << "    r    required" << endl;
    cerr << "    n    not required (default, like APAR.c)" << endl;
    cerr << "-l<arg>  how to handle loops in traces:" << endl;
    cerr << "    d    discard the entire trace" << endl;
    cerr << "    b    use only the part before the loop (default)" << endl;
    cerr << "    ba   use the parts before and after the loop (like APAR.c)" << endl;
    cerr << "-1<arg>  how to handle loops of length 1:" << endl;
    cerr << "    a    treat first appearance of address as anonymous (default)" << endl;
    cerr << "    l    treat as a loop according to -l option" << endl;
    cerr << "-t<arg>  use TTLs (loaded by -D) to rule out:" << endl;
    cerr << "    s    inferred subnets" << endl;
    cerr << "    si   inferred subnets, inferred aliases (default)" << endl;
		// -tsi is equivalent to -tA in version <=1.105
    cerr << "    sil  inferred subnets, inferred aliases, aliases loaded by -A (like APAR.c)" << endl;
		// -tsil is equivalent to -tD in version <=1.105
    cerr << "-p<arg>  mark subnet as NON-point-to-point if a larger subnet is used?" << endl;
    cerr << "    y    yes (default)" << endl;
    cerr << "    n    no (like APAR.c)" << endl;
    cerr << "-o<arg>  what to output (default \"al\").  Any combination of" << endl;
    cerr << "    a    aliases, to \"<outfile>.aliases\"" << endl;
    cerr << "    l    links, to \"<outfile>.links\"" << endl;
    cerr << "    i    interfaces, to \"<outfile>.ifaces\"" << endl;
    cerr << "    s    subnets, to \"<outfile>.subnets\"" << endl;
    cerr << "-z<n>    infer subnets with prefix length >= n only (default " << MINSUBNETLEN << ")" << endl;
    cerr << "-X<n>    during -A loading, require <n> bit shared prefix (default 0)" << endl;
    cerr << "-N       make negative inferences for aliases absent in -A" << endl;
    cerr << "-O <outfile>" << endl;
    cerr << "         The base name for result output files (default: \"kapar\")" << endl;
    cerr << "-d0      Do not include destination addrs (default with -x)" << endl;
    cerr << "-d1      Include destination addrs, but do not use in alias inference (default" << endl;
    cerr << "         without -x)" << endl;
    cerr << "-g<addr> use only traces to destination <addr>" << endl;
    cerr << "-b<arg>  emulate any combination of bugs:" << endl;
    cerr << "    a    -ad also applies to REVERSED sequences (in APAR.c and kapar < 1.160," << endl;
    cerr << "         2012-03-09)" << endl;
    cerr << "    p    APAR.c pprev bug" << endl;
    cerr << "    r    -sr calculates rank incorrectly, and implies -sl (fixed in 1.116," << endl;
    cerr << "         2010-01-28)" << endl;
    cerr << "    b    -nv doesn't check no-broadcast condition (fixed in 1.118, 2010-02-19)" << endl;
    cerr << "    l    buggy B-E link inference after A-E common neighbor test (fixed in" << endl;
    cerr << "         1.119, 2010-03-01)" << endl;
    cerr << "    d    with -d1, anonymous iface seen at penultimate hop could be assigned to" << endl;
    cerr << "         multiple nodes (fixed in 1.163, 2013-08-02)" << endl;
    cerr << endl;
    cerr << "File options:  each is an option followed by a list of filenames." << endl;
    cerr << "Files whose names end in \".gz\" or \".bz2\" will be automatically uncompressed." << endl;
    cerr << "Any filename preceeded by \"@\" (not part of the name) will be interpreted" << endl;
    cerr << "as a file containing a list of filenames, one per line." << endl;
    cerr << "-B <bogonfile>..." << endl;
    cerr << "   Text files containing bogon prefixes, one per line, in CIDR notation" << endl;
    cerr << "   (e.g., from http://www.cymru.com/Documents/bogon-bn-agg.txt)" << endl;
    cerr << "-A <aliasfile>..." << endl;
    cerr << "   Text files of already-known aliases in the form:  <IPaddr> <IPaddr>" << endl;
    cerr << "-I <ifacefile>..." << endl;
    cerr << "   text files containing addresses known to exist, one per line (useful for " << endl;
    cerr << "   subnet inference)" << endl;
    cerr << "-D <ttlfile>..." << endl;
    cerr << "   Warts files of ICMP echo probes from which TTLs are extracted," << endl;
    cerr << "   or text file of lines with the format \"<IPaddr> <TTL>\"." << endl;
    cerr << "-P <pathfile>..." << endl;
    cerr << "   Files containing path traces: \"*.warts\" for warts files; \"trace.out.*\" for" << endl;
    cerr << "   iPlane files; otherwise text.  In text files, each trace starts with a \"#\"" << endl;
    cerr << "   line, followed by one hop address per line." << endl;
    cerr << endl;
    cerr << endl;
    cerr << "Address extraction usage:" << endl;
    cerr << name << " -x [behavior-options] [file-options]" << endl;
    cerr << "Reads pathfiles and/or address files, and dumps a list of observed router" << endl;
    cerr << "addresses to file \"<outfile>.addrs\"." << endl;
    cerr << endl;
    cerr << "Behavior options:" << endl;
    cerr << "-mr      Also dump missing addresses in middle of inferred subnets" << endl;
    cerr << "         to file \"<outfile>.missing\"." << endl;
    cerr << "         Probing these could help support or rule out subnet inferences." << endl;
    cerr << "-m29     Also dump missing addresses in middle of inferred /29 subnets" << endl;
    cerr << "         to file \"<outfile>.missing\" (default)." << endl;
    cerr << "         Probing these could help rule out false /30 inferences." << endl;
    cerr << "-mn      Don't dump missing addresses in middle of subnets" << endl;
    cerr << "-d       Also extract destination addrs (if reached)" << endl;
    cerr << "         (default: source and intermediate addrs only)" << endl;
    cerr << "-l<arg>  loop handling (same as above)" << endl;
    cerr << endl;
    cerr << "File options:  each is an option followed by a list of filenames." << endl;
    cerr << "-I <ifacefile>...    same as above" << endl;
    cerr << "-B <bogonfile>...    same as above" << endl;
    cerr << "-P <pathfile>...     same as above" << endl;
    cerr << "-O <outfile>         same as above" << endl;
    exit(status);
}

static void printFileOptions(ofstream &out, const char &option,
    vector<const char*> files)
{
    vector<const char*>::const_iterator fit;
    if (!files.empty()) {
	for (fit = files.begin(); fit != files.end(); ++fit)
	    out << endl << "#   -" << option << " " << *fit;
    }
}

static void openOutfile(ofstream &out, const string &suffix, char *argv[])
{
    string name =
	string(cfg.output_basename ? cfg.output_basename : "kapar") + suffix;
    out.open(name.c_str());
    if (!out) {
	cerr << "can't open " << name << ": " << strerror(errno) << endl;
	exit(1);
    }

    out << "# version: " << ::cvsID << endl;
    out << "# version: " << PathLoader::cvsID << endl;
    char timebuf[80];
    struct tm *tm = localtime(&cfg.start_time);
    strftime(timebuf, sizeof(timebuf), " (%F %T %Z)", tm);
    out << "# start time: " << cfg.start_time << timebuf << endl;
    out << "# command line: " << argv[0];
    if (cfg.mode_extract) {
	out << " -x";
    } else {
	out << " -i";
	    if (cfg.infer_aliases) out << "a";
	    if (cfg.infer_links) out << "l";
	if (cfg.bug_rev_anondup || cfg.bug_pprev || cfg.bug_rank || cfg.bug_broadcast || cfg.bug_BE_link) {
	    out << " -b";
	    if (cfg.bug_rev_anondup) out << "a";
	    if (cfg.bug_pprev) out << "p";
	    if (cfg.bug_rank) out << "r";
	    if (cfg.bug_broadcast) out << "b";
	    if (cfg.bug_BE_link) out << "l";
	}
	if (pathLoader.grep_dst)
	    out << " -g" << pathLoader.grep_dst;
	out << " -p" << (cfg.markNonP2P ? 'y' : 'n');
#ifdef ENABLE_TTL
	if (cfg.ttlFiles.size() > 0) {
	    out << " -t";
	    if (cfg.ttl_beats_subnet) out << "s";
	    if (cfg.ttl_beats_inferred_alias) out << "i";
	    if (cfg.ttl_beats_loaded_alias) out << "l";
	}
#endif
	out << " -r" << (cfg.s30_beats_s31 ? "30" : "31");
	out << " -s";
	    if (cfg.subnet_verify) out << "v";
	    if (cfg.subnet_inference) out << "i";
	    if (cfg.subnet_len) out << "l";
	    if (cfg.subnet_rank) out << "r";
	out << " -c" << cfg.mincompleteness;
	out << " -n" << (cfg.alias_subnet_verify ? "v" : "n");
	out << " -a";
	    if (cfg.anon_ignore) out << "i";
	    if (cfg.anon_dups) out << "d";
	    if (cfg.anon_match) out << "m";
	    if (cfg.anon_shared_nodelink) out << "s";
    }
    out << " -d" << (cfg.include_dst ? '1' : '0');
    out << " -m";
	if (cfg.min_subnet_middle_required == MINSUBNETLEN) out << "r";
	else if (cfg.min_subnet_middle_required == 32) out << "n";
	else out << cfg.min_subnet_middle_required;
    out << " -l" << (pathLoader.loop_discard ? "d" : pathLoader.loop_after ? "ba" : "b");
    out << " -1" << (cfg.oneloop_anon ? "a" : "l");
    if (!cfg.mode_extract) {
	out << " -o";
	    if (cfg.output_aliases) out << "a";
	    if (cfg.output_links) out << "l";
	    if (cfg.output_ifaces) out << "i";
	    if (cfg.output_subnets) out << "s";
    }
    if (cfg.output_basename)
	out << " -O " << cfg.output_basename;
    if (cfg.pfxlen)
	out << " -X " << cfg.pfxlen;
    if (cfg.minsubnetlen)
	out << " -z " << cfg.minsubnetlen;
    if (cfg.negativeAlias)
	out << " -N ";
    printFileOptions(out, 'B', cfg.bogonFiles);
    printFileOptions(out, 'A', cfg.aliasFiles);
#ifdef ENABLE_TTL
    printFileOptions(out, 'D', cfg.ttlFiles);
#endif
    printFileOptions(out, 'I', cfg.ifaceFiles);
    printFileOptions(out, 'P', cfg.traceFiles);
    out << endl << "#" << endl;
}


static void exitPerformance()
{
    memoryInfo.print("exit");
}

int main(int argc, char *argv[])
{
  InFile::fork = false;
  try {
    set_new_handler(outOfMemory);
    time(&cfg.start_time);
    pathLoader.handler = new MyPathLoaderHandler;
    pathLoader.raw = false;

    // default options
    cfg.filetype = 0;
    // -r31
    cfg.s30_beats_s31 = false;
    // -sir
    cfg.subnet_inference = true;
    cfg.subnet_rank = true;
    // -c0.5
    cfg.mincompleteness = MINCOMPLETENESS;
    // -nv
    cfg.alias_subnet_verify = true;
    // -adms
    cfg.anon_dups = true;
    cfg.anon_match = true;
    cfg.anon_shared_nodelink = true;
    // -m?
    cfg.min_subnet_middle_required = -1;
    // -O kapar
    cfg.output_basename = 0;
    // -ial
    cfg.infer_aliases = true;
    cfg.infer_links = true;
    // -oal
    cfg.output_aliases = true;
    cfg.output_links = true;
    cfg.output_ifaces = false;
    cfg.output_subnets = false;
    // -1a
    cfg.oneloop_anon = true;
    // -py
    cfg.markNonP2P = true;
    // -z24
    cfg.minsubnetlen = MINSUBNETLEN;
#ifdef ENABLE_TTL
    // -tsi (equivalent to -tA in version <= 1.105)
    cfg.ttl_beats_subnet = true;
    cfg.ttl_beats_inferred_alias = true;
    cfg.ttl_beats_loaded_alias = false;
#endif
    // -X0
    cfg.pfxlen = 0;

    pathLoader.include_src = true;

// allow "-xarg" or "-x arg"
#define get_optarg()  ( argv[optind][2] ? argv[optind] + 2 : \
    optind+1 < argc ? argv[++optind] : 0 )

    for (optind = 1; optind < argc; ++optind) {
	if (argv[optind][0] == '-') {
	    switch (argv[optind][1]) {
	    case 'i':
		cfg.infer_aliases = cfg.infer_links = false;
		for (char *p = get_optarg(); *p; ++p) {
		    switch (*p) {
			case 'a': cfg.infer_aliases = true; break;
			case 'l': cfg.infer_links = true; break;
			default:  usageExit(argv[0], argv[optind], 1);
		    }
		}
		break;
	    case 'o':
		cfg.output_aliases = cfg.output_links = cfg.output_ifaces = cfg.output_subnets = false;
		for (char *p = get_optarg(); *p; ++p) {
		    switch (*p) {
			case 'a': cfg.output_aliases = true; break;
			case 'l': cfg.output_links = true; break;
			case 'i': cfg.output_ifaces = true; break;
			case 's': cfg.output_subnets = true; break;
			default:  usageExit(argv[0], argv[optind], 1);
		    }
		}
		break;
	    case 'O':
		optarg = get_optarg();
		cfg.output_basename = strdup(optarg);
		break;
	    case 'g':
		optarg = get_optarg();
		pathLoader.grep_dst = ip4addr_t(optarg);
		break;
	    case 's':
		cfg.subnet_verify = cfg.subnet_inference = false;
		cfg.subnet_len = cfg.subnet_rank = false;
		for (char *p = get_optarg(); *p; ++p) {
		    switch (*p) {
			case 'v': cfg.subnet_verify = true; break;
			case 'i': cfg.subnet_inference = true; break;
			case 'l': cfg.subnet_len = true; break;
			case 'r': cfg.subnet_rank = true; break;
			default:  usageExit(argv[0], argv[optind], 1);
		    }
		}
		if ((cfg.subnet_len && cfg.subnet_rank) ||
		    (cfg.subnet_verify && cfg.subnet_inference))
			usageExit(argv[0], argv[optind], 1);
		break;
	    case 'c':
		optarg = get_optarg();
		cfg.mincompleteness = atof(optarg);
		break;
	    case 'n':
		optarg = get_optarg();
		if (strcmp(optarg, "n") == 0)
		    cfg.alias_subnet_verify = false;
		else if (strcmp(optarg, "v") == 0)
		    cfg.alias_subnet_verify = true;
		else
		    usageExit(argv[0], argv[optind], 1);
		break;
	    case 'r':
		optarg = get_optarg();
		if (strcmp(optarg, "30") == 0)
		    cfg.s30_beats_s31 = true;
		else if (strcmp(optarg, "31") == 0)
		    cfg.s30_beats_s31 = false;
		else
		    usageExit(argv[0], argv[optind], 1);
		break;
	    case 'a':
		cfg.anon_ignore = cfg.anon_dups = cfg.anon_match =
		    cfg.anon_shared_nodelink = false;
		for (char *p = get_optarg(); *p; ++p) {
		    switch (*p) {
			case 'i': cfg.anon_ignore = true; break;
			case 'd': cfg.anon_dups = true; break;
			case 'm': cfg.anon_match = true; break;
			case 's': cfg.anon_shared_nodelink = true; break;
			default:  usageExit(argv[0], argv[optind], 1);
		    }
		}
		if (cfg.anon_ignore &&
		    (cfg.anon_dups || cfg.anon_match || cfg.anon_shared_nodelink))
			usageExit(argv[0], argv[optind], 1);
		break;
	    case 't':
#ifdef ENABLE_TTL
		cfg.ttl_beats_subnet = false;
		cfg.ttl_beats_inferred_alias = false;
		cfg.ttl_beats_loaded_alias = false;
		for (char *p = get_optarg(); *p; ++p) {
		    switch (*p) {
			case 's': cfg.ttl_beats_subnet = true; break;
			case 'i': cfg.ttl_beats_inferred_alias = true; break;
			case 'l': cfg.ttl_beats_loaded_alias = true; break;
			default:  usageExit(argv[0], argv[optind], 1);
		    }
		}
#else
		cerr << "TTL features are disabled.\n";
		usageExit(argv[0], argv[optind], 1);
#endif
		break;

	    case 'p':
		optarg = get_optarg();
		if (strcmp(optarg, "n") == 0)
		    cfg.markNonP2P = false;
		else if (strcmp(optarg, "y") == 0)
		    cfg.markNonP2P = true;
		else
		    usageExit(argv[0], argv[optind], 1);
		break;
	    case 'b':
		cfg.bug_rev_anondup = cfg.bug_pprev = cfg.bug_rank = cfg.bug_broadcast = cfg.bug_BE_link = false;
		for (char *p = get_optarg(); *p; ++p) {
		    switch (*p) {
			case 'a': cfg.bug_rev_anondup = true; break;
			case 'p': cfg.bug_pprev = true; break;
			case 'r': cfg.bug_rank = true; break;
			case 'b': cfg.bug_broadcast = true; break;
			case 'l': cfg.bug_BE_link = true; break;
			case 'd': cfg.bug_swap_dstlink = true; break;
			default:  usageExit(argv[0], argv[optind], 1);
		    }
		}
		break;
	    case 'x':
		if (argv[optind][2]) // trailing garbage?
		    usageExit(argv[0], argv[optind], 1);
		cfg.mode_extract = true;
		break;
	    case 'z':
		optarg = get_optarg();
		cfg.minsubnetlen = atoi(optarg);
		break;
	    case 'X':
		optarg = get_optarg();
		cfg.pfxlen = atoi(optarg);
		break;
	    case 'N':
		cfg.negativeAlias = true;
		break;
	    case 'd':
		optarg = get_optarg();
		switch (*optarg) {
		    case '0': cfg.include_dst = false; break;
		    case '1': cfg.include_dst = true; break;
		    default:  usageExit(argv[0], argv[optind], 1);
		}
		cfg.include_dst_explicit = true;
		break;
	    case 'm':
		optarg = get_optarg();
		if (strcmp(optarg, "n") == 0)
		    cfg.min_subnet_middle_required = 32;
		else if (strcmp(optarg, "29") == 0)
		    cfg.min_subnet_middle_required = 29;
		else if (strcmp(optarg, "r") == 0)
		    cfg.min_subnet_middle_required = MINSUBNETLEN;
		else
		    usageExit(argv[0], argv[optind], 1);
		break;
	    case 'l':
		optarg = get_optarg();
		if (strcmp(optarg, "d") == 0) {
		    pathLoader.loop_discard = true;
		} else if (strcmp(optarg, "b") == 0) {
		    pathLoader.loop_discard = false;
		    pathLoader.loop_after = false;
		} else if (strcmp(optarg, "ba") == 0) {
		    pathLoader.loop_discard = false;
		    pathLoader.loop_after = true;
		} else {
		    usageExit(argv[0], argv[optind], 1);
		}
		break;
	    case '1':
		for (char *p = get_optarg(); *p; ++p) {
		    switch (*p) {
			case 'a': cfg.oneloop_anon = true; break;
			case 'l': cfg.oneloop_anon = false; break;
			default:  usageExit(argv[0], argv[optind], 1);
		    }
		}
		break;
	    case 'D':
#ifndef ENABLE_TTL
		cerr << "TTL features are disabled.\n";
		usageExit(argv[0], argv[optind], 1);
		break;
#endif
	    case 'B': case 'A': case 'I': case 'P':
		cfg.filetype = argv[optind][1];
		if (argv[optind][2]) // allow "-Xfile" without space
		    if (!cfg.setFile(argv[optind]+2))
			usageExit(argv[0], 0, 1);
		break;
	    default:
		usageExit(argv[0], argv[optind], 1);
	    }
	} else {
	    // allow "-X... file ..."
	    if (!cfg.setFile(argv[optind]))
		usageExit(argv[0], 0, 1);
	}
    }

    // -d?
    // (Extraction mode: destinations are not necessarily router addrs.)
    // (Analysis mode: destinations are not necessarily on the interface on
    // the route back to the monitor, so would create a false B->C link, which
    // could lead to a false BCD alias inference and other false topology.)
    if (!cfg.include_dst_explicit)
	cfg.include_dst = !cfg.mode_extract;
    pathLoader.include_dst = cfg.include_dst;

    if (cfg.mode_extract) {
	cfg.infer_aliases = false;
	cfg.infer_links = false;
	if (cfg.min_subnet_middle_required < 0)
	    cfg.min_subnet_middle_required = 29; // -m29
    } else {
	if (cfg.min_subnet_middle_required < 0)
	    cfg.min_subnet_middle_required = 32; // -mn
    }

    if (cfg.bug_rank && cfg.subnet_rank)
	cfg.subnet_len = true;

    openOutfile(out_log, ".log", argv);
    if (cfg.mode_extract) {
	openOutfile(out_addrs, ".addrs", argv);
	openOutfile(out_missing, ".missing", argv);
#if 0
	openOutfile(out_ptp, ".ptp", argv);
#endif
    } else {
	if (cfg.output_aliases)
	    openOutfile(out_aliases, ".aliases", argv);
	if (cfg.output_links)
	    openOutfile(out_links, ".links", argv);
	if (cfg.output_ifaces)
	    openOutfile(out_ifaces, ".ifaces", argv);
	if (cfg.output_subnets)
	    openOutfile(out_subnets, ".subnets", argv);
    }

    cfg.need_traceids = cfg.infer_aliases || cfg.output_subnets ||
	!cfg.aliasFiles.empty() || cfg.min_subnet_middle_required < 30;

    cfg.dump_ptp_mates = false;

    subnets = new SubnetSet();
    badSubnets = new NetPrefixSet();

    memoryInfo.print("startup");
    atexit(exitPerformance);

    // load bogons
    bogons.installStdBogons();
    out_log << "# loaded " << bogons.size() << " bogons" << endl;
    if (cfg.bogonFiles.size() < 1) {
	cerr << "WARNING: no bogon files specified" << endl;
    }
    for (unsigned i = 0; i < cfg.bogonFiles.size(); ++i) {
	out_log << "# loadBogons: " << cfg.bogonFiles[i] << endl;
	bogons.load(cfg.bogonFiles[i]);
	out_log << "# loaded " << bogons.size() << " bogons" << endl;
    }
#if 0
    NetPrefixSet::const_iterator bit;
    out_log << "# Bogons:" << endl;
    for (bit = bogons.begin(); bit != bogons.end(); ++bit) {
	out_log << "# " << *bit << endl;
    }
#endif
    memoryInfo.print("loaded bogons");

#ifdef ENABLE_TTL
    // load TTL data
    for (unsigned i = 0; i < cfg.ttlFiles.size(); ++i) {
	loadTTLs(i, cfg.ttlFiles[i]);
    }
#if 0
    for (NamedIfaceSet::const_iterator it = namedIfaces.begin(); it != namedIfaces.end(); ++it)
    {
	if ((*it)->ttl.empty()) continue;
	out_log << "# TTLs: " << *(*it) << (*it)->ttl << endl;
    }
#endif
#endif

    // load known interfaces
    for (unsigned i = 0; i < cfg.ifaceFiles.size(); ++i) {
	loadIfaces(cfg.ifaceFiles[i]);
    }

    // load known aliases
    for (unsigned i = 0; i < cfg.aliasFiles.size(); ++i) {
	loadAliases(cfg.aliasFiles[i]);
    }
    if (cfg.aliasFiles.size() > 0) {
	printNodeLinkCounts("loadAliases");
    }
#if 0
    for (NodeSet::const_iterator n = nodes.begin(); n != nodes.end(); ++n) {
	out_log << "# aliasSet: " << *n << endl;
    }
#endif

#if 0
    for (NetPrefixSet::const_iterator it = badSubnets->begin();
	it != badSubnets->end(); ++it)
    {
	out_log << "# bad subnet: " << *it << endl;
    }
#endif

    // load path traces
    for (unsigned i = 0; i < cfg.traceFiles.size(); ++i) {
	loadTraces(cfg.traceFiles[i]);
    }
    delete pathLoader.handler;
    pathLoader.handler = 0;

    // anonSegs is no longer needed; free it
    anonSegs.clear();
    AnonSeg::freeall();
    memoryInfo.print("freed anonSegs");

#if 0
    {
	map<int,int> prevhist;
	map<int,int> nexthist;
	NamedIfaceSet::const_iterator ni;
	for (ni = namedIfaces.begin(); ni != namedIfaces.end(); ++ni) {
	    ++prevhist[(*ni)->prev.size()];
	    ++nexthist[(*ni)->next.size()];
	}
	out_log << "prevhist: ";
	for (map<int,int>::const_iterator i = prevhist.begin(); i != prevhist.end(); ++i)
	    out_log << (*i).first << ":" << (*i).second << " ";
	out_log << endl;
	out_log << "nexthist: ";
	for (map<int,int>::const_iterator i = nexthist.begin(); i != nexthist.end(); ++i)
	    out_log << (*i).first << ":" << (*i).second << " ";
	out_log << endl;
	prevhist.clear();
	nexthist.clear();
    }
#endif

    if (cfg.anon_match) {
	matchAnonymousIfaces();
	memoryInfo.print("matched anons");
    }

    if (cfg.mode_extract) {
	// Address extraction mode
	// dump ifaces
	out_addrs << "# Observed addresses: " << namedIfaces.size() << endl;
	for (NamedIfaceSet::iterator it = namedIfaces.begin(); it != namedIfaces.end(); ++it)
	    out_addrs << **it << endl;
	out_addrs.close();

	if (cfg.min_subnet_middle_required < 30) {
	    // dump missing middles
	    findSubnets();
	    out_missing << "# Missing ";
	    if (cfg.min_subnet_middle_required < 29)
	       out_missing << "/" << cfg.min_subnet_middle_required << " - ";
	    out_missing << "/29 subnet middles: " << subnetMids.size() << endl;
	    vector<ip4addr_t>::iterator i;
	    for (i = subnetMids.begin(); i != subnetMids.end(); ++i)
		out_missing << *i << endl;
	    out_missing.close();
	}

#if 0
	if (cfg.dump_ptp_mates) {
	    // dump point-to-point mates
	    vector<ip4addr_t>::iterator i;
	    for (NamedIfaceSet::iterator it = namedIfaces.begin();
		it != namedIfaces.end(); ++it)
	    {
		NamedIfaceSet::const_iterator iit;
		ip4addr_t addr = (*it)->addr;
		{
		    NamedIface mate(ip4addr_t(addr ^ ip4addr_t(0x1))); // /31
		    iit = namedIfaces.find(&mate);
		    if (iit == namedIfaces.end())
			out_ptp << mate << endl;
		}
		if (((addr & 0x3) == 0x1) || ((addr & 0x3) == 0x2)) {
		    NamedIface mate(ip4addr_t(addr ^ ip4addr_t(0x3))); // /30
		    iit = namedIfaces.find(&mate);
		    if (iit == namedIfaces.end())
			out_ptp << mate << endl;
		}
	    }
	    out_ptp.close();
	}
#endif

    } else {
	// Analysis mode
	if (cfg.infer_aliases || cfg.output_subnets) {
	    findSubnets();
	    memoryInfo.print("found subnets");
	}

	if (cfg.infer_aliases) {
	    findAliases(false);
	    printNodeLinkCounts("findAliases 1");
	    memoryInfo.print("found aliases 1");

	    badSubnets->clear(); // no longer needed (but WAS needed for verifySubnet() during findAliases(true)).
	    delete badSubnets;
	    badSubnets = 0;
	    memoryInfo.print("freed badSubnets");

	    findAliases(true);
	    printNodeLinkCounts("findAliases 2");
	    memoryInfo.print("found aliases 2");
	}

#if 1
	// dump subnets
	if (cfg.output_subnets) {
	    int rightnets = 0, leftnets = 0;
	    SubnetVec::iterator sit;
	    for (sit = rankedSubnets->begin(); sit != rankedSubnets->end(); ++sit) {
		out_subnets << *(*sit);
		if ((*sit)->used_right) {
		    rightnets++;
		    out_subnets << " CD";
		}
		if ((*sit)->used_left) {
		    leftnets++;
		    out_subnets << " BE";
		}
		out_subnets << endl;
	    }
	    out_subnets << "# found " << rankedSubnets->size() << " subnets" << endl;
	    out_subnets << "# found " << rightnets << " CD-nets" << endl;
	    out_subnets << "# found " << leftnets << " BE-nets" << endl;
	    out_subnets.close();
	    memoryInfo.print("dumped subnets");
	}
#endif

	// TraceIDSets are no longer needed
	for (NamedIfaceSet::iterator iit = namedIfaces.begin(); iit != namedIfaces.end(); ++iit) {
	    (*iit)->traces.free(true);
	}
	for (AnonIfaceSet::iterator iit = anonIfaces.begin(); iit != anonIfaces.end(); ++iit) {
	    (*iit)->traces.free(true);
	}
	memoryInfo.print("freed traceids");

	// subnets are no longer needed
	if (rankedSubnets) {
	    rankedSubnets->clear();
	    delete rankedSubnets;
	    rankedSubnets = 0;
	}
	for (SubnetSet::iterator sit = subnets->begin(); sit != subnets->end(); ++sit) {
	    delete (*sit);
	}
	subnets->clear();
	delete subnets;
	subnets = 0;
	memoryInfo.print("freed subnets");

	// next hops are no longer needed
	for (NamedIfaceSet::iterator iit = namedIfaces.begin(); iit != namedIfaces.end(); ++iit) {
	    (*iit)->next.free(true);
	}
	memoryInfo.print("freed nexts");

	if (cfg.infer_links) {
	    findLinks(); // note: findLinks may create aliases
	    printNodeLinkCounts("findLinks");
	    memoryInfo.print("found links");

	    fixOrphans();
	    memoryInfo.print("fixed orphans");
	}

	// dump aliases
	if (cfg.output_aliases) {
	    if (cfg.anon_shared_nodelink) {
		markRedundantAnon();
		memoryInfo.print("redundant anon");
	    }
	    nodes.calculateStats();
	    out_aliases << "# found " << nodes.size() << " nodes, containing " <<
		nodes.n_ifaces - nodes.n_redundant_ifaces << " interfaces (" <<
		nodes.n_redundant_ifaces << " redundant (omitted), " <<
		nodes.n_anon_ifaces << " anonymous, " <<
		nodes.n_named_ifaces << " named)." << endl;
	    for (NodeSet::const_iterator n = nodes.begin(); n != nodes.end(); ++n) {
		out_aliases << *n << endl;
		// nodes.erase(n); // keeps memory-leak-checker happy
	    }
	    out_aliases.close();
	    memoryInfo.print("dumped aliases");
	}

	// dump links
	if (cfg.output_links) {
	    links.calculateStats();
	    out_links << "# found " << links.size() << " links, containing " <<
		links.n_ifaces - links.n_redundant_ifaces << " interfaces (" <<
		links.n_implicit_ifaces << " implicit, " <<
		links.n_redundant_ifaces << " redundant (omitted), " <<
		links.n_anon_ifaces << " anonymous, " <<
		links.n_named_ifaces << " named)." << endl;
	    LinkSet::const_iterator lit;
	    for (lit = links.begin(); lit != links.end(); ++lit) {
		out_links << *lit << endl;
		// links.erase(lit); // keeps memory-leak-checker happy
	    }
	    out_links.close();
	    memoryInfo.print("dumped links");
	}

	// dump ifaces
	if (cfg.output_ifaces) {
	    anonIfaces.calculateStats();
	    out_ifaces << "# key:" << endl;
	    out_ifaces << "#   N<n> = on Node id <n>" << endl;
	    out_ifaces << "#   L<n> = on Link id <n>" << endl;
	    out_ifaces << "#   T = appeared in a traceroute as a transit hop" << endl;
	    out_ifaces << "#   D = appeared in a traceroute as a destination hop" << endl;
	    out_ifaces << "#" << endl;
	    out_ifaces << "# found " << namedIfaces.size() << " named interfaces" << endl;
	    for (NamedIfaceSet::iterator iit = namedIfaces.begin(); iit != namedIfaces.end(); ++iit) {
		dump(out_ifaces, *iit);
	    }
	    out_ifaces << "# found " << anonIfaces.size() << " anonymous interfaces (" << anonIfaces.n_kept_ifaces << " kept, " << anonIfaces.n_redundant_ifaces << " redundant)" << endl;
	    for (AnonIfaceSet::iterator iit = anonIfaces.begin(); iit != anonIfaces.end(); ++iit) {
		dump(out_ifaces, *iit);
	    }
	    out_ifaces.close();
	    memoryInfo.print("dumped ifaces");
	}
    }

    memoryInfo.print("done");
    return 0;

  } catch (const std::exception &e) {
    cerr << e.what() << endl;
    exit(1);
  }
}
