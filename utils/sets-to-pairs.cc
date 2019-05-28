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
 * Convert alias sets to the full mesh of alias pairs.
 */

const char *cvsID = "$Id: sets-to-pairs.cc,v 1.13 2016/03/07 18:52:08 kkeys Exp $";

#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <assert.h>

#include <functional>
#include <list>
#include <vector>
#include <map>
#include <set>
#include <new>
#include <algorithm>
#include <stdexcept>

#include "../lib/config.h"
#include "../lib/infile.h"
#include "../lib/ip4addr.h"

using namespace std;


// a network interface
struct Iface {
    ip4addr_t addr;		// interface's address
    struct Node *node;		// node (router) to which interface belongs
    explicit Iface(uint32_t a = 0) : addr(a), node(0) {}
};

static ostream& operator<< (ostream& out, const Iface& iface) {
    return out << iface.addr; 
}

struct iface_less_than {
    bool operator()(const Iface * const &a, const Iface * const &b) const {
	return (a->addr < b->addr);
    }
};

// an alias set / network node / router
struct Node {
    vector<Iface*> ifaces;	// interfaces belonging to this node
    const char *name;
    Node() : ifaces(), name(0) {}
};

ostream& operator<< (ostream& out, const Node& node) {
    vector<Iface*>::const_iterator i;
    for (i = node.ifaces.begin(); i != node.ifaces.end(); ++i) {
	out << *(*i) << " "; 
    }
    return out;
}

typedef set<Node*> NodeSet;
typedef set<Iface*, iface_less_than> IfaceSet;


static NodeSet nodes;
static IfaceSet ifaces;
static bool cfg_keep_zeronet = false;

static inline bool samePrefix(const uint32_t &a, const uint32_t &b, const int &len)
{
    return !((a ^ b) >> (32 - len));
}


static Iface *findOrInsertIface(Iface * const key)
{
    Iface *iface;
    IfaceSet::const_iterator iit = ifaces.find(key);
    if (iit == ifaces.end()) {
	iface = new Iface(key->addr); // new interface
	ifaces.insert(iface);
    } else {
	iface = (*iit); // known interface
    }
    return iface;
}


static void addIfaceToNode(Node *node, Iface *iface)
{
    node->ifaces.push_back(iface);
    iface->node = node;
}

static void setAlias(Iface * const a, Iface * const b)
{
    if (a->node && b->node) {
	if (a->node == b->node) return; // already aliases
	// merge existing nodes
	Node *keep = a->node;
	Node *dead = b->node;
	vector<Iface*>::iterator i;
	for (i = dead->ifaces.begin(); i != dead->ifaces.end(); ++i)
	    (*i)->node = keep;
	keep->ifaces.insert(keep->ifaces.end(),
	    dead->ifaces.begin(), dead->ifaces.end());
	nodes.erase(dead);
	delete(dead);
    } else if (a->node) {
	// add b to a's node
	addIfaceToNode(a->node, b);
    } else if (b->node) {
	// add a to b's node
	addIfaceToNode(b->node, a);
    } else {
	// new node
	Node *node = new Node();
	addIfaceToNode(node, a);
	addIfaceToNode(node, b);
	nodes.insert(node);
    }
}

static void loadSets(const char *filename)
{
    char buf[1024000];
    const char *ifstr, *name = 0;
    Iface ifaceKey;
    Iface *iface, *previface;
    bool singleline = false;
    bool multiline = false;

    InFile in(filename);
    previface = 0;
    while (in.gets(buf, sizeof(buf))) {
      try {
	if (buf[strlen(buf)-1] != '\n')
	    throw std::runtime_error("buffer overflow");
	if (buf[0] == '\n' || buf[0] == '#') {
	    name = 0;
	    if (strncmp(buf, "# name: ", 8) == 0) {
		multiline = true;
		char *p = buf + 8;
		strtok(p, "\n");
		while (isspace(*p)) ++p;
		name = strdup(p);
		previface = 0;
	    } else if (strncmp(buf, "# set ", 6) == 0) {
		multiline = true;
		char *p = buf + 6;
		while (isspace(*p)) ++p;
		strtok(p, ": \n");
		name = strdup(p);
		previface = 0;
	    }
	    continue;
	}
	char *src = buf;
	if (strncmp(buf, "node N", 6) == 0) {
	    singleline = true;
	    previface = 0;
	    char *p = buf + 5;
	    src = strchr(p, ':');
	    *src++ = '\0';
	    while (isspace(*p)) ++p;
	    name = strdup(p);
	    while (isspace(*src)) ++src;
	} else if (!multiline) {
	    singleline = true;
	    previface = 0;
	}
	for (; (ifstr = strtok(src, " \t\n")); src = 0) {
	    ifaceKey.addr = ip4addr_t(ifstr);
	    if (!cfg_keep_zeronet && (ifaceKey.addr & 0xFF000000) == 0)
		continue;
	    iface = findOrInsertIface(&ifaceKey);
	    if (iface->node) {
		if (iface->node->name && *iface->node->name && strcmp(iface->node->name, name) != 0) {
		    cerr << "warning: merging " << name << " and " << iface->node->name << " due to " << ifstr << endl;
		    iface->node->name = "";
		}
	    }
	    if (previface) {
		setAlias(previface, iface);
	    } else if (!iface->node) {
		Node *node = new Node();
		node->name = name;
		nodes.insert(node);
		addIfaceToNode(node, iface);
	    }
	    previface = iface;
	}
	if (singleline) name = 0;
      } catch (const std::runtime_error &e) { throw InFile::Error(in, e); }
    }
    in.close();

    cout << "# alias sets=" << nodes.size() <<
	", ifaces=" << ifaces.size() <<
	endl;
}

static void outOfMemory()
{
    cout << "# OUT OF MEMORY" << endl;
    abort();
}

static void usageExit(const char *name, const char *badoption, int status) {
    if (badoption)
	cerr << "invalid option " << badoption << endl;
    cerr << endl;
    cerr << "Usage:" << endl;
    cerr << name << " [options] <aliasSetFile>..." << endl;
    cerr << "Convert alias sets to the full mesh of alias pairs." << endl;
    cerr << "Ignores addresses in 0.0.0.0/8, unless the -z option is given." << endl;
    cerr << "Input file may contain sets in any of these forms:" << endl;
    cerr << "  \"# set <n>: ...\", followed by 1 address per line; or" << endl;
    cerr << "  \"# name: <name>\", followed by 1 address per line; or" << endl;
    cerr << "  \"node N<n>: <addr1> <addr2> ... <addrN>\"; or" << endl;
    cerr << "  \"<addr1> <addr2> ... <addrN>\"" << endl;
    exit(status);
}

int main(int argc, char *argv[])
{
    set_new_handler(outOfMemory);
    int opt;

    while ((opt = getopt(argc, argv, "z")) != -1) {
	if (opt == 'z')
	    cfg_keep_zeronet = true;
	else
	    usageExit(argv[0], 0, 1);
    }

    if (optind == argc)
	usageExit(argv[0], 0, 1);

    for ( ; optind < argc; ++optind) {
	loadSets(argv[optind]);
    }

    // dump pairs
    NodeSet::const_iterator n;
    vector<Iface*>::const_iterator i, j;
    int n_sets = 0;
    for (n = nodes.begin(); n != nodes.end(); ++n) {
	sort((*n)->ifaces.begin(), (*n)->ifaces.end(), iface_less_than());
	cout << "# set " << n_sets++;
	int nif = (*n)->ifaces.size();
	if ((*n)->name && *(*n)->name)
	    cout << " (" << (*n)->name << ")";
	cout << ": " << nif << " ifaces, " << (nif * (nif-1) / 2) << " pairs" << endl;
	for (i = (*n)->ifaces.begin(); i != (*n)->ifaces.end(); ++i) {
	    j = i;
	    for (++j; j != (*n)->ifaces.end(); ++j) {
		cout << **i << "\t" << **j << endl;
	    }
	}
    }
    cout << "# done" << endl;

    return 0;
}
