/* $Id: iff-analyze.cc,v 1.4 2015/09/18 18:25:02 kkeys Exp $
 *
 * usage: iff-analyze <iffinder-output-file>...
 *
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <assert.h>

#include <functional>
#include <list>
#include <vector>
#include <algorithm>
#include "../lib/unordered_set.h"

using namespace std;

typedef std::list<struct Node*> NodeList;
typedef std::vector<struct Iface*> IfaceList;

struct Iface {
    struct in_addr addr;
    NodeList::iterator nit;
};

struct Node {
    IfaceList ifaces;
};

struct node_less_than {
    bool operator()(const Node *a, const Node *b) const {
	return (htonl(a->ifaces[0]->addr.s_addr) <
	    htonl(b->ifaces[0]->addr.s_addr));
    }
};

struct iface_less_than {
    bool operator()(const Iface *a, const Iface *b) const {
	return (htonl(a->addr.s_addr) < htonl(b->addr.s_addr));
    }
};

struct iface_equal {
    bool operator()(const Iface *a, const Iface *b) const {
	return (a->addr.s_addr == b->addr.s_addr);
    }
};

struct iface_hash {
    int operator()(const Iface *i) const {
	return i->addr.s_addr;
    }
};

typedef UNORDERED_NAMESPACE::unordered_set<Iface*, iface_hash, iface_equal> IfaceTab;

NodeList nodes;
IfaceTab iface_tab;

static Iface *new_iface(const NodeList::iterator &nit, struct in_addr &addr)
{
    Iface *i = new Iface();
    i->addr = addr;
    i->nit = nit;
    (*nit)->ifaces.push_back(i);
    iface_tab.insert(i);
    return i;
}

int main(int argc, char *argv[])
{
    FILE *in;
    char buf[2048];
    const char *filename;
    int i;

#if 0
    int opt;
    while ((opt = getopt(argc, argv, "o:")) != -1) {
        switch(opt) {
	case 'o':
	    outdir = strdup(optarg);
	    break;
	default:
	    fprintf(stderr, "usage:  %s [-o<dir>] <cycledir>...\n", argv[0]);
	    exit(1);
	}
    }
#else
    optind = 1;
#endif

    for (i = optind; i < argc; i++) {
	filename = argv[i];
	in = fopen(filename, "r");
	if (!in) {
	    fprintf(stderr, "can't read %s: %s\n", filename, strerror(errno));
	    exit(1);
	}

	while (fgets(buf, sizeof(buf), in)) {
	    char a1[16], a2[16], result;
	    Iface addr1, addr2;
	    IfaceTab::iterator it1, it2;
	    if (buf[0] == '#' || buf[0] == '\n')
		continue;
	    if (sscanf(buf, "%16[-0-9.] %16[-0-9.] %*3s %*3s %*s %1c",
		a1, a2, &result) != 3)
	    {
		fprintf(stderr, "invalid input: %s\n", buf);
		exit(1);
	    }
	    if (result != 'D')
		continue;
	    if (inet_pton(AF_INET, a1, &addr1.addr) != 1) {
		fprintf(stderr, "error in address: %s\n", a1);
		exit(1);
	    }
	    if (inet_pton(AF_INET, a2, &addr2.addr) != 1) {
		fprintf(stderr, "error in address: %s\n", a2);
		exit(1);
	    }
	    it1 = iface_tab.find(&addr1);
	    it2 = iface_tab.find(&addr2);
	    if (it1 == iface_tab.end() && it2 == iface_tab.end()) {
		/* create a new node and 2 new ifaces */
		nodes.push_front(new Node());
		new_iface(nodes.begin(), addr1.addr);
		new_iface(nodes.begin(), addr2.addr);
	    } else if (it1 != iface_tab.end() && it2 != iface_tab.end()) {
		/* merge two nodes, if they're not already the same */
		if ((*it1)->nit != (*it2)->nit) {
		    IfaceList::iterator j;
		    Node *n1 = (*(*it1)->nit);
		    Node *n2 = (*(*it2)->nit);
		    nodes.erase((*it2)->nit);
		    for (j = n2->ifaces.begin(); j != n2->ifaces.end(); j++) {
			(*j)->nit = (*it1)->nit;
		    }
		    n1->ifaces.insert(n1->ifaces.end(),
			n2->ifaces.begin(), n2->ifaces.end());
		    delete n2;
		}
	    } else {
		/* create 1 new iface and add to existing node */
		if (it1 != iface_tab.end()) {
		    new_iface((*it1)->nit, addr2.addr);
		} else {
		    new_iface((*it2)->nit, addr1.addr);
		}
	    }
	}

	if (ferror(in)) {
	    fprintf(stderr, "error reading %s: %s\n",
		filename, strerror(errno));
	    exit(1);
	}
	fclose(in);
    }

    NodeList::iterator nit;
    vector<Node*>::iterator nvit;
    IfaceList::iterator iit;

    // sort interfaces of each node
    for (nit = nodes.begin(); nit != nodes.end(); nit++) {
	sort((*nit)->ifaces.begin(), (*nit)->ifaces.end(), iface_less_than());
    }

    // sort nodes
    vector<Node*> nodevec(nodes.begin(), nodes.end());
    sort(nodevec.begin(), nodevec.end(), node_less_than());

    // print nodes
    printf("# nodes: %zu\n", nodevec.size());
    printf("# interfaces: %zu\n", iface_tab.size());
    for (nvit = nodevec.begin(); nvit != nodevec.end(); nvit++) {
	printf("%3zu:  ", (*nvit)->ifaces.size());
	for (iit = (*nvit)->ifaces.begin(); iit != (*nvit)->ifaces.end(); iit++)
	    printf("%16s", inet_ntoa((*iit)->addr));
	putchar('\n');
    }

    return 0;
}
