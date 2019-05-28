/* $Id: iff-chain.cc,v 1.2 2015/09/16 19:51:30 kkeys Exp $
 *
 * usage: iff-chain <iffinder-output-file>
 *
 * assumption: each address was probed only once.
 *
 * Prints a set of connected interfaces on each line.  A set has the format:
 * >   Addr
 * or
 * >   Addr { List }
 * where Addr is an IP address, and List is a list of subsets whose addrs
 * responded with X when probed.
 * A subset may have any of the set formats above, or
 * >   self
 * meaning the address responded from its own addr (named in its superset), or
 * >   Addr LOOP:n
 * flagging the case where a loop of n addresses exists.
 *
 * E.g.
 *   A { B, C, self, D }
 * means
 *   responses from A were elicited by probes to B, C, A itself, and D
 *
 * E.g.
 *   A { B, C { D, E }, F { A LOOP:2 } }
 * means
 *   responses from A were elicited by probes to B, C, and F;
 *   responses from C were elicited by probes to D and E;
 *   responses from F were elicited by probes to A (creating a loop in the
 *     response graph).
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
#include "../lib/unordered_set.h"

typedef std::vector<struct Node*> NodeList;

struct Node {
    struct in_addr addr;
    unsigned long probed;
    Node *response;
    NodeList requests;
    Node() { addr.s_addr = 0; probed = 0; response = NULL; }
};

struct node_equal {
    bool operator()(const Node *a, const Node *b) const {
	return (a->addr.s_addr == b->addr.s_addr);
    }
};

struct node_hash {
    int operator()(const Node *n) const {
	return n->addr.s_addr;
    }
};

typedef UNORDERED_NAMESPACE::unordered_set<Node*, node_hash, node_equal> NodeTab;
NodeTab nodetab;

static void printnode(Node *node, const struct in_addr &top, int depth)
{
    depth++;
    printf("%s", inet_ntoa(node->addr));
    if (!node->requests.empty()) {
	NodeList::iterator nit;
	printf(" { ");
	bool first = true;
	for (nit = node->requests.begin(); nit != node->requests.end(); nit++) {
	    if (!first)
		printf(", ");
	    first = false;
	    if ((*nit) == node)
		printf("self");
	    else if ((*nit)->addr.s_addr == top.s_addr)
		printf("%s LOOP:%d", inet_ntoa((*nit)->addr), depth);
	    else
		printnode(*nit, top, depth);
	}
	printf(" }");
    }
}

int main(int argc, char *argv[])
{
    FILE *in;
    char buf[2048];
    const char *filename;
    int i;
    unsigned long unique_responses = 0, same = 0, diff = 0;

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

    if (optind > 1) {
	fprintf(stderr, "too many files\n");
	exit(1);
    }

    for (i = optind; i < argc; i++) {
	filename = argv[i];
	in = fopen(filename, "r");
	if (!in) {
	    fprintf(stderr, "can't read %s: %s\n", filename, strerror(errno));
	    exit(1);
	}

	while (fgets(buf, sizeof(buf), in)) {
	    char addrbuf1[16], addrbuf2[16], result;
	    Node addr1, addr2;
	    Node *node1, *node2;
	    NodeTab::iterator it1, it2;
	    if (buf[0] == '#' || buf[0] == '\n')
		continue;
	    if (sscanf(buf, "%16[-0-9.] %16[-0-9.] %*3s %*3s %*s %1c",
		addrbuf1, addrbuf2, &result) != 3)
	    {
		fprintf(stderr, "invalid input: %s\n", buf);
		exit(1);
	    }

	    if (inet_pton(AF_INET, addrbuf1, &addr1.addr) != 1) {
		fprintf(stderr, "error in address: %s\n", addrbuf1);
		exit(1);
	    }
	    it1 = nodetab.find(&addr1);

	    if (it1 == nodetab.end()) {
		node1 = new Node();
		node1->addr = addr1.addr;
		nodetab.insert(node1);
	    } else {
		node1 = *it1;
	    }
	    node1->probed++;

	    if (result != 'D' && result != 'S') {
		continue;
	    }

	    if (inet_pton(AF_INET, addrbuf2, &addr2.addr) != 1) {
		fprintf(stderr, "error in address: %s\n", addrbuf2);
		exit(1);
	    }
	    it2 = nodetab.find(&addr2);

	    if (addr1.addr.s_addr == addr2.addr.s_addr) {
		same++;
		node2 = node1;
	    } else {
		diff++;
		if (it2 == nodetab.end()) {
		    node2 = new Node();
		    node2->addr = addr2.addr;
		    nodetab.insert(node2);
		} else {
		    node2 = *it2;
		}
	    }
	    if (node2->requests.empty())
		unique_responses++;
	    node2->requests.push_back(node1);
	    node1->response = node2;
	}

	if (ferror(in)) {
	    fprintf(stderr, "error reading %s: %s\n",
		filename, strerror(errno));
	    exit(1);
	}
	fclose(in);
    }

    NodeTab::iterator nit;
    unsigned long unprobed = 0;
    unsigned long multiprobed = 0;
    for (nit = nodetab.begin(); nit != nodetab.end(); nit++) {
	if ((*nit)->probed == 0)
	    unprobed++;
	if ((*nit)->probed > 1)
	    multiprobed++;
    }
    printf("# ifaces:                    %9lu\n", (unsigned long)nodetab.size());
    printf("# responses from same iface: %9lu\n", same);
    printf("# responses from diff iface: %9lu\n", diff);
    printf("# unique response ifaces:    %9lu\n", unique_responses);
    printf("# unprobed ifaces:           %9lu\n", unprobed);
    printf("# multiprobed ifaces:        %9lu\n", multiprobed);

    for (nit = nodetab.begin(); nit != nodetab.end(); nit++) {
	// We want to print each component only once, from its top responder
	// if there is one, otherwise from a unique node in the loop.
	if (!(*nit)->response || (*nit)->response == (*nit)) {
	    // This node is the top responder in the component.  Print it.
	} else {
	    // This node is not the top responder in the component.
	    // Print it only if the component has a loop and this node is
	    // the lowest address in the loop.
	    int count = 0;
	    bool node_is_lowest = true;
	    Node *loopcheck = NULL;
	    for (Node *r = (*nit)->response; r; r = r->response) {
		++count;
		if (!r->response || r->response==r) { // r is the top responder.
		    goto nextnode;
		} else if (r == (*nit)) { // loop containing this node
		    if (node_is_lowest) break;
		    goto nextnode;
		} else if (r == loopcheck) { // loop not containing this node
		    goto nextnode;
	 	} else if (count == 10) { // optimize for possible loop
		    loopcheck = r;
		} else if (count > 256) { // assume it's a loop
		    fprintf(stderr, "%s: assumed loop\n",
			inet_ntoa((*nit)->addr));
		    goto nextnode;
		}
		if (r->addr.s_addr < (*nit)->addr.s_addr)
		    node_is_lowest = false;
	    }
	}

	printnode(*nit, (*nit)->addr, 0);
	putchar('\n');
	nextnode: continue;
    }

    return 0;
}
