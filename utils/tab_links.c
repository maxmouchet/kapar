/* $Id: tab_links.c,v 1.2 2011/09/19 21:31:56 kkeys Exp $
 *
 * usage: tab_links {cycle1}.links {cycle2}.links ... {cycleN}.links >links.dat
 *
 * Creates a table of link occurances.
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

#include "ipset.h"
#include "hashtab.h"

typedef struct cycleinfo {
    const char *cyclename;
    unsigned long total_links;
    unsigned long never_seen_before;
    unsigned long never_seen_again;
    unsigned long unique;
    unsigned long fwd_total;
    unsigned long rev_total;
} cycleinfo_t;

typedef struct linkinfo {
    struct in_addr addr1;
    struct in_addr addr2;
    cycleinfo_t *last_seen_in;
    int seen_count;
} linkinfo_t;

static cycleinfo_t *cycles = NULL;
static hash_tab *links = NULL;

static int linkinfo_cmp(const void *pa, const void *pb)
{
    linkinfo_t *a = (linkinfo_t *)pa;
    linkinfo_t *b = (linkinfo_t *)pb;
    return (a->addr1.s_addr != b->addr1.s_addr) ?
	(a->addr1.s_addr - b->addr1.s_addr) :
	(a->addr2.s_addr - b->addr2.s_addr);
}

static unsigned long linkinfo_hash(const void *ptr)
{
    linkinfo_t *iplink = (linkinfo_t *)ptr;
    return iplink->addr1.s_addr ^ iplink->addr2.s_addr;
}

int main(int argc, char *argv[])
{
    FILE *in;
    char buf[2048];
    const char *filename;
    char *p, *q;
    char *cyclename;
    int i;
    linkinfo_t *linkinfo;
    unsigned long accum;

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
    int cycle_count = argc - optind;

    cycles = calloc(cycle_count, sizeof(cycleinfo_t));
    links = init_hash_table("links", linkinfo_cmp, linkinfo_hash, free,
	8388607);

    for (i = 0; i < cycle_count; i++) {
	filename = argv[optind + i];
	in = fopen(filename, "r");
	if (!in) {
	    fprintf(stderr, "can't read %s: %s\n", filename, strerror(errno));
	    exit(1);
	}
	p = strrchr(filename, '-');
	q = strrchr(p, '.');
	cyclename = strncpy(malloc(q-p), p+1, q-p-1);
	cyclename[q-p-1] = '\0';
	cycles[i].cyclename = cyclename;
	fprintf(stderr, "cycle: %s\n", cyclename);

	while (fgets(buf, sizeof(buf), in)) {
	    char a1[16], a2[16];
	    if (sscanf(buf, "%16[0-9.] %16[0-9.] ", a1, a2) != 2) {
		fprintf(stderr, "invalid input: %s\n", buf);
		exit(1);
	    }
	    linkinfo_t findlink;
	    if (inet_pton(AF_INET, a1, &findlink.addr1) != 1) {
		fprintf(stderr, "error in address: %s\n", a1);
		exit(1);
	    }
	    if (inet_pton(AF_INET, a2, &findlink.addr2) != 1) {
		fprintf(stderr, "error in address: %s\n", a2);
		exit(1);
	    }
	    /*fprintf(stderr, "link: <%s>\t<%s>\n", a1, a2);*/
	    linkinfo = find_hash_entry(links, &findlink);
	    if (!linkinfo) {
		linkinfo = malloc(sizeof(linkinfo_t));
		linkinfo->addr1 = findlink.addr1;
		linkinfo->addr2 = findlink.addr2;
		linkinfo->seen_count = 0;
		add_hash_entry(links, linkinfo);
		cycles[i].never_seen_before++;
	    }
	    linkinfo->last_seen_in = &cycles[i];
	    linkinfo->seen_count++;
	    cycles[i].total_links++;
	}

	if (ferror(in)) {
	    fprintf(stderr, "error reading %s: %s\n",
		filename, strerror(errno));
	    exit(1);
	}
	fclose(in);
    }

    init_hash_walk(links);
    while ((linkinfo = next_hash_walk(links))) {
	linkinfo->last_seen_in->never_seen_again++;
	if (linkinfo->seen_count == 1)
	    linkinfo->last_seen_in->unique++;
    }

    accum = 0;
    for (i = 0; i < cycle_count; i++) {
	cycles[i].fwd_total = (accum += cycles[i].never_seen_before);
    }
    accum = 0;
    for (i = cycle_count - 1; i >= 0; i--) {
	cycles[i].rev_total = (accum += cycles[i].never_seen_again);
    }

    printf("# total links: %ld\n", num_hash_entries(links));
    printf("#cyclename\tlinks\t!before\t!again\tunique\tfwdtot\trevtot\n");
    for (i = 0; i < cycle_count; i++) {
	printf("%s\t%ld\t%ld\t%ld\t%ld\t%ld\t%ld\n",
	    cycles[i].cyclename,
	    cycles[i].total_links,
	    cycles[i].never_seen_before,
	    cycles[i].never_seen_again,
	    cycles[i].unique,
	    cycles[i].fwd_total,
	    cycles[i].rev_total);
    }

    return 0;
}
