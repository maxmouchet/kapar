/* $Id: tab_addrs.c,v 1.2 2011/09/19 21:31:56 kkeys Exp $
 *
 * usage: tab_addrs {cycle1}.addrs {cycle2}.addrs ... {cycleN}.addrs >addrs.dat
 *
 * Creates a table of address occurances.
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
    unsigned long total_addrs;
    unsigned long never_seen_before;
    unsigned long never_seen_again;
    unsigned long unique;
    unsigned long fwd_total;
    unsigned long rev_total;
} cycleinfo_t;

typedef struct addrinfo {
    struct in_addr addr;
    cycleinfo_t *last_seen_in;
    int seen_count;
} addrinfo_t;

static cycleinfo_t *cycles = NULL;
static hash_tab *addrs = NULL;

static int addrinfo_cmp(const void *pa, const void *pb)
{
    addrinfo_t *a = (addrinfo_t *)pa;
    addrinfo_t *b = (addrinfo_t *)pb;
    return (a->addr.s_addr - b->addr.s_addr);
}

static unsigned long addrinfo_hash(const void *ptr)
{
    addrinfo_t *addr = (addrinfo_t *)ptr;
    return addr->addr.s_addr;
}

static void chomp(char *str)
{
    while (*str && *str != '\n') str++;
    if (*str == '\n') *str = '\0';
}

int main(int argc, char *argv[])
{
    FILE *in;
    char buf[2048];
    const char *filename;
    char *p, *q;
    char *cyclename;
    int i;
    addrinfo_t *addrinfo;
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
    addrs = init_hash_table("addrs", addrinfo_cmp, addrinfo_hash, free,
	2097151);

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
	    chomp(buf);
	    addrinfo_t findaddr;
	    if (inet_pton(AF_INET, buf, &findaddr.addr) != 1) {
		fprintf(stderr, "error in address: %s\n", buf);
		exit(1);
	    }
	    addrinfo = find_hash_entry(addrs, &findaddr);
	    if (!addrinfo) {
		addrinfo = malloc(sizeof(addrinfo_t));
		addrinfo->addr = findaddr.addr;
		addrinfo->seen_count = 0;
		add_hash_entry(addrs, addrinfo);
		cycles[i].never_seen_before++;
	    }
	    addrinfo->last_seen_in = &cycles[i];
	    addrinfo->seen_count++;
	    cycles[i].total_addrs++;
	}

	if (ferror(in)) {
	    fprintf(stderr, "error reading %s: %s\n",
		filename, strerror(errno));
	    exit(1);
	}
	fclose(in);
    }

    init_hash_walk(addrs);
    while ((addrinfo = next_hash_walk(addrs))) {
	addrinfo->last_seen_in->never_seen_again++;
	if (addrinfo->seen_count == 1)
	    addrinfo->last_seen_in->unique++;
    }

    accum = 0;
    for (i = 0; i < cycle_count; i++) {
	cycles[i].fwd_total = (accum += cycles[i].never_seen_before);
    }
    accum = 0;
    for (i = cycle_count - 1; i >= 0; i--) {
	cycles[i].rev_total = (accum += cycles[i].never_seen_again);
    }

    printf("# total addresses: %ld\n", num_hash_entries(addrs));
    printf("#cyclename\taddrs\t!before\t!again\tunique\tfwdtot\trevtot\n");
    for (i = 0; i < cycle_count; i++) {
	printf("%s\t%ld\t%ld\t%ld\t%ld\t%ld\t%ld\n",
	    cycles[i].cyclename,
	    cycles[i].total_addrs,
	    cycles[i].never_seen_before,
	    cycles[i].never_seen_again,
	    cycles[i].unique,
	    cycles[i].fwd_total,
	    cycles[i].rev_total);
    }

    return 0;
}
