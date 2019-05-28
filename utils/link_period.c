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
#include <math.h>

#include <assert.h>

#include "hashtab.h"

#define is_power_of_2(n)    (((n) & ((n) - 1)) == 0)
#define MIN_DISTS	    16

typedef struct linkinfo {
    struct in_addr addr1;
    struct in_addr addr2;
    int last_seen_in; /* cycle index */
    int sum; /* sum of distances */
    int sum2; /* sum of squares of distances */
    int seen_count;
    uint16_t *dists;
} linkinfo_t;

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

static int cmp16(const void *a, const void *b) {
    return *(uint16_t*)a - *(uint16_t*)b;
}

static double percentile(uint16_t *v, int N, int p)
{
    double kd;
    int k;
    kd = p / 100.0 * (N - 1);
    k = (int)kd;
    return v[k] + (kd - k) * (v[k+1] - v[k]);
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
	    linkinfo = find_hash_entry(links, &findlink);
	    if (!linkinfo) {
		linkinfo = malloc(sizeof(linkinfo_t));
		linkinfo->addr1 = findlink.addr1;
		linkinfo->addr2 = findlink.addr2;
		linkinfo->seen_count = 0;
		linkinfo->sum = 0;
		linkinfo->sum2 = 0;
		linkinfo->dists = NULL;
		add_hash_entry(links, linkinfo);
	    } else {
		int n = linkinfo->seen_count;
		int dist = i - linkinfo->last_seen_in;
		linkinfo->sum += dist;
		linkinfo->sum2 += dist * dist;
		if (n == 1)
		    linkinfo->dists = malloc(MIN_DISTS * sizeof(uint16_t));
		else if (n >= MIN_DISTS && is_power_of_2(n-1))
		    linkinfo->dists = realloc(linkinfo->dists,
			2 * n * sizeof(uint16_t));
		linkinfo->dists[n-1] = dist;
	    }
	    linkinfo->last_seen_in = i;
	    linkinfo->seen_count++;
	}

	if (ferror(in)) {
	    fprintf(stderr, "error reading %s: %s\n",
		filename, strerror(errno));
	    exit(1);
	}
	fclose(in);
    }

    printf("# total links: %ld\n", num_hash_entries(links));
    printf("#times\tmean\tstddev\tmin\t25%%ile\t50%%ile\t75%%ile\tmax\tmax\n");
    printf("#seen\tdist\tdist\tdist\tdist\tdist\tdist\tdist\tclust\n");
    init_hash_walk(links);
    while ((linkinfo = next_hash_walk(links))) {
	double mean, stddev, median;
	int N = linkinfo->seen_count - 1;
	if (N < 1) continue;
	mean = (double)linkinfo->sum / N;
	stddev = sqrt((double)linkinfo->sum2/N - mean * mean);
	qsort(linkinfo->dists, N, sizeof(uint16_t), cmp16);
	if (0) { /* debug */
	    printf("#");
	    for (i = 0; i < N; i++) {
		printf(" %d", linkinfo->dists[i]);
	    }
	    printf("\n");
	}
	median = percentile(linkinfo->dists, N, 50);
	for (i = 0; i < N; i++) {
	    if (linkinfo->dists[i] <= median) continue;
	    if (linkinfo->dists[i] > 2 * linkinfo->dists[i-1])
		break;
	}
	printf("%d\t%.3f\t%.3f\t%d\t%.3f\t%.3f\t%.3f\t%d\t%d\n",
	    linkinfo->seen_count, mean, stddev,
	    linkinfo->dists[0],
	    percentile(linkinfo->dists, N, 25),
	    median,
	    percentile(linkinfo->dists, N, 75),
	    linkinfo->dists[N-1],
	    linkinfo->dists[i-1]);
    }

    return 0;
}
