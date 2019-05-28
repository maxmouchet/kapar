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

typedef struct addrinfo {
    struct in_addr addr;
    int last_seen_in; /* cycle index */
    int sum; /* sum of distances */
    int sum2; /* sum of squares of distances */
    int seen_count;
    uint16_t *dists;
} addrinfo_t;

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
    addrinfo_t *addrinfo;

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
		addrinfo->sum = 0;
		addrinfo->sum2 = 0;
		addrinfo->dists = NULL;
		add_hash_entry(addrs, addrinfo);
	    } else {
		int n = addrinfo->seen_count;
		int dist = i - addrinfo->last_seen_in;
		addrinfo->sum += dist;
		addrinfo->sum2 += dist * dist;
		if (n == 1)
		    addrinfo->dists = malloc(MIN_DISTS * sizeof(uint16_t));
		else if (n >= MIN_DISTS && is_power_of_2(n-1))
		    addrinfo->dists = realloc(addrinfo->dists,
			2 * n * sizeof(uint16_t));
		addrinfo->dists[n-1] = dist;
	    }
	    addrinfo->last_seen_in = i;
	    addrinfo->seen_count++;
	}

	if (ferror(in)) {
	    fprintf(stderr, "error reading %s: %s\n",
		filename, strerror(errno));
	    exit(1);
	}
	fclose(in);
    }

    printf("# total addresses: %ld\n", num_hash_entries(addrs));
    printf("#times\tmean\tstddev\tmin\t25%%ile\t50%%ile\t75%%ile\tmax\tmax\n");
    printf("#seen\tdist\tdist\tdist\tdist\tdist\tdist\tdist\tclust\n");
    init_hash_walk(addrs);
    while ((addrinfo = next_hash_walk(addrs))) {
	double mean, stddev, median;
	int N = addrinfo->seen_count - 1;
	if (N < 1) continue;
	mean = (double)addrinfo->sum / N;
	stddev = sqrt((double)addrinfo->sum2/N - mean * mean);
	qsort(addrinfo->dists, N, sizeof(uint16_t), cmp16);
	if (1) { /* debug */
	    printf("#");
	    for (i = 0; i < N; i++) {
		printf(" %d", addrinfo->dists[i]);
	    }
	    printf("\n");
	}
	median = percentile(addrinfo->dists, N, 50);
	for (i = 0; i < N; i++) {
	    if (addrinfo->dists[i] <= median) continue;
	    if (addrinfo->dists[i] > 2 * addrinfo->dists[i-1])
		break;
	}
	printf("%d\t%.3f\t%.3f\t%d\t%.3f\t%.3f\t%.3f\t%d\t%d\n",
	    addrinfo->seen_count, mean, stddev,
	    addrinfo->dists[0],
	    percentile(addrinfo->dists, N, 25),
	    median,
	    percentile(addrinfo->dists, N, 75),
	    addrinfo->dists[N-1],
	    addrinfo->dists[i-1]);
    }

    return 0;
}
