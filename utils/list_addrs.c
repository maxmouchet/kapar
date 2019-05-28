/*
 * $Id: list_addrs.c,v 1.6 2011/10/28 00:20:29 kkeys Exp $
 *
 * NOTE: This program is no longer maintained, though it seems to work.
 *       For similar functionality, use kapar (-x option to extract IP
 *       addresses) or warts-to-paths (to extract paths).
 *
 * usage:  list_addrs [-o<dir>] <cycledir>
 * typically:
 *    for cycle in cycledir1 cycledir2 ... cycledirN; do
 *        list_addrs -o<dir> $cycle 
 *    done
 * or use the "run_list_addrs" script.
 * 
 * Reads arts files from <cycledir>, and writes the following files:
 * <dir>/<cycle>.addrs - IP addresses
 * <dir>/<cycle>.links - links (tab-separated pairs of addrs)
 * <dir>/<cycle>.stats - summary statistics for cycle
 */

#if defined(__APPLE__)
#include <stdint.h>
#endif

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

#define	true	1
#define false	!true

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_trace.h"
#include "scamper_file.h"
#include "ipset.h"
#include "hashtab.h"

static long tracecount = 0;
static long multiresponse = 0;
static long noresponse = 0;
static long hopcount = 0;
static long loopcount = 0;
static int filecount = 0;
static ipset_t *ipset = NULL;
static hash_tab *linkset = NULL;

typedef struct iplink {
    struct in_addr x;
    struct in_addr y;
} iplink_t;


static int iplink_cmp(const void *a, const void *b)
{
    iplink_t *la = (iplink_t *)a;
    iplink_t *lb = (iplink_t *)b;
    return (la->x.s_addr != lb->x.s_addr) ? (la->x.s_addr - lb->x.s_addr) :
	(la->y.s_addr - lb->y.s_addr);
}

static unsigned long iplink_hash(const void *ptr)
{
    iplink_t *iplink = (iplink_t *)ptr;
    return iplink->x.s_addr ^ iplink->y.s_addr;
}


static void process_trace(scamper_trace_t *trace, int unidirectional)
{
    int i, j, hop_count_loopless;
    int foundhop;

    /* This is the number of hops before a loop is detected */
    hop_count_loopless = trace->hop_count;
    for (i = 0; i < trace->hop_count-1; i++) {
	scamper_trace_hop_t *hi;
	for (hi = trace->hops[i]; hi; hi = hi->hop_next) {
	    if (scamper_addr_cmp(hi->hop_addr, trace->dst) == 0) {
		hop_count_loopless = i+1;
		goto loop_found_exit;
	    }
	    for (j = i+1; j < trace->hop_count; j++) {
		scamper_trace_hop_t *hj;
		for (hj = trace->hops[j]; hj; hj = hj->hop_next) {
		    if (scamper_addr_cmp(hi->hop_addr, hj->hop_addr) != 0)
			continue; // not a loop
		    if (j == i + 1) {
			if (SCAMPER_TRACE_HOP_IS_ICMP_TTL_EXP(hj)) {
			    /* TTL expired from R at hop N-1 followed by TTL
			     * expired from R at hop N is _not_ a loop, but
			     * really an anonymous router at distance N-1 that
			     * decrements TTL but then forwards to R instead
			     * of generating an error, so R generates an error
			     * for it. */
			    while ((hj = trace->hops[j])) {
				trace->hops[j] = trace->hops[j]->hop_next;
				scamper_trace_hop_free(hj);
			    }
			    break; // not a loop
			} else if (j == trace->hop_count - 1) {
			    /* TTL expired from R at hop N-1 followed by
			     * another error from R at hop N, where N is the
			     * last hop, is _not_ a loop, but simply a single
			     * router at distance N-1 that tests TTL before
			     * testing for the other error. */
			    continue; // not a loop
			}
		    }
		    hop_count_loopless = i+1;
//printf("hop_count_loopless:%d,%d\n",hop_count_loopless,trace->hop_count);
		    goto loop_found_exit;
		}
	    }
	}
    }
    loop_found_exit:

    foundhop = 0;
    for (i = hop_count_loopless - 1; i >= 0; i--) {
	scamper_trace_hop_t *hop;
	if (!trace->hops[i]) {
	    if (foundhop) noresponse++;
	    continue;
	}
	foundhop = 1;
	if (trace->hops[i]->hop_next)
	    multiresponse++;
	for (hop = trace->hops[i]; hop; hop = hop->hop_next) {
	    struct in_addr *addr = (struct in_addr*)(hop->hop_addr->addr);
	    ipset_add(ipset, ntohl(addr->s_addr));
	    hopcount++;
	}
    }

    scamper_trace_hop_t *last_hop;
    for (i = 1; i < hop_count_loopless; i++) {
	scamper_trace_hop_t *hi;
	for (hi = trace->hops[i]; hi; hi = hi->hop_next) {
	    last_hop = hi;
	    scamper_trace_hop_t *hj;
	    for (hj = trace->hops[i-1]; hj; hj = hj->hop_next) {
		iplink_t findkey;
		int cmp = scamper_addr_cmp(hi->hop_addr, hj->hop_addr);
		if (true == unidirectional ) {
		    if (cmp == 0) {
			continue;
		    } else {
			findkey.x = *(struct in_addr*)hj->hop_addr->addr;
			findkey.y = *(struct in_addr*)hi->hop_addr->addr;
//fprintf(stdout, "%d,%s\t", i,inet_ntoa(findkey.x));
//fprintf(stdout, "%s\n", inet_ntoa(findkey.y));
		    }
		} else {
		    /* We store links in a consistent order so we don't have
		     * to search for it twice. */
		    if (cmp < 0) {
			findkey.x = *(struct in_addr*)hi->hop_addr->addr;
			findkey.y = *(struct in_addr*)hj->hop_addr->addr;
		    } else if (cmp > 0) {
			findkey.x = *(struct in_addr*)hj->hop_addr->addr;
			findkey.y = *(struct in_addr*)hi->hop_addr->addr;
		    } else {
			continue;
		    }
		}
		if (!find_hash_entry(linkset, &findkey)) {
		    iplink_t *inskey = malloc(sizeof(iplink_t));
		    *inskey = findkey;
		    add_hash_entry(linkset, inskey);
		}
	    }
	}
    }

    tracecount++;
}

int main(int argc, char *argv[])
{
    const char *cycledir, *cyclebase;
    DIR *dir = NULL;
    struct dirent *dirent = NULL;
    FILE *rin;
    scamper_file_t *sin;
    scamper_file_filter_t *filter;
    scamper_trace_t *trace;
    char cmd[2048];
    uint16_t type;
    int status;
    int fd;
    const char *outdir = ".";
    char statfilename[1024];
    char ipfilename[1024];
    char linkfilename[1024];
    FILE *statfile;
    FILE *ipfile;
    FILE *linkfile;
    int opt;
    int unidirectional = false;

    while ((opt = getopt(argc, argv, "uo:")) != -1) {
        switch(opt) {
	case 'u':
	    unidirectional = true;
	    break;
	case 'o':
	    outdir = strdup(optarg);
	    break;
	default:
	    fprintf(stderr, "usage:  %s [-o<dir>] <cycledir>...\n", argv[0]);
	    exit(1);
	}
    }

    type = SCAMPER_FILE_OBJ_TRACE;
    if (!(filter = scamper_file_filter_alloc(&type, 1))) {
	fprintf(stderr, "could not allocate filter\n");
	exit(1);
    }

    for ( ; optind < argc; optind++) {
	cycledir = argv[optind];
	cyclebase = strrchr(cycledir, '/');
	cyclebase = cyclebase ? cyclebase + 1 : cycledir;
	fprintf(stderr, "cycle: %s\n", cyclebase);
	dir = opendir(cycledir);
	if (!dir) {
	    fprintf(stderr, "can't read %s: %s\n", cycledir, strerror(errno));
	    exit(1);
	}
	sprintf(statfilename, "%s/%s.stats", outdir, cyclebase);
	if (!(statfile = fopen(statfilename, "w"))) {
	    fprintf(stderr, "can't open %s: %s\n",
		statfilename, strerror(errno));
	    exit(1);
	}
	sprintf(ipfilename, "%s/%s.addrs", outdir, cyclebase);
	if (!(ipfile = fopen(ipfilename, "w"))) {
	    fprintf(stderr, "can't open %s: %s\n",
		ipfilename, strerror(errno));
	    exit(1);
	}
	sprintf(linkfilename, "%s/%s.links", outdir, cyclebase);
	if (!(linkfile = fopen(linkfilename, "w"))) {
	    fprintf(stderr, "can't open %s: %s\n",
		linkfilename, strerror(errno));
	    exit(1);
	}
	if (ipset) ipset_free(ipset);
	ipset = ipset_new();
	if (!ipset) {
	    fprintf(stderr, "can't allocate ipset\n");
	    exit(1);
	}
	if (linkset) free_hash_table(linkset);
	linkset = init_hash_table("ip links", iplink_cmp, iplink_hash, free,
	    2097151);
	if (!linkset) {
	    fprintf(stderr, "can't allocate linkset\n");
	    exit(1);
	}
	tracecount = 0;
	multiresponse = 0;
	noresponse = 0;
	hopcount = 0;
	loopcount = 0;
	filecount = 0;

	while ((dirent = readdir(dir))) {
	    if (strncmp(dirent->d_name, "daily.", 6) != 0)
		continue;
	    fprintf(stderr, "  file: %s\n", dirent->d_name);
	    snprintf(cmd, sizeof(cmd), "exec gzip -dc %s/%s",
		cycledir, dirent->d_name);
	    if (!(rin = popen(cmd, "r"))) {
		fprintf(stderr, "can't open %s: %s\n",
		    dirent->d_name, strerror(errno));
		exit(1);
	    }
	    if ((fd = dup(fileno(rin))) < 0) {
		fprintf(stderr, "can't dup: %s\n", strerror(errno));
		exit(1);
	    }

	    if (!(sin = scamper_file_openfd(fd, dirent->d_name, 'r',"warts"))) {
		fprintf(stderr, "can't read %s: %s\n",
		    dirent->d_name, strerror(errno));
		exit(1);
	    }

	    while (scamper_file_read(sin, filter, &type, (void *)&trace) == 0) {
		if (!trace) break; /* EOF */
		process_trace(trace, unidirectional);
		scamper_trace_free(trace);
		//break; // XXX
	    }

	    scamper_file_close(sin);
	    status = pclose(rin);

	    if (status == -1) {
		fprintf(stderr, "  gzip: error: %s\n", strerror(errno));
		exit(1);
	    } else if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) != 0) {
		    fprintf(stderr, "  gzip: exited: %d\n",WEXITSTATUS(status));
		}
	    } else if (WIFSIGNALED(status)) {
		fprintf(stderr, "  gzip: signaled: %d\n", WTERMSIG(status));
		exit(1);
	    } else if (WIFSTOPPED(status)) {
		fprintf(stderr, "  gzip: stopped: %d\n", WSTOPSIG(status));
		exit(1);
	    }
	    filecount++;
	    // if (filecount >= 3) break; // XXX
	}

	closedir(dir);
	fprintf(statfile,
	    "cycle: %s\nfiles: %d\nloop traces: %ld\ngood traces: %ld\n"
	    "hops with no responses: %ld\n"
	    "hops with multiple responses: %ld\n"
	    "hop responses: %ld\n"
	    "addrs: %ld\n"
	    "links: %ld\n",
	    cyclebase, filecount, loopcount, tracecount,
	    noresponse, multiresponse, hopcount,
	    ipset_count(ipset),
	    num_hash_entries(linkset));
	fclose(statfile);
	ipset_dump(ipset, ipfile);
	fclose(ipfile);
	{
	    iplink_t *iplink;
	    init_hash_walk(linkset);
	    while ((iplink = next_hash_walk(linkset))) {
		fprintf(linkfile, "%s\t", inet_ntoa(iplink->x));
		fprintf(linkfile, "%s\n", inet_ntoa(iplink->y));
	    }
	}
	fclose(linkfile);
    }

    return 0;
}
