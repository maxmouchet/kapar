#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ipset.h"

typedef struct {
    unsigned char bitmap[1<<(16-3)];
} ipset_node16_t;

typedef struct {
    ipset_node16_t *node16[1<<8];
} ipset_node8_t;

struct ipset {
    ipset_node8_t *node8[1<<8];
};

static uint32_t ipset_bitcount[] = {
    0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8,
};

ipset_t *ipset_new() {
    return calloc(1, sizeof(ipset_t));
}

void ipset_add(ipset_t *ipset, uint32_t a) {
    unsigned part1 = a>>24;
    unsigned part2 = (a>>16) & 0xFF;
    unsigned part3 = (a & 0xFFFF) >> 3;
    unsigned part4 = a & 0x7;
    if (!ipset->node8[part1]) {
	ipset->node8[part1] = calloc(1, sizeof(ipset_node8_t));
    }
    if (!ipset->node8[part1]->node16[part2]) {
	ipset->node8[part1]->node16[part2] = calloc(1, sizeof(ipset_node16_t));
    }
    ipset->node8[part1]->node16[part2]->bitmap[part3] |= (1 << part4);
}

int ipset_test(ipset_t *ipset, uint32_t a) {
    unsigned part1 = a>>24;
    unsigned part2 = (a>>16) & 0xFF;
    unsigned part3 = (a & 0xFFFF) >> 3;
    unsigned part4 = a & 0x7;
    if (!ipset->node8[part1])
	return 0;
    if (!ipset->node8[part1]->node16[part2])
	return 0;
    return !!(ipset->node8[part1]->node16[part2]->bitmap[part3] & (1 << part4));
}

void ipset_free(ipset_t *ipset)
{
    int i, j;
    for (i = 0; i < (1<<8); i++) {
	if (!ipset->node8[i]) continue;
	for (j = 0; j < (1<<8); j++) {
	    if (!ipset->node8[i]->node16[j]) continue;
	    free(ipset->node8[i]->node16[j]);
	}
	free(ipset->node8[i]);
    }
    free(ipset);
}

void ipset_iterate(ipset_t *ipset, void *data,
    void (*func)(struct in_addr, void *))
{
    int i, j, k;
    struct in_addr addr;
    for (i = 0; i < (1<<8); i++) {
	if (!ipset->node8[i]) continue;
	for (j = 0; j < (1<<8); j++) {
	    if (!ipset->node8[i]->node16[j]) continue;
	    for (k = 0; k < (1<<16); k++) {
		if (ipset->node8[i]->node16[j]->bitmap[k>>3] & (1<<(k&7))) {
		    addr.s_addr = (i << 24) | (j << 16) | k;
		    addr.s_addr = htonl(addr.s_addr);
		    func(addr, data);
		}
	    }
	}
    }
}

long ipset_count(ipset_t *ipset) {
    long count = 0;
    int i, j, k;
    for (i = 0; i < (1<<8); i++) {
	if (!ipset->node8[i]) continue;
	for (j = 0; j < (1<<8); j++) {
	    if (!ipset->node8[i]->node16[j]) continue;
	    for (k = 0; k < (1<<(16-3)); k++) {
		count += ipset_bitcount[ipset->node8[i]->node16[j]->bitmap[k]];
	    }
	}
    }
    return count;
}

static void ip_print(struct in_addr addr, void *data) {
    FILE *file = data ? (FILE*)data : stdout;
    fprintf(file, "%s\n", inet_ntoa(addr));
} 

void ipset_dump(ipset_t *ipset, FILE *file) {
    ipset_iterate(ipset, file, ip_print);
}
