typedef struct ipset ipset_t;

ipset_t *ipset_new(void);
void ipset_add(ipset_t *ipset, uint32_t a);
int ipset_test(ipset_t *ipset, uint32_t a);
void ipset_free(ipset_t *ipset);
void ipset_iterate(ipset_t *ipset, void *data,
    void (*func)(struct in_addr, void *));
long ipset_count(ipset_t *ipset);
void ipset_dump(ipset_t *ipset, FILE *file);
