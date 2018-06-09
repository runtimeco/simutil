#include <stddef.h>
#include <string.h>
#include "cjson/cJSON.h"
#include "defs/error.h"
#include "simduo/simduo.h"
#include "simduo_priv.h"

#define SIMDUO_RX_MAX_PROTOS    16

struct simduo_rx_dispatch_entry {
    const char *proto;
    simduo_rx_fn *cb;
    void *arg;
};

static struct simduo_rx_dispatch_entry
simduo_rx_dispatch_table[SIMDUO_RX_MAX_PROTOS];

static int simduo_rx_dispatch_table_sz;

int
simduo_rx_dispatch_add(const char *proto, simduo_rx_fn *cb, void *arg)
{
    struct simduo_rx_dispatch_entry *entry;

    if (simduo_rx_dispatch_table_sz >= SIMDUO_RX_MAX_PROTOS) {
        return SYS_ENOMEM;
    }

    entry = &simduo_rx_dispatch_table[simduo_rx_dispatch_table_sz++];
    entry->proto = proto;
    entry->cb = cb;
    entry->arg = arg;

    return 0;
}

const struct simduo_rx_dispatch_entry *
simduo_rx_dispatch_find(const char *proto)
{
    const struct simduo_rx_dispatch_entry *entry;
    int i;

    for (i = 0; i < simduo_rx_dispatch_table_sz; i++) {
        entry = simduo_rx_dispatch_table + i;
        if (strcmp(entry->proto, proto) == 0) {
            return entry;
        }
    }

    return NULL;
}

int
simduo_rx(cJSON *map)
{
    const struct simduo_rx_dispatch_entry *entry;
    const char *proto;
    int rc;

    proto = simduo_get_string(map, "protocol", &rc);
    if (rc != 0) {
        return rc;
    }

    entry = simduo_rx_dispatch_find(proto);
    if (entry == NULL) {
        return SYS_ERANGE;
    }

    entry->cb(map, entry->arg);
    return 0;
}
