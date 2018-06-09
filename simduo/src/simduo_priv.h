#ifndef H_SIMDUO_PRIV_
#define H_SIMDUO_PRIV_

#include <stdio.h>
#include "log/log.h"
#include "cjson/cJSON.h"
struct os_mbuf;
struct mn_socket;

extern struct mn_socket *simduo_socket;

void simduo_lock(void);
void simduo_unlock(void);
int simduo_write(struct os_mbuf *om);
int simduo_rx(cJSON *map);
int simduo_enqueue_tx(struct os_mbuf *om);
void *malloc_success(size_t num_bytes);

#define SIMDUO_LOG(lvl, ...)                                    \
    do {                                                        \
        if (MYNEWT_VAL(LOG_LEVEL) <= LOG_LEVEL_ ## lvl) {       \
            dprintf(1, __VA_ARGS__);                            \
        }                                                       \
    } while (0)

#endif
