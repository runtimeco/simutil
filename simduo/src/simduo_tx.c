#include <assert.h>
#include <string.h>
#include <unistd.h>
#include "cjson/cJSON.h"
#include "defs/error.h"
#include "os/os.h"
#include "simduo/simduo.h"
#include "simduo_priv.h"

static uint32_t simduo_tx_seq;

int
simduo_tx(cJSON *map)
{
    struct os_mbuf *om;
    uint16_t hdr;
    size_t len;
    char *text;
    int rc;

    om = NULL;

    cJSON_AddItemToObject(map, "ver", cJSON_CreateNumber(SIMDUO_VERSION));
    cJSON_AddItemToObject(map, "seq", cJSON_CreateNumber(simduo_tx_seq++));

    text = cJSON_Print(map);
    if (text == NULL) {
        rc = SYS_ENOMEM;
        goto done;
    }

    len = strlen(text);
    if (len > SIMDUO_MAX_MSG_SZ) {
        rc = SYS_EINVAL;
        goto done;
    }

    om = os_msys_get_pkthdr(sizeof hdr + len, 0);
    if (om == NULL) {
        rc = SYS_ENOMEM;
        goto done;
    }

    hdr = htons(len);
    rc = os_mbuf_append(om, &hdr, sizeof hdr);
    if (rc != 0) {
        rc = SYS_ENOMEM;
        goto done;
    }

    rc = os_mbuf_append(om, text, len);
    if (rc != 0) {
        rc = SYS_ENOMEM;
        goto done;
    }

    rc = simduo_enqueue_tx(om);
    om = NULL;

done:
    free(text);
    cJSON_Delete(map);
    os_mbuf_free_chain(om);
    return rc;
}
