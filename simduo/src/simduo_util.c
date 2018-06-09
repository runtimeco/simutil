#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "cjson/cJSON.h"
#include "defs/error.h"
#include "parse/parse.h"
#include "simduo/simduo.h"

static void
simduo_set_status(int *status, int val)
{
    if (status != NULL) {
        *status = val;
    }
}

char *
simduo_hex_str(char *dst, int max_dst_len, int *out_dst_len,
               const uint8_t *src, int src_len)
{
    int rem_len;
    int off;
    int rc;
    int i;

    off = 0;
    rem_len = max_dst_len;

    if (max_dst_len >= 1) {
        *dst = '\0';
    }

    for (i = 0; i < src_len; i++) {
        rc = snprintf(dst + off, rem_len, "%s0x%02x",
                      i > 0 ? ":" : "", src[i]);
        if (rc >= rem_len) {
            break;
        }
        off += rc;
        rem_len -= rc;
    }

    if (out_dst_len != NULL) {
        *out_dst_len = off;
    }

    return dst;
}

char *
simduo_get_string(cJSON *parent, const char *key, int *out_status)
{
    cJSON *item;

    item = cJSON_GetObjectItem(parent, key);
    if (item == NULL) {
        simduo_set_status(out_status, SYS_ENOENT);
        return NULL;
    }

    if (item->type != cJSON_String) {
        simduo_set_status(out_status, SYS_ERANGE);
        return NULL;
    }

    simduo_set_status(out_status, 0);
    return item->valuestring;
}

int
simduo_get_byte_string(cJSON *parent, const char *key, int max_len,
                       void *dst, int *out_len)
{
    char *s;
    int rc;

    s = simduo_get_string(parent, key, &rc);
    if (rc != 0) {
        return rc;
    }

    return parse_byte_stream(s, max_len, dst, out_len);
}

int
simduo_get_byte_string_exact_len(cJSON *parent, const char *key, int len,
                                 void *dst)
{
    char *s;
    int rc;

    s = simduo_get_string(parent, key, &rc);
    if (rc != 0) {
        return rc;
    }

    return parse_byte_stream_exact_length(s, dst, len);
}

int
simduo_add_protocol(cJSON *parent, const char *proto)
{
    cJSON *obj;

    obj = cJSON_CreateString(proto);
    if (obj == NULL) {
        return SYS_ENOMEM;
    }

    cJSON_AddItemToObject(parent, "protocol", obj);
    return 0;
}

static cJSON *
simduo_create_byte_string(const uint8_t *data, int len)
{
    cJSON *item;
    char *buf;
    int max_len;

    assert(len >= 0);

    max_len = len * 5 + 1; /* 0xXX: */

    buf = malloc_success(max_len);

    simduo_hex_str(buf, max_len, NULL, data, len);
    item = cJSON_CreateString(buf);

    free(buf);
    return item;
}

int
simduo_add_byte_string(cJSON *parent, const char *key, const void *val,
                       int len)
{
    cJSON *obj;

    obj = simduo_create_byte_string(val, len);
    if (obj == NULL) {
        return SYS_ENOMEM;
    }

    cJSON_AddItemToObject(parent, key, obj);
    return 0;
}

void *
malloc_success(size_t num_bytes)
{
    void *v;

    v = malloc(num_bytes);
    assert(v != NULL && "malloc returned null");

    return v;
}
