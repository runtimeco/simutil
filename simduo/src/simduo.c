#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "os/mynewt.h"
#include "native_sockets/native_sock.h"
#include "mn_socket/mn_socket.h"
#include "simduo/simduo.h"
#include "simduo_priv.h"

#define SIMDUO_STACK_SIZE   (OS_STACK_ALIGN(512))

static void simduo_socket_readable(void *unused, int err);
static void simduo_socket_writable(void *unused, int err);
static int simduo_socket_newconn(void *cb_arg, struct mn_socket *new);

static const union mn_socket_cb simduo_connected_socket_cbs = {
    .socket = {
        .readable = simduo_socket_readable,
        .writable = simduo_socket_writable,
    },
};

static const union mn_socket_cb simduo_listen_socket_cbs = {
    .listen = {
        .newconn = simduo_socket_newconn,
    },
};

static bool simduo_server;
static char *simduo_server_addr_str = "127.0.0.1";
static const uint16_t simduo_server_port = 9919;

struct mn_socket *simduo_socket;
struct mn_socket *simduo_listen_socket;
static struct mn_sockaddr_in simduo_server_sin;

static struct os_task simduo_task;
OS_TASK_STACK_DEFINE(simduo_stack, SIMDUO_STACK_SIZE);

static struct os_eventq simduo_evq;
static struct os_mqueue simduo_rx_mq;
static struct os_mqueue simduo_tx_mq;
static struct os_mbuf *simduo_packet;
static uint16_t simduo_packet_len;

static void
simduo_log_mbuf(const struct os_mbuf *om)
{
    uint8_t u8;
    int rc;
    int i;

    if (MYNEWT_VAL(LOG_LEVEL) > LOG_LEVEL_DEBUG) {
        return;
    }

    for (i = 0; i < OS_MBUF_PKTLEN(om); i++) {
        rc = os_mbuf_copydata(om, i, 1, &u8);
        assert(rc == 0);
        SIMDUO_LOG(DEBUG, "%s0x%02x", i == 0 ? "" : " ", u8);
    }
    SIMDUO_LOG(DEBUG, "\n");
}

int
simduo_enqueue_tx(struct os_mbuf *om)
{
    int rc;

    rc = os_mqueue_put(&simduo_tx_mq, &simduo_evq, om);
    assert(rc == 0);

    return 0;
}

static int
simduo_process_tx(struct os_mbuf *om)
{
    int rc;

    // XXX: MUTEX
    if (simduo_socket == NULL) {
        return SYS_ENODEV;
    }

    SIMDUO_LOG(DEBUG, "Sending %d bytes\n", OS_MBUF_PKTLEN(om));

    simduo_log_mbuf(om);
    rc = native_sock_sendto(simduo_socket, om,
                            (struct mn_sockaddr *)&simduo_server_sin);
    return rc;
}

static void
simduo_process_tx_mq(struct os_event *ev)
{
    struct os_mbuf *om;
    os_sr_t sr;
    int rc;

    while ((om = os_mqueue_get(&simduo_tx_mq)) != NULL) {
        rc = simduo_process_tx(om);
        if (rc == MN_EAGAIN) {
            /* Socket cannot accommodate packet; try again later. */
            OS_ENTER_CRITICAL(sr);
            STAILQ_INSERT_HEAD(&simduo_tx_mq.mq_head,
                               OS_MBUF_PKTHDR(om),
                               omp_next);
            OS_EXIT_CRITICAL(sr);
            break;
        } else if (rc != 0) {
            SIMDUO_LOG(INFO, "native_sock_sendto() failed; rc=%d\n", rc);
            break;
        }
    }
}

static void
simduo_process_rx(struct os_mbuf *om)
{
    cJSON *map;
    char *json;
    //int send_rsp;
    int rc;

    map = NULL;

    json = malloc_success(OS_MBUF_PKTLEN(om) + 1);

    SIMDUO_LOG(DEBUG, "Received %d bytes\n", OS_MBUF_PKTLEN(om));
    rc = os_mbuf_copydata(om, 0, OS_MBUF_PKTLEN(om), json);
    if (rc != 0) {
        SIMDUO_LOG(ERROR, "os_mbuf_copydata() failed: rc=%d\n", rc);
        goto done;
    }

    json[OS_MBUF_PKTLEN(om)] = '\0';
    SIMDUO_LOG(DEBUG, "Received JSON request:\n%s\n", json);

    map = cJSON_Parse(json);
    if (map == NULL) {
        /* Drop invalid packet. */
        goto done;
    }

    simduo_rx(map);

    //send_rsp = bhd_req_dec(json, &rsp);
    //if (send_rsp) {
        //bhd_rsp_send(&rsp);
    //}

    //cJSON *tmp = cJSON_CreateObject();
    //simduo_tx(tmp);

done:
    cJSON_Delete(map);
    os_mbuf_free_chain(om);
    free(json);
}

static void
simduo_process_rx_mq(struct os_event *ev)
{
    struct os_mbuf *om;

    while ((om = os_mqueue_get(&simduo_rx_mq)) != NULL) {
        simduo_process_rx(om);
    }
}

static int
simduo_enqueue_one(void)
{
    struct os_mbuf *om;
    int rc;

    if (simduo_packet_len == 0) {
        rc = os_mbuf_copydata(simduo_packet, 0, sizeof simduo_packet_len,
                              &simduo_packet_len);
        if (rc == 0) {
            simduo_packet_len = ntohs(simduo_packet_len);

            /* Temporary hack: Allow user to bypass length header; assume
             * entire packet received in one read.
             */
            if (simduo_packet_len > SIMDUO_MAX_MSG_SZ) {
                simduo_packet_len = OS_MBUF_PKTLEN(simduo_packet);
            } else {
                os_mbuf_adj(simduo_packet, sizeof simduo_packet_len);
            }
        }
    }

    if (simduo_packet_len == 0 ||
        OS_MBUF_PKTLEN(simduo_packet) < simduo_packet_len) {

        return 0;
    }

    if (OS_MBUF_PKTLEN(simduo_packet) == simduo_packet_len) {
        om = simduo_packet;
        simduo_packet = NULL;
        simduo_packet_len = 0;
    } else {
        /* Full packet plus some (or all) of next packet received. */
        om = os_msys_get_pkthdr(simduo_packet_len, 0);
        if (om == NULL) {
            fprintf(stderr, "* Error: failed to allocate mbuf\n");
            return 0;
        }

        rc = os_mbuf_appendfrom(om, simduo_packet, 0, simduo_packet_len);
        if (rc != 0) {
            fprintf(stderr, "* Error: failed to allocate mbuf\n");
            return 0;
        }

        os_mbuf_adj(simduo_packet, simduo_packet_len);
        simduo_packet_len = 0;
    }

    rc = os_mqueue_put(&simduo_rx_mq, &simduo_evq, om);
    assert(rc == 0);

    return 1;
}

static void
simduo_socket_readable(void *unused, int err)
{
    struct mn_sockaddr_un from_addr;
    struct os_mbuf *om;
    int enqueued;
    int rc;

    if (err != 0) {
        /* Socket error. */
        return;
    }

    rc = native_sock_recvfrom(simduo_socket, &om, (void *)&from_addr);
    if (rc != 0) {
        return;
    }

    SIMDUO_LOG(DEBUG, "Rxed UDS data:\n");
    simduo_log_mbuf(om);

    if (simduo_packet == NULL) {
        /* Beginning of packet. */
        simduo_packet = om;
    } else {
        /* Continuation of packet. */
        os_mbuf_concat(simduo_packet, om);
    }

    while (1) {
        enqueued = simduo_enqueue_one();
        if (!enqueued) {
            break;
        }
    }
}

static void
simduo_socket_writable(void *unused, int err)
{
    /* XXX: Spurious event when there is nothing else left to write. */
    os_eventq_put(&simduo_evq, &simduo_tx_mq.mq_ev);
}

static int
simduo_fill_addr(struct mn_sockaddr_in *sin, const char *addr_str,
                 uint16_t port)
{
    int rc;

    rc = mn_inet_pton(MN_PF_INET, addr_str, &sin->msin_addr);
    if (rc == 0) {
        return SYS_EINVAL;
    }

    sin->msin_len = sizeof *sin;
    sin->msin_family = MN_AF_INET;
    sin->msin_port = htons(port);

    return 0;
}

static int
simduo_init_socket(void)
{
    int rc;

    rc = simduo_fill_addr(&simduo_server_sin, simduo_server_addr_str,
                          simduo_server_port);
    if (rc != 0) {
        return rc;
    }

    rc = native_sock_create(&simduo_socket, MN_PF_INET, SOCK_STREAM, 0);
    if (rc != 0) {
        return rc;
    }

    mn_socket_set_cbs(simduo_socket, NULL, &simduo_connected_socket_cbs);

    return 0;
}

static int
simduo_socket_newconn(void *cb_arg, struct mn_socket *new)
{
    struct mn_sockaddr_in peer_sin;
    int rc;

    simduo_socket = new;

    rc = mn_getpeername(new, (struct mn_sockaddr *)&peer_sin);
    if (rc != 0) {
        return rc;
    }

    SIMDUO_LOG(DEBUG, "Connection from %p\n", &peer_sin);
    mn_socket_set_cbs(simduo_socket, NULL, &simduo_connected_socket_cbs);

    return 0;
}

static int
simduo_init_listen_socket(void)
{
    int rc;

    rc = simduo_fill_addr(&simduo_server_sin, simduo_server_addr_str,
                          simduo_server_port);
    if (rc != 0) {
        return rc;
    }

    rc = native_sock_create(&simduo_listen_socket, MN_PF_INET,
                            SOCK_STREAM, 0);
    if (rc != 0) {
        return rc;
    }

    mn_socket_set_cbs(simduo_listen_socket, NULL, &simduo_listen_socket_cbs);

    return 0;
}

static int
simduo_connect_client(void)
{
    int rc;

    rc = simduo_init_socket();
    if (rc != 0) {
        return rc;
    }

    rc = native_sock_connect(simduo_socket,
                             (struct mn_sockaddr *)&simduo_server_sin);
    if (rc != 0) {
        return rc;
    }

    return 0;
}

static int
simduo_connect_server(void)
{
    int rc;

    rc = simduo_init_listen_socket();
    if (rc != 0) {
        return rc;
    }

    rc = native_sock_bind(simduo_listen_socket,
                 (struct mn_sockaddr *)&simduo_server_sin);
    if (rc != 0) {
        return rc;
    }

    rc = native_sock_listen(simduo_listen_socket, 1);
    if (rc != 0) {
        return rc;
    }

    return 0;
}

static void
simduo_task_handler(void *arg)
{
    int rc;

    if (simduo_server) {
        rc = simduo_connect_server();
    } else {
        rc = simduo_connect_client();
        if (rc == MN_EAGAIN) {
            rc = 0;
        }
    }
    assert(rc == 0);

    while (1) {
        os_eventq_run(&simduo_evq);
    }
}

void
simduo_set_server(bool server)
{
    simduo_server = server;
}

void
simduo_init(void)
{
    int rc;

    /* Ensure this function only gets called by sysinit. */
    SYSINIT_ASSERT_ACTIVE();

    os_eventq_init(&simduo_evq);

    rc = os_mqueue_init(&simduo_tx_mq, simduo_process_tx_mq, NULL);
    SYSINIT_PANIC_ASSERT(rc == 0);

    rc = os_mqueue_init(&simduo_rx_mq, simduo_process_rx_mq, NULL);
    SYSINIT_PANIC_ASSERT(rc == 0);

    os_task_init(&simduo_task, "simduo", simduo_task_handler,
                 NULL, MYNEWT_VAL(SIMDUO_TASK_PRIO), OS_WAIT_FOREVER,
                 simduo_stack, SIMDUO_STACK_SIZE);
}
