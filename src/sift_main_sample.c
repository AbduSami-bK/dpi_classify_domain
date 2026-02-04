/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2021 Intel Corporation
 */

#include <assert.h>
#include <errno.h>
#include <execinfo.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <unistd.h>

#include <rte_acl.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_interrupts.h>
#include <rte_ip.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_per_lcore.h>
#include <rte_prefetch.h>
#include <rte_vect.h>
#include <rte_random.h>
#include <rte_string_fns.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include <cmdline_parse.h>

#define DO_RFC_1812_CHECKS

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RX_DESC_DEFAULT 1024
#define TX_DESC_DEFAULT 1024

#define DEFAULT_PKT_BURST 32
#define MAX_PKT_BURST 512
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

#define MEMPOOL_CACHE_SIZE RTE_MEMPOOL_CACHE_MAX_SIZE
#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_RX_QUEUE_PER_PORT 128

#define VECTOR_SIZE_DEFAULT   MAX_PKT_BURST
#define VECTOR_TMO_NS_DEFAULT 1E6 /* 1ms */

#define NB_SOCKETS      8

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET     3

struct __rte_cache_aligned lcore_rx_queue {
    uint16_t port_id;
    uint16_t queue_id;
};

struct __rte_cache_aligned lcore_conf {
    uint16_t n_rx_queue;
    struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
    uint16_t n_tx_port;
    uint16_t tx_port_id[RTE_MAX_ETHPORTS];
    uint16_t tx_queue_id[RTE_MAX_ETHPORTS];
    struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];
    // struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];
    // void *ipv4_lookup_struct;
    // void *ipv6_lookup_struct;
};

#define MAX_LCORE_PARAMS 1024

static_assert(MEMPOOL_CACHE_SIZE >= MAX_PKT_BURST, "MAX_PKT_BURST should be at most MEMPOOL_CACHE_SIZE");
uint16_t nb_rxd = RX_DESC_DEFAULT;
uint16_t nb_txd = TX_DESC_DEFAULT;
uint32_t rx_burst_size = DEFAULT_PKT_BURST;
uint32_t mb_mempool_cache_size = MEMPOOL_CACHE_SIZE;

/**< Ports set in promiscuous mode on by default. */
static int promiscuous_on = true;

#define     RTE_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL   0x10

static struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];

#define BURST_R_DRAIN 100

/* Global variables */
static int numa_on = 1; /**< NUMA is enabled by default. */
volatile bool force_quit;

/* ethernet addresses of ports */
struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
uint32_t enabled_port_mask;

struct __rte_cache_aligned lcore_params {
    uint16_t port_id;
    uint16_t queue_id;
    uint32_t lcore_id;
};

static struct lcore_params lcore_params_array[MAX_LCORE_PARAMS];
static struct lcore_params lcore_params_array_default[] = {
    {0, 0, 2},
    {0, 1, 2},
    {0, 2, 2},
    {1, 0, 2},
    {1, 1, 2},
    {1, 2, 2},
    {2, 0, 2},
    {3, 0, 3},
    {3, 1, 3},
};

static struct lcore_params * lcore_params = lcore_params_array_default;
static uint16_t nb_lcore_params = sizeof(lcore_params_array_default) /
                sizeof(lcore_params_array_default[0]);

static struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode = RTE_ETH_MQ_RX_RSS,
        .offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf = RTE_ETH_RSS_IP,
        },
    },
    .txmode = {
        .mq_mode = RTE_ETH_MQ_TX_NONE,
    },
};

static struct rte_mempool *pktmbuf_pool[NB_SOCKETS];
#define uint32_t_to_char(ip, a, b, c, d) do {\
    *a = (unsigned char)(ip >> 24 & 0xff);\
    *b = (unsigned char)(ip >> 16 & 0xff);\
    *c = (unsigned char)(ip >> 8 & 0xff);\
    *d = (unsigned char)(ip & 0xff);\
} while (0)
#define OFF_ETHHEAD    (sizeof(struct ether_hdr))
#define OFF_IPV42PROTO (offsetof(struct rte_ipv4_hdr, next_proto_id))
#define OFF_IPV62PROTO (offsetof(struct ipv6_hdr, proto))
#define MBUF_IPV4_2PROTO(m)    \
    rte_pktmbuf_mtod_offset((m), uint8_t *, OFF_ETHHEAD + OFF_IPV42PROTO)
#define MBUF_IPV6_2PROTO(m)    \
    rte_pktmbuf_mtod_offset((m), uint8_t *, OFF_ETHHEAD + OFF_IPV62PROTO)

#define GET_CB_FIELD(in, fd, base, lim, dlm)    do {        \
    unsigned long val;                                      \
    char *end;                                              \
    errno = 0;                                              \
    val = strtoul((in), &end, (base));                      \
    if (errno != 0 || end[0] != (dlm) || val > (lim))       \
        return -EINVAL;                                     \
    (fd) = (typeof(fd))val;                                 \
    (in) = end + 1;                                         \
} while (0)

static struct lcore_conf lcore_conf[RTE_MAX_LCORE];
int lcores[RTE_MAX_LCORE];

#ifdef DO_RFC_1812_CHECKS
static inline int
is_valid_ipv4_pkt(struct rte_ipv4_hdr *pkt, uint32_t link_len, uint64_t ol_flags)
{
    /* From http://www.rfc-editor.org/rfc/rfc1812.txt section 5.2.2 */
    /*
     * 1. The packet length reported by the Link Layer must be large
     * enough to hold the minimum length legal IP datagram (20 bytes).
     */
    if (link_len < sizeof(struct rte_ipv4_hdr))
        return -1;

    /* 2. The IP checksum must be correct. */
    /* if this is not checked in H/W, check it. */
    if ((ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK) == RTE_MBUF_F_RX_IP_CKSUM_NONE) {
        uint16_t actual_cksum, expected_cksum;
        actual_cksum = pkt->hdr_checksum;
        pkt->hdr_checksum = 0;
        expected_cksum = rte_ipv4_cksum(pkt);
        if (actual_cksum != expected_cksum)
            return -2;
    }

    /*
     * 3. The IP version number must be 4. If the version number is not 4
     * then the packet may be another version of IP, such as IPng or
     * ST-II.
     */
    if (((pkt->version_ihl) >> 4) != 4)
        return -3;
    /*
     * 4. The IP header length field must be large enough to hold the
     * minimum length legal IP datagram (20 bytes = 5 words).
     */
    if ((pkt->version_ihl & 0xf) < 5)
        return -4;

    /*
     * 5. The IP total length field must be large enough to hold the IP
     * datagram header, whose length is specified in the IP header length
     * field.
     */
    if (rte_cpu_to_be_16(pkt->total_length) < sizeof(struct rte_ipv4_hdr))
        return -5;

    return 0;
}
#endif /* DO_RFC_1812_CHECKS */

static int
set_enabled_lcores(void)
{
    int lcore_id;
    int i = 0;

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; ++lcore_id) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;
        lcores[i] = lcore_id;
        ++i;
    }

    return i;
}

static void
remote_launch_modules(void)
{
    int ret;
    int i;
    set_enabled_lcores();

    for (i = 0; i < nb_modules; ++i) {
        rte_delay_us_block(20 * 1000);

        if (mlp_mapping[i].lcore == lcores[0] || rte_lcore_is_enabled(mlp_mapping[i].lcore) == 0) {
            if ((mlp_mapping[i].lcore) == 255) {
                sift_log(INFO, MAIN, "Disabled Module: %s", mlp_mapping[i].module_name);
                continue;
            }
            rte_exit(EXIT_FAILURE, "Cannot launch %s module on lcore %u\n", mlp_mapping[i].module_name, mlp_mapping[i].lcore);
        }
        if (strncmp(mlp_mapping[i].module_name, "log_handler", strlen(mlp_mapping[i].module_name) - 1) == 0) {
            rte_eal_remote_launch(logDequeuer, NULL, mlp_mapping[i].lcore);
        } else {
            rte_exit(EXIT_FAILURE, "\tMDF 2.0 :: Invalid Module Name %s\n", mlp_mapping[i].module_name);
        }
    }
}

static int
check_lcore_params(void)
{
    uint16_t queue, i;
    uint32_t lcore;
    int socketid;

    for (i = 0; i < nb_lcore_params; ++i) {
        queue = lcore_params[i].queue_id;
        if (queue >= MAX_RX_QUEUE_PER_PORT) {
            printf("invalid queue number: %" PRIu16 "\n", queue);
            return -1;
        }

        lcore = lcore_params[i].lcore_id;
        if (!rte_lcore_is_enabled(lcore)) {
            printf("error: lcore %u is not enabled in lcore mask\n", lcore);
            return -1;
        }

        socketid = rte_lcore_to_socket_id(lcore);
        if (socketid != 0 && numa_on == 0) {
            printf("warning: lcore %u is on socket %d with numa off\n",
                lcore, socketid);
        }
    }
    return 0;
}

static int
check_port_config(void)
{
    uint16_t portid;
    uint16_t i;

    for (i = 0; i < nb_lcore_params; ++i) {
        portid = lcore_params[i].port_id;

        if ((enabled_port_mask & (1 << portid)) == 0) {
            printf("port %u is not enabled in port mask\n", portid);
            return -1;
        }
        if (!rte_eth_dev_is_valid_port(portid)) {
            printf("port %u is not present on the board\n", portid);
            return -1;
        }
    }
    return 0;
}

static uint16_t
get_port_n_rx_queues(const uint16_t port)
{
    int queue = -1;
    uint16_t i;

    for (i = 0; i < nb_lcore_params; ++i) {
        if (lcore_params[i].port_id == port &&
            lcore_params[i].queue_id > queue)
            queue = lcore_params[i].queue_id;
    }
    return (uint8_t) (++queue);
}

static int
init_lcore_rx_queues(void)
{
    uint16_t i, nb_rx_queue;
    uint32_t lcore;

    for (i = 0; i < nb_lcore_params; ++i) {
        lcore = lcore_params[i].lcore_id;
        nb_rx_queue = lcore_conf[lcore].n_rx_queue;

        if (nb_rx_queue >= MAX_RX_QUEUE_PER_LCORE) {
            printf("error: too many queues (%u) for lcore: %u\n",
                nb_rx_queue + 1, lcore);
            return -1;
        } else {
            lcore_conf[lcore].rx_queue_list[nb_rx_queue].port_id = lcore_params[i].port_id;
            lcore_conf[lcore].rx_queue_list[nb_rx_queue].queue_id = lcore_params[i].queue_id;
            ++(lcore_conf[lcore].n_rx_queue);
        }
    }
    return 0;
}

static int
parse_portmask(const char *portmask)
{
    char *end = NULL;
    unsigned long pm;

    /* parse hexadecimal string */
    pm = strtoul(portmask, &end, 16);
    if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;

    if (pm == 0)
        return -1;

    return pm;
}

static int
parse_lcore_args(void)
{
    int ret;
    int i;
    nb_lcore_params = 0;
    nb_modules = 0;
    DATAPATH_INSTANCE = 0;

    for (i = 0; i < ret; ++i) {
        char *config[3];
        int l = 0;
        char *token;

        if (nb_lcore_params >= MAX_LCORE_PARAMS) {
            printf("exceeded max number of lcore params: %hu\n",
                nb_lcore_params);
            return -1;
        }

        if (strcmp(PORT_LCORE_PARAMS[i].name, "packet_receiver") == 0) {
            ++RPARSER_INSTANCE;
            sprintf(mlp_mapping[nb_modules].module_name, "packet_receiver%d", RPARSER_INSTANCE);
        }
        for (token = strtok(PORT_LCORE_PARAMS[i].value, ","); token != NULL; token = strtok(NULL, ",")) {
            config[l] = token;
            ++l;
        }

        uint8_t temp_port  = atoi(config[0]);
        uint8_t temp_queue = atoi(config[1]);
        uint8_t temp_lcore = atoi(config[2]);
        if (temp_port != 255 || temp_queue != 255) {
            lcore_params_array[nb_lcore_params].port_id  = temp_port;
            lcore_params_array[nb_lcore_params].queue_id = temp_queue;
            lcore_params_array[nb_lcore_params].lcore_id = temp_lcore;

            ++nb_lcore_params;
        }

        mlp_mapping[nb_modules].port  = temp_port;
        mlp_mapping[nb_modules].queue = temp_queue;
        mlp_mapping[nb_modules].lcore = temp_lcore;
        ++nb_modules;

    }

    lcore_params = lcore_params_array;
    return ret;
}

/*
 * This expression is used to calculate the number of mbufs needed
 * depending on user input, taking  into account memory for rx and
 * tx hardware rings, cache per lcore and mtable per port per lcore.
 * RTE_MAX is used to ensure that NB_MBUF never goes below a minimum
 * value of 8192
 */
#define NB_MBUF(nports) RTE_MAX(          \
    (nports * nb_rx_queue * nb_rxd +      \
     nports * nb_lcores * MAX_PKT_BURST + \
     nports * n_tx_queue * nb_txd +       \
     nb_lcores * MEMPOOL_CACHE_SIZE),     \
    (unsigned)8192)

/* Parse the argument given in the command line of the application */
static int
parse_app_args(int argc, char **argv)
{
    int opt, ret;

    for (int i = 0; i < ret; ++i) {
        if (strcmp(APP_PARAMS[i].name, "port_mask") == 0) {
            /* Port Mask */
            enabled_port_mask = parse_portmask(APP_PARAMS[i].value);
            if (enabled_port_mask == 0) {
                rte_exit(EXIT_FAILURE, "Invalid portmask\n");
            }
        } else if (strcmp(APP_PARAMS[i].name, "promiscuous") == 0) {
        /* Promiscuous Mode */
            if (strcmp(APP_PARAMS[i].value, "yes") == 0) {
                sift_log(ERROR, MAIN, "Promiscuous mode enabled");
                promiscuous_on = 1;
            }
        }
    }

    return ret;
}

static void
print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr)
{
    char buf[RTE_ETHER_ADDR_FMT_SIZE];
    rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
    printf("%s:%s\n", name, buf);
}

int
init_mem(unsigned int nb_mbuf)
{
    int socketid;
    unsigned lcore_id;
    char s[64];

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; ++lcore_id) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;

        if (numa_on)
            socketid = rte_lcore_to_socket_id(lcore_id);
        else
            socketid = 0;

        if (socketid >= NB_SOCKETS) {
            rte_exit(EXIT_FAILURE,
                "Socket %d of lcore %u is out of range %d\n",
                socketid, lcore_id, NB_SOCKETS);
        }

        if (pktmbuf_pool[socketid] == NULL) {
            snprintf(s, sizeof (s), "mbuf_pool_%d", socketid);
            pktmbuf_pool[socketid] =
                rte_pktmbuf_pool_create(s, nb_mbuf,
                    MEMPOOL_CACHE_SIZE, 0,
                    RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
            if (pktmbuf_pool[socketid] == NULL) {
                rte_exit(EXIT_FAILURE,
                    "Cannot init mbuf pool on socket %d\n",
                    socketid);
            } else {
                printf("Allocated mbuf pool on socket %d\n",
                    socketid);
            }
        }
    }
    return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
    uint16_t portid;
    uint8_t count, all_ports_up, print_flag = 0;
    struct rte_eth_link link;
    int ret;

    printf("\nChecking link status");
    fflush(stdout);
    for (count = 0; count <= MAX_CHECK_TIME; ++count) {
        if (force_quit)
            return;
        all_ports_up = 1;
        RTE_ETH_FOREACH_DEV(portid) {
            if (force_quit)
                return;
            if ((port_mask & (1 << portid)) == 0)
                continue;
            memset(&link, 0, sizeof (link));
            ret = rte_eth_link_get_nowait(portid, &link);
            if (ret < 0) {
                all_ports_up = 0;
                if (print_flag == 1)
                    printf("Port %u link get failed: %s\n",
                        portid, rte_strerror(-ret));
                continue;
            }
            /* print link status if flag set */
            if (print_flag == 1) {
                if (link.link_status) {
                    printf(
                        "Port%d Link Up. Speed %u Mbps %s\n",
                        portid, link.link_speed,
                        (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                        ("full-duplex") : ("half-duplex\n"));
                } else
                    printf("Port %d Link Down\n", portid);
                continue;
            }
            /* clear all_ports_up flag if any link down */
            if (link.link_status == RTE_ETH_LINK_DOWN) {
                all_ports_up = 0;
                break;
            }
        }
        /* after finally printing all link status, get out */
        if (print_flag == 1)
            break;

        if (all_ports_up == 0) {
            printf(".");
            fflush(stdout);
            rte_delay_ms(CHECK_INTERVAL);
        }

        /* set the print_flag if all ports up or timeout */
        if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
            print_flag = 1;
            printf("done\n");
        }
    }
}

/* main datapath loop */
static int
datapath_loop(__attribute__ ((unused)) void *dummy)
{
    //rte_log_set_level(RTE_LOGTYPE_USER1, RTE_LOG_DEBUG);
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    struct rte_mbuf *pPacket;
    unsigned lcore_id;
    uint64_t prev_tsc, diff_tsc, cur_tsc;
    uint64_t prev_parse_time, diff_parse_time, cur_parse_time;
    int i,j,nb_rx;
    uint16_t portid;
    uint8_t queueid;
    struct lcore_conf *qconf;
    int socketid;
    uint64_t rx_pkt = 0;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1)
            / US_PER_S * BURST_TX_DRAIN_US;
    prev_tsc = 0;
    lcore_id = rte_lcore_id();
    qconf = &lcore_conf[lcore_id];
    socketid = rte_lcore_to_socket_id(lcore_id);

    if (qconf->n_rx_queue == 0) {
        sift_log(ALERT, DATAPATH, "lcore %u has nothing to do\n", lcore_id);
        return ;
    }
    for (i = 0; i < qconf->n_rx_queue; ++i) {
        portid = qconf->rx_queue_list[i].port_id;
        queueid = qconf->rx_queue_list[i].queue_id;
        sift_log(ALERT, DATAPATH,
            " -- lcoreid=%u portid=%u rxqueueid=%hhu\n",
            lcore_id, portid, queueid);
    }
    while (!force_quit) {
        cur_tsc = rte_rdtsc();
        /*
         * TX burst queue drain
         */
        diff_tsc = cur_tsc - prev_tsc;
        if (unlikely(diff_tsc > drain_tsc)) {
            for (i = 0; i < qconf->n_tx_port; ++i) {
                portid = qconf->tx_port_id[i];
                rte_eth_tx_buffer_flush(portid,
                                        qconf->tx_queue_id[portid],
                                        qconf->tx_buffer[portid]);
            }
            prev_tsc = cur_tsc;
        }
        /*
         * Read packet from RX queues
         */
        for (i = 0; i < qconf->n_rx_queue; ++i) {
            portid = qconf->rx_queue_list[i].port_id;
            queueid = qconf->rx_queue_list[i].queue_id;
            nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst, MAX_PKT_BURST);
            for (j = 0; j < nb_rx; ++j) {
                prev_parse_time = rte_rdtsc();
                ++rx_pkt;
                pPacket = pkts_burst[j];

                rte_prefetch0(rte_pktmbuf_mtod(pPacket, void *));
                // Send logic

                diff_parse_time = rte_rdtsc() - prev_parse_time;
            }
        }
    }
}

static void
poll_resource_setup(void)
{
    uint8_t socketid;
    uint16_t nb_rx_queue, queue;
    struct rte_eth_dev_info dev_info;
    uint32_t n_tx_queue, nb_lcores;
    struct rte_eth_txconf *txconf;
    struct lcore_conf *qconf;
    uint16_t queueid, portid;
    unsigned int nb_ports;
    unsigned int lcore_id;
    int ret;

    if (check_lcore_params() < 0)
        rte_exit(EXIT_FAILURE, "check_lcore_params failed\n");

    ret = init_lcore_rx_queues();
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "init_lcore_rx_queues failed\n");

    nb_ports = rte_eth_dev_count_avail();

    if (check_port_config() < 0)
        rte_exit(EXIT_FAILURE, "check_port_config failed\n");

    nb_lcores = rte_lcore_count();

    /* Initialize all ports */
    RTE_ETH_FOREACH_DEV(portid) {
        struct rte_eth_conf local_port_conf = port_conf;

        /* skip ports that are not enabled */
        if ((enabled_port_mask & (1 << portid)) == 0) {
            printf("\nSkipping disabled port %d\n", portid);
            continue;
        }

        /* init port */
        printf("Initializing port %d ... ", portid);
        fflush(stdout);

        nb_rx_queue = get_port_n_rx_queues(portid);
        n_tx_queue = nb_lcores;
        if (n_tx_queue > MAX_TX_QUEUE_PER_PORT)
            n_tx_queue = MAX_TX_QUEUE_PER_PORT;
        printf("Creating queues: nb_rxq=%d nb_txq=%u... ", nb_rx_queue, (unsigned)n_tx_queue);

        ret = rte_eth_dev_info_get(portid, &dev_info);
        if (ret != 0)
            rte_exit(EXIT_FAILURE, "Error during getting device (port %u) info: %s\n", portid, strerror(-ret));

        if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
            local_port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

        local_port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
        if (local_port_conf.rx_adv_conf.rss_conf.rss_hf != port_conf.rx_adv_conf.rss_conf.rss_hf) {
            printf("Port %u modified RSS hash function based on hardware support,"
                "requested:%#"PRIx64" configured:%#"PRIx64"\n",
                portid,
                port_conf.rx_adv_conf.rss_conf.rss_hf,
                local_port_conf.rx_adv_conf.rss_conf.rss_hf);
        }

        ret = rte_eth_dev_configure(portid, nb_rx_queue, (uint16_t)n_tx_queue, &local_port_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE,
                "Cannot configure device: err=%d, port=%d\n",
                ret, portid);

        ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
        if (ret < 0)
            rte_exit(EXIT_FAILURE,
                "Cannot adjust number of descriptors: err=%d, port=%d\n",
                ret, portid);

        /* init memory */
        ret = init_mem(NB_MBUF);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "init_mem failed\n");

        /* init one TX queue per couple (lcore,port) */
        queueid = 0;
        for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; ++lcore_id) {
            if (rte_lcore_is_enabled(lcore_id) == 0)
                continue;

            if (numa_on)
                socketid = (uint8_t) rte_lcore_to_socket_id(lcore_id);
            else
                socketid = 0;

            printf("txq=%u,%d,%d ", lcore_id, queueid, socketid);
            fflush(stdout);

            txconf = &dev_info.default_txconf;
            txconf->offloads = local_port_conf.txmode.offloads;
            ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd,
                             socketid, txconf);
            if (ret < 0)
                rte_exit(EXIT_FAILURE,
                    "rte_eth_tx_queue_setup: err=%d, "
                    "port=%d\n", ret, portid);

            qconf = &lcore_conf[lcore_id];
            qconf->tx_queue_id[portid] = queueid;
            queueid++;

            qconf->tx_port_id[qconf->n_tx_port] = portid;
            qconf->n_tx_port++;
        }
        printf("\n");
    }

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;

        nb_cores[cores] = lcore_id;
        cores++;

        qconf = &lcore_conf[lcore_id];
        printf("\nInitializing rx queues on lcore %u ... ", lcore_id);
        fflush(stdout);
        /* init RX queues */
        for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
            struct rte_eth_dev *dev;
            struct rte_eth_conf *conf;
            struct rte_eth_rxconf rxq_conf;

            portid = qconf->rx_queue_list[queue].port_id;
            queueid = qconf->rx_queue_list[queue].queue_id;
            dev = &rte_eth_devices[portid];
            conf = &dev->data->dev_conf;

            if (numa_on)
                socketid = (uint8_t) rte_lcore_to_socket_id(lcore_id);
            else
                socketid = 0;

            printf("rxq=%d,%d,%d ", portid, queueid, socketid);
            fflush(stdout);

            ret = rte_eth_dev_info_get(portid, &dev_info);
            if (ret != 0)
                rte_exit(EXIT_FAILURE,
                    "Error during getting device (port %u) info: %s\n",
                    portid, strerror(-ret));
            rxq_conf = dev_info.default_rxconf;
            rxq_conf.offloads = conf->rxmode.offloads;
            ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd,
                    socketid, &rxq_conf,
                    pktmbuf_pool[socketid]);
            if (ret < 0)
                rte_exit(EXIT_FAILURE,
                    "rte_eth_rx_queue_setup: err=%d, port=%d\n", ret, portid);
        }
    }
}

int
main(int argc, char **argv)
{
    struct lcore_conf *qconf;
    uint16_t queueid, portid;
    unsigned int lcore_id;
    int ret;

    /* init EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
    argc -= ret;
    argv += ret;

    /* parse application arguments (after the EAL ones) */
    ret = parse_app_args();
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid App parameters\n");

    ret = parse_lcore_args();
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid lcore parameters\n");

    int nb_cores[RTE_MAX_LCORE];
    int cores = 0;

        rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
        print_ethaddr(" Address:", &ports_eth_addr[portid]);
        printf(", ");

        for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
            if (rte_lcore_is_enabled(lcore_id) == 0) {
                continue;
            }
            /* Initialize TX buffers */
            qconf = &lcore_conf[lcore_id];
            qconf->tx_buffer[portid] = rte_zmalloc_socket("tx_buffer",
                    RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
                    rte_eth_dev_socket_id(portid));
            if (qconf->tx_buffer[portid] == NULL)
                rte_exit(EXIT_FAILURE, "Can't allocate tx buffer for port %u\n",
                        (unsigned) portid);

            rte_eth_tx_buffer_init(qconf->tx_buffer[portid], MAX_PKT_BURST);
        }

    poll_resource_setup();

    /* start ports */
    RTE_ETH_FOREACH_DEV(portid) {
        if ((enabled_port_mask & (1 << portid)) == 0) {
            continue;
        }
        /* Start device */
        ret = rte_eth_dev_start(portid);
        if (ret < 0)
            rte_exit(EXIT_FAILURE,
                "rte_eth_dev_start: err=%d, port=%d\n",
                ret, portid);

        /*
         * If enabled, put device in promiscuous mode.
         * This allows IO forwarding mode to forward packets
         * to itself through 2 cross-connected  ports of the
         * target machine.
         */
        if (promiscuous_on) {
            ret = rte_eth_promiscuous_enable(portid);
            if (ret != 0)
                rte_exit(EXIT_FAILURE, "rte_eth_promiscuous_enable: err=%s, port=%u\n", rte_strerror(-ret), portid);
        }
    }

    check_all_ports_link_status(enabled_port_mask);

    /* launch per-lcore init on every lcore */
    remote_launch_modules();

    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0)
            return EXIT_FAILURE;
    }

    /* stop ports */
    RTE_ETH_FOREACH_DEV(portid) {
        if ((enabled_port_mask & (1 << portid)) == 0)
            continue;
        printf("Closing port %d...", portid);
        ret = rte_eth_dev_stop(portid);
        if (ret != 0)
            printf("rte_eth_dev_stop: err=%d, port=%u\n", ret, portid);
        rte_eth_dev_close(portid);
        printf(" Done\n");
    }
    /* clean up the EAL */
    rte_eal_cleanup();

    return EXIT_SUCCESS;
}
