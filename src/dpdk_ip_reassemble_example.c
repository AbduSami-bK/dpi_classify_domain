/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2021 Intel Corporation
 */

// #include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
// #include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/param.h>

#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_common.h>
// #include <rte_cpuflags.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_interrupts.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
// #include <malloc.h>>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_per_lcore.h>
#include <rte_prefetch.h>
// #include <rte_vect.h>
#include <rte_random.h>
#include <rte_string_fns.h>
// #include <rte_tcp.h>
// #include <rte_udp.h>

// #include <cmdline_parse.h>
// #include <cmdline_parse_etheraddr.h>

#define MAX_PKT_BURST   32

#define MAX_RX_QUEUE_PER_LCORE 16

#define RTE_LOGTYPE_IP_RSMBL RTE_LOGTYPE_USER1

static_assert(MEMPOOL_CACHE_SIZE >= MAX_PKT_BURST, "MAX_PKT_BURST should be at most MEMPOOL_CACHE_SIZE");

/*
 * Configurable number of RX ring descriptors
 */
#define RX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RX_DESC_DEFAULT;

/* allow max jumbo frame 9.5 KB */
#define JUMBO_FRAME_MAX_SIZE    0x2600
#define MAX_JUMBO_PKT_LEN       9600

/*
 * The overhead from max frame size to MTU.
 * We have to consider the max possible overhead.
 */
#define MTU_OVERHEAD    \
    (RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN + \
        2 * sizeof(struct rte_vlan_hdr))

/*
 * Max number of fragments per packet expected - defined by config file.
 */
#define    MAX_PACKET_FRAG RTE_LIBRTE_IP_RSMBL_MAX_FRAG

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET    3

volatile bool force_quit = false;

/* ethernet addresses of ports */
uint64_t dest_eth_addr[RTE_MAX_ETHPORTS];
struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

#ifndef IPv4_BYTES
#define IPv4_BYTES_FMT "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8
#define IPv4_BYTES(addr) \
        (uint8_t) (((addr) >> 24) & 0xFF),\
        (uint8_t) (((addr) >> 16) & 0xFF),\
        (uint8_t) (((addr) >> 8) & 0xFF),\
        (uint8_t) ((addr) & 0xFF)
#endif

#ifndef IPv6_BYTES
#define IPv6_BYTES_FMT "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"\
                       "%02x%02x:%02x%02x:%02x%02x:%02x%02x"
#define IPv6_BYTES(addr) \
    addr[0],  addr[1], addr[2],  addr[3], \
    addr[4],  addr[5], addr[6],  addr[7], \
    addr[8],  addr[9], addr[10], addr[11],\
    addr[12], addr[13],addr[14], addr[15]
#endif

#define IPV6_ADDR_LEN 16

/* mask of enabled ports */
uint32_t enabled_port_mask = 0;

static int rx_queue_per_lcore = 1;

#define MBUF_TABLE_SIZE  (2 * MAX(MAX_PKT_BURST, MAX_PACKET_FRAG))

struct mbuf_table {
    uint16_t len;
    struct rte_mbuf *m_table[MBUF_TABLE_SIZE];
};

struct rx_queue {
    struct rte_mempool *direct_pool;
    struct rte_mempool *indirect_pool;
    struct rte_lpm *lpm;
    struct rte_lpm6 *lpm6;
    uint32_t portid;
};

struct __rte_cache_aligned lcore_queue_conf {
    uint16_t n_rx_queue;
    struct rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
};

struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

static struct rte_eth_conf port_conf = {
    .rxmode = {
        .mtu = JUMBO_FRAME_MAX_SIZE - RTE_ETHER_HDR_LEN - RTE_ETHER_CRC_LEN,
        .mq_mode = RTE_ETH_MQ_RX_RSS,
        .offloads = (RTE_ETH_RX_OFFLOAD_CHECKSUM | RTE_ETH_RX_OFFLOAD_SCATTER),
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf = RTE_ETH_RSS_IP,
        },
    },
};

#define LPM_MAX_RULES         1024
#define LPM6_MAX_RULES         1024
#define LPM6_NUMBER_TBL8S (1 << 16)

struct rte_lpm6_config lpm6_config = {
        .max_rules = LPM6_MAX_RULES,
        .number_tbl8s = LPM6_NUMBER_TBL8S,
        .flags = 0
};

static struct rte_mempool *socket_direct_pool[RTE_MAX_NUMA_NODES];
static struct rte_mempool *socket_indirect_pool[RTE_MAX_NUMA_NODES];
static struct rte_lpm *socket_lpm[RTE_MAX_NUMA_NODES];
static struct rte_lpm6 *socket_lpm6[RTE_MAX_NUMA_NODES];

/* main processing loop */
static int
main_loop(__rte_unused void *dummy)
{
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    unsigned lcore_id;
    uint64_t diff_tsc, cur_tsc, prev_tsc;
    int i, j, nb_rx;
    uint16_t portid;
    struct lcore_queue_conf *qconf;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

    prev_tsc = 0;

    lcore_id = rte_lcore_id();
    qconf = &lcore_queue_conf[lcore_id];

    if (qconf->n_rx_queue == 0) {
        RTE_LOG(INFO, IP_RSMBL, "lcore %u has nothing to do\n", lcore_id);
        return 0;
    }

    RTE_LOG(INFO, IP_RSMBL, "entering main loop on lcore %u\n", lcore_id);

    for (i = 0; i < qconf->n_rx_queue; i++) {
        portid = qconf->rx_queue_list[i].portid;
        RTE_LOG(INFO, IP_RSMBL, " -- lcoreid=%u portid=%u\n", lcore_id,
            portid);
    }

    while (force_quit) {
        cur_tsc = rte_rdtsc();

        /*
         * Read packet from RX queues
         */
        for (i = 0; i < qconf->n_rx_queue; ++i) {
            portid = qconf->rx_queue_list[i].portid;

            nb_rx = rte_eth_rx_burst(portid, 0, pkts_burst,
                MAX_PKT_BURST);

            /* Prefetch first packets */
            for (j = 0; j < PREFETCH_OFFSET && j < nb_rx; j++) {
                rte_prefetch0(rte_pktmbuf_mtod(
                        pkts_burst[j], void *));
            }
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
        if (lcore_params[i].port_id == port) {
            if (lcore_params[i].queue_id == queue+1)
                queue = lcore_params[i].queue_id;
            else
                rte_exit(EXIT_FAILURE, "queue ids of the port %d must be"
                        " in sequence and must start with 0\n",
                        lcore_params[i].port_id);
        }
    }
    return (uint16_t)(++queue);
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
                (unsigned int) nb_rx_queue + 1, lcore);
            return -1;
        } else {
            lcore_conf[lcore].rx_queue_list[nb_rx_queue].port_id = lcore_params[i].port_id;
            lcore_conf[lcore].rx_queue_list[nb_rx_queue].queue_id = lcore_params[i].queue_id;
            ++(lcore_conf[lcore].n_rx_queue);
        }
    }
    return 0;
}

/* display usage */
static void
print_usage(const char *prgname)
{
    char alg[PATH_MAX];

    usage_acl_alg(alg, sizeof(alg));
    fprintf(stderr, "%s [EAL options] --"
                    " -p PORTMASK"
                    " [-q NQ]\n"
                    "  -p PORTMASK: Hexadecimal bitmask of ports to configure\n"
                    "  -q NQ: number of queue (=ports) per lcore (default is 1)\n",
        prgname);
}

static int
parse_max_pkt_len(const char *pktlen)
{
    char *end = NULL;
    unsigned long len;

    /* parse decimal string */
    len = strtoul(pktlen, &end, 10);
    if ((pktlen[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;

    if (len == 0)
        return -1;

    return len;
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
parse_nqueue(const char *q_arg)
{
    char *end = NULL;
    unsigned long n;

    /* parse hexadecimal string */
    n = strtoul(q_arg, &end, 10);
    if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;
    if (n == 0)
        return -1;
    if (n >= MAX_RX_QUEUE_PER_LCORE)
        return -1;

    return n;
}

static const char short_options[] =
    "p:"    /* portmask */
    "q:"    /* nqueue */
    "L"     /* legacy enable long prefix match */
    "E"     /* legacy enable exact match */
    ;

static const struct option long_options[] = {
    {NULL, 0, 0, 0}
};

/*
 * This expression is used to calculate the number of mbufs needed
 * depending on user input, taking  into account memory for rx and
 * tx hardware rings, cache per lcore and mtable per port per lcore.
 * RTE_MAX is used to ensure that NB_MBUF never goes below a minimum
 * value of 8192
 */
#define NB_MBUF(nports) RTE_MAX(            \
    (nports * nb_rx_queue * nb_rxd          \
    + nports * nb_lcores * MAX_PKT_BURST    \
    + nb_lcores * MEMPOOL_CACHE_SIZE),      \
    (unsigned)8192                          \
)

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
    int opt, ret;
    char **argvopt;
    int option_index;
    char *prgname = argv[0];
    uint8_t lcore_params = 0;
    int speed_num;

    argvopt = argv;

    /* Error or normal output strings. */
    while ((opt = getopt_long(argc, argvopt, short_options,
                long_options, &option_index)) != EOF) {

        switch (opt) {
        /* portmask */
        case 'p':
            enabled_port_mask = parse_portmask(optarg);
            if (enabled_port_mask == 0) {
                fprintf(stderr, "Invalid portmask\n");
                print_usage(prgname);
                return -1;
            }
            break;

        /* nqueue */
        case 'q':
            rx_queue_per_lcore = parse_nqueue(optarg);
            if (rx_queue_per_lcore < 0) {
                printf("invalid queue number\n");
                print_usage(prgname);
                return -1;
            }
            break;

        /* long options */
        case 0:
            print_usage(prgname);
            return -1;

        default:
            print_usage(prgname);
            return -1;
        }
    }

    if (optind >= 0)
        argv[optind-1] = prgname;

    ret = optind-1;
    optind = 1; /* reset getopt lib */
    return ret;
}

static void
print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr)
{
    char buf[RTE_ETHER_ADDR_FMT_SIZE];
    rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
    printf("%s%s", name, buf);
}

int
init_mem(void)
{
    struct rte_mempool *mp;
    struct rte_lpm *lpm;
    struct rte_lpm6 *lpm6;
    struct rte_lpm_config lpm_config;
    int socketid;
    unsigned lcore_id;
    char buf[PATH_MAX];

    /* traverse through lcores and initialize structures on each socket */
    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; ++lcore_id) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;

        if (numa_on) {
            socketid = rte_lcore_to_socket_id(lcore_id);

            if (socketid == SOCKET_ID_ANY)
                socketid = 0;
            else if (socketid >= NB_SOCKETS) {
                rte_exit(EXIT_FAILURE,
                    "Socket %d of lcore %u is out of range %d\n",
                    socketid, lcore_id, NB_SOCKETS);
            }
        } else
            socketid = 0;

        if (socket_direct_pool[socketid] == NULL) {
            RTE_LOG(INFO, IP_RSMBL, "Creating direct mempool on socket %i\n", socketid);
            snprintf(buf, sizeof(buf), "pool_direct_%i", socketid);

            mp = rte_pktmbuf_pool_create(buf, NB_MBUF, mb_mempool_cache_size, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
            if (mp == NULL) {
                RTE_LOG(ERR, IP_RSMBL, "Cannot create direct mempool\n");
                return -1;
            }
            socket_direct_pool[socketid] = mp;
        }

        if (socket_indirect_pool[socketid] == NULL) {
            RTE_LOG(INFO, IP_RSMBL, "Creating indirect mempool on socket %i\n", socketid);
            snprintf(buf, sizeof(buf), "pool_indirect_%i", socketid);

            mp = rte_pktmbuf_pool_create(buf, NB_MBUF, 32, 0, 0, socketid);
            if (mp == NULL) {
                RTE_LOG(ERR, IP_RSMBL, "Cannot create indirect mempool\n");
                return -1;
            }
            socket_indirect_pool[socketid] = mp;
        }

        if (socket_lpm[socketid] == NULL) {
            RTE_LOG(INFO, IP_RSMBL, "Creating LPM table on socket %i\n", socketid);
            snprintf(buf, sizeof(buf), "IP_RSMBL_LPM_%i", socketid);

            lpm_config.max_rules = LPM_MAX_RULES;
            lpm_config.number_tbl8s = 256;
            lpm_config.flags = 0;

            lpm = rte_lpm_create(buf, socketid, &lpm_config);
            if (lpm == NULL) {
                RTE_LOG(ERR, IP_RSMBL, "Cannot create LPM table\n");
                return -1;
            }
            socket_lpm[socketid] = lpm;
        }

        if (socket_lpm6[socketid] == NULL) {
            RTE_LOG(INFO, IP_RSMBL, "Creating LPM6 table on socket %i\n", socketid);
            snprintf(buf, sizeof(buf), "IP_RSMBL_LPM_%i", socketid);

            lpm6 = rte_lpm6_create(buf, socketid, &lpm6_config);
            if (lpm6 == NULL) {
                RTE_LOG(ERR, IP_RSMBL, "Cannot create LPM table\n");
                return -1;
            }
            socket_lpm6[socketid] = lpm6;
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
    char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];

    printf("\nChecking link status");
    fflush(stdout);
    for (count = 0; count <= MAX_CHECK_TIME; count++) {
        if (force_quit)
            return;
        all_ports_up = 1;
        RTE_ETH_FOREACH_DEV(portid) {
            if (force_quit)
                return;
            if ((port_mask & (1 << portid)) == 0)
                continue;
            memset(&link, 0, sizeof(link));
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
                rte_eth_link_to_str(link_status_text,
                    sizeof(link_status_text), &link);
                printf("Port %d %s\n", portid,
                       link_status_text);
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

static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit...\n", signum);
        force_quit = true;
    }
}

static uint32_t
eth_dev_get_overhead_len(uint32_t max_rx_pktlen, uint16_t max_mtu)
{
    uint32_t overhead_len;

    if (max_mtu != UINT16_MAX && max_rx_pktlen > max_mtu)
        overhead_len = max_rx_pktlen - max_mtu;
    else
        overhead_len = RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN;

    return overhead_len;
}

int
config_port_max_pkt_len(struct rte_eth_conf *conf,
        struct rte_eth_dev_info *dev_info)
{
    uint32_t overhead_len;

    if (max_pkt_len == 0)
        return 0;

    if (max_pkt_len < RTE_ETHER_MIN_LEN || max_pkt_len > MAX_JUMBO_PKT_LEN)
        return -1;

    overhead_len = eth_dev_get_overhead_len(dev_info->max_rx_pktlen,
            dev_info->max_mtu);
    conf->rxmode.mtu = max_pkt_len - overhead_len;

    return 0;
}

static int
check_ptype(int portid)
{
    int i, ret;
    int ptype_l3_ipv4 = 0, ptype_l3_ipv6 = 0;
    uint32_t ptype_mask = RTE_PTYPE_L3_MASK;

    ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, NULL, 0);
    if (ret <= 0)
        return 0;

    uint32_t ptypes[ret];

    ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, ptypes, ret);
    for (i = 0; i < ret; ++i) {
        if (ptypes[i] & RTE_PTYPE_L3_IPV4)
            ptype_l3_ipv4 = 1;
        if (ptypes[i] & RTE_PTYPE_L3_IPV6)
            ptype_l3_ipv6 = 1;
    }

    if (ptype_l3_ipv4 == 0)
        printf("port %d cannot parse RTE_PTYPE_L3_IPV4\n", portid);

    if (ptype_l3_ipv6 == 0)
        printf("port %d cannot parse RTE_PTYPE_L3_IPV6\n", portid);

    if (ptype_l3_ipv4 && ptype_l3_ipv6)
        return 1;

    return 0;
}

/* Parse packet type of a packet by SW */
static inline void
parse_ptype(struct rte_mbuf *m)
{
    struct rte_ether_hdr *eth_hdr;
    uint32_t packet_type = RTE_PTYPE_UNKNOWN;
    uint16_t ether_type;

    eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    ether_type = eth_hdr->ether_type;
    if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
        packet_type |= RTE_PTYPE_L3_IPV4_EXT_UNKNOWN;
    else if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))
        packet_type |= RTE_PTYPE_L3_IPV6_EXT_UNKNOWN;

    m->packet_type = packet_type;
}

/* callback function to detect packet type for a queue of a port */
static uint16_t
cb_parse_ptype(uint16_t port __rte_unused, uint16_t queue __rte_unused,
           struct rte_mbuf *pkts[], uint16_t nb_pkts,
           uint16_t max_pkts __rte_unused,
           void *user_param __rte_unused)
{
    uint16_t i;

    for (i = 0; i < nb_pkts; ++i)
        parse_ptype(pkts[i]);

    return nb_pkts;
}

static void
poll_resource_setup(void)
{
    uint8_t socketid;
    uint16_t nb_rx_queue, queue;
    struct rte_eth_dev_info dev_info;
    uint32_t nb_lcores;
    struct lcore_queue_conf *qconf;
    uint16_t queueid = 0, portid;
    uint16_t nb_ports;
    unsigned int lcore_id = 0, rx_lcore_id = 0;
    int ret;

    if (check_lcore_params() < 0)
        rte_exit(EXIT_FAILURE, "check_lcore_params failed\n");

    ret = init_lcore_rx_queues();
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "init_lcore_rx_queues failed\n");

    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No ports found!\n");

    if (check_port_config() < 0)
        rte_exit(EXIT_FAILURE, "check_port_config failed\n");

    nb_lcores = rte_lcore_count();

    /* initialize all ports */
    RTE_ETH_FOREACH_DEV(portid) {
        struct rte_eth_rxconf rxq_conf;
        struct rte_eth_conf local_port_conf = port_conf;

        /* skip ports that are not enabled */
        if ((enabled_port_mask & (1 << portid)) == 0) {
            printf("Skipping disabled port %d\n", portid);
            continue;
        }

        qconf = &lcore_queue_conf[rx_lcore_id];

        /* init port */
        printf("Initializing port %d ... ", portid);
        fflush(stdout);

        nb_rx_queue = get_port_n_rx_queues(portid);

        /* limit the frame size to the maximum supported by NIC */
        ret = rte_eth_dev_info_get(portid, &dev_info);
        if (ret != 0)
            rte_exit(EXIT_FAILURE, "Error during getting device (port %u) info: %s\n", portid, strerror(-ret));

        ret = config_port_max_pkt_len(&local_port_conf, &dev_info);
        if (ret != 0)
            rte_exit(EXIT_FAILURE, "Invalid max packet length: %u (port %u)\n", max_pkt_len, portid);

        local_port_conf.rxmode.mtu = RTE_MIN(
            dev_info.max_mtu,
            local_port_conf.rxmode.mtu);

        /* get the lcore_id for this port */
        while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
               qconf->n_rx_queue == (unsigned)rx_queue_per_lcore) {

            rx_lcore_id++;
            if (rx_lcore_id >= RTE_MAX_LCORE)
                rte_exit(EXIT_FAILURE, "Not enough cores\n");

            qconf = &lcore_queue_conf[rx_lcore_id];
        }

        socketid = (int) rte_lcore_to_socket_id(rx_lcore_id);
        if (socketid == SOCKET_ID_ANY)
            socketid = 0;

        rxq = &qconf->rx_queue_list[qconf->n_rx_queue];
        rxq->portid = portid;
        rxq->direct_pool = socket_direct_pool[socketid];
        rxq->indirect_pool = socket_indirect_pool[socketid];
        rxq->lpm = socket_lpm[socketid];
        rxq->lpm6 = socket_lpm6[socketid];
        qconf->n_rx_queue++;

        /* init port */
        printf("Initializing port %d on lcore %u...", portid,
               rx_lcore_id);
        fflush(stdout);

        ret = rte_eth_dev_configure(portid, nb_rx_queue, 0, &local_port_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%d\n",
                ret, portid);

        /* set the mtu to the maximum received packet size */
        ret = rte_eth_dev_set_mtu(portid, local_port_conf.rxmode.mtu);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "Set MTU failed: err=%d, port=%d\n",
                ret, portid);

        /* init one RX queue */
        rxq_conf = dev_info.default_rxconf;
        rxq_conf.offloads = local_port_conf.rxmode.offloads;
        ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd,
                         socketid, &rxq_conf,
                         socket_direct_pool[socketid]);
        if (ret < 0) {
            printf("\n");
            rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err=%d, port=%d\n",
                ret, portid);
        }

        ret = rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
        if (ret < 0)
            rte_exit(EXIT_FAILURE,
                "\nrte_eth_macaddr_get: err=%d, port=%d\n",
                ret, portid);
    }
}

int
main(int argc, char **argv)
{
    struct lcore_conf *qconf;
    uint16_t queueid, portid;
    unsigned int lcore_id;
    uint16_t queue;
    int ret;
    struct rx_queue *rxq;

    /* init EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
    argc -= ret;
    argv += ret;

    force_quit = false;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* parse application arguments (after the EAL ones) */
    ret = parse_args(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid App parameters\n");

    /* initialize structures (mempools, lpm etc.) */
    if (init_mem() < 0)
        rte_panic("Cannot initialize memory structures!\n");

    /* check if portmask has non-existent ports */
    if (enabled_port_mask & ~(RTE_LEN2MASK(nb_ports, unsigned)))
        rte_exit(EXIT_FAILURE, "Non-existent ports in portmask!\n");

    poll_resource_setup();

    /* start ports */
    RTE_ETH_FOREACH_DEV(portid) {
        if ((enabled_port_mask & (1 << portid)) == 0) {
            continue;
        }
        /* Start device */
        ret = rte_eth_dev_start(portid);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%d\n",
                ret, portid);

        if (promiscuous_on) {
            ret = rte_eth_promiscuous_enable(portid);
            if (ret != 0)
                rte_exit(EXIT_FAILURE, "rte_eth_promiscuous_enable: err=%s, port=%u\n", rte_strerror(-ret), portid);
        }

        if (check_ptype(portid) == 0) {
            rte_eth_add_rx_callback(portid, 0, cb_parse_ptype, NULL);
            printf("Add Rx callback function to detect L3 packet type by SW :"
                " port = %d\n", portid);
        }
    }

    check_all_ports_link_status(enabled_port_mask);

    /* launch per-lcore init on every lcore */
    rte_eal_mp_remote_launch(main_loop, NULL, CALL_MAIN);

    rte_eal_mp_wait_lcore();

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

    return ret;
}
