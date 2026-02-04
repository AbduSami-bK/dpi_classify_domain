/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2021 Intel Corporation
 */

#include <assert.h>
#include <errno.h>
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

#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cpuflags.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_interrupts.h>
#include <rte_ip.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
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
#include <cmdline_parse_etheraddr.h>

#define MAX_PKT_BURST   32

#define MAX_RX_QUEUE_PER_PORT 128

#define MAX_LCORE_PARAMS 1024

static_assert(MEMPOOL_CACHE_SIZE >= MAX_PKT_BURST, "MAX_PKT_BURST should be at most MEMPOOL_CACHE_SIZE");
uint16_t nb_rxd = RX_DESC_DEFAULT;
uint32_t rx_burst_size = MAX_PKT_BURST;
uint32_t mb_mempool_cache_size = MEMPOOL_CACHE_SIZE;

/* allow max jumbo frame 9.5 KB */
#define JUMBO_FRAME_MAX_SIZE    0x2600
#define MAX_JUMBO_PKT_LEN       9600

/**< Ports set in promiscuous mode on by default. */
static int promiscuous_on = true;

/* Global variables. */
static int numa_on = 1; /**< NUMA is enabled by default. */
static int parse_ptype; /**< Parse packet type using rx callback, and */
            /**< disabled by default */
static int disable_rss; /**< Disable RSS mode */
static int relax_rx_offload; /**< Relax Rx offload mode, disabled by default */

volatile bool force_quit;

/* ethernet addresses of ports */
uint64_t dest_eth_addr[RTE_MAX_ETHPORTS];
struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

xmm_t val_eth[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
uint32_t enabled_port_mask = 0;

/* Used only in exact match mode. */
int ipv6; /**< ipv6 is false by default. */

struct lcore_conf lcore_conf[RTE_MAX_LCORE];

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

uint32_t max_pkt_len;

static struct rte_mempool *pktmbuf_pool[NB_SOCKETS];

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
                    " [-P]"
                    " [--lookup]"
                    " --config (port,queue,lcore)[,(port,queue,lcore)]"
                    " [--rx-queue-size NPKTS]"
                    " [--rx-burst NPKTS]"
                    " [--mbcache CACHESZ]"
                    " [--eth-dest=X,MM:MM:MM:MM:MM:MM]"
                    " [--max-pkt-len PKTLEN]"
                    " [--no-numa]"
                    " [--ipv6]"
                    " [--parse-ptype]"

                    "  -p PORTMASK: Hexadecimal bitmask of ports to configure\n"
                    "  -P : Enable promiscuous mode\n"
                    "  --lookup: Select the lookup method\n"
                    "            Default: lpm\n"
                    "            Accepted: em (Exact Match), lpm (Longest Prefix Match), fib (Forwarding Information Base),\n"
                    "                      acl (Access Control List)\n"
                    "  --config (port,queue,lcore): Rx queue configuration\n"
                    "  --eth-link-speed: force link speed\n"
                    "  --rx-queue-size NPKTS: Rx queue size in decimal\n"
                    "  --rx-burst NPKTS: RX Burst size in decimal\n"
                    "  --mbcache CACHESZ: Mbuf cache size in decimal\n"
                    "  --eth-dest=X,MM:MM:MM:MM:MM:MM: Ethernet destination for port X\n"
                    "  --max-pkt-len PKTLEN: maximum packet length in decimal (64-9600)\n"
                    "  --no-numa: Disable numa awareness\n"
                    "  --ipv6: Set if running ipv6 packets\n"
                    "  --parse-ptype: Set to use software to analyze packet type\n",
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
        return 0;

    return pm;
}

static int
parse_config(const char *q_arg)
{
    char s[256];
    const char *p, *p0 = q_arg;
    char *end;
    enum fieldnames {
        FLD_PORT = 0,
        FLD_QUEUE,
        FLD_LCORE,
        _NUM_FLD
    };
    unsigned long int_fld[_NUM_FLD];
    char *str_fld[_NUM_FLD];
    int i;
    unsigned size;
    uint16_t max_fld[_NUM_FLD] = {
        RTE_MAX_ETHPORTS,
        RTE_MAX_QUEUES_PER_PORT,
        RTE_MAX_LCORE
    };

    nb_lcore_params = 0;

    while ((p = strchr(p0,'(')) != NULL) {
        ++p;
        if((p0 = strchr(p,')')) == NULL)
            return -1;

        size = p0 - p;
        if(size >= sizeof(s))
            return -1;

        snprintf(s, sizeof(s), "%.*s", size, p);
        if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
            return -1;
        for (i = 0; i < _NUM_FLD; i++){
            errno = 0;
            int_fld[i] = strtoul(str_fld[i], &end, 0);
            if (errno != 0 || end == str_fld[i] || int_fld[i] > max_fld[i])
                return -1;
        }
        if (nb_lcore_params >= MAX_LCORE_PARAMS) {
            printf("exceeded max number of lcore params: %hu\n",
                nb_lcore_params);
            return -1;
        }
        lcore_params_array[nb_lcore_params].port_id =
            (uint16_t)int_fld[FLD_PORT];
        lcore_params_array[nb_lcore_params].queue_id =
            (uint16_t)int_fld[FLD_QUEUE];
        lcore_params_array[nb_lcore_params].lcore_id =
            (uint32_t)int_fld[FLD_LCORE];
        ++nb_lcore_params;
    }
    lcore_params = lcore_params_array;
    return 0;
}

static void
parse_queue_size(const char *queue_size_arg, uint16_t *queue_size, int rx)
{
    char *end = NULL;
    unsigned long value;

    /* parse decimal string */
    value = strtoul(queue_size_arg, &end, 10);
    if ((queue_size_arg[0] == '\0') || (end == NULL) ||
        (*end != '\0') || (value == 0)) {
        if (rx == 1)
            rte_exit(EXIT_FAILURE, "Invalid rx-queue-size\n");
        else
            rte_exit(EXIT_FAILURE, "Invalid tx-queue-size\n");

        return;
    }

    if (value > UINT16_MAX) {
        if (rx == 1)
            rte_exit(EXIT_FAILURE, "rx-queue-size %lu > %d\n",
                value, UINT16_MAX);
        else
            rte_exit(EXIT_FAILURE, "tx-queue-size %lu > %d\n",
                value, UINT16_MAX);

        return;
    }

    *queue_size = value;
}

static void
parse_mbcache_size(const char *optarg)
{
    unsigned long mb_cache_size;
    char *end = NULL;

    mb_cache_size = strtoul(optarg, &end, 10);
    if ((optarg[0] == '\0') || (end == NULL) || (*end != '\0'))
        return;
    if (mb_cache_size <= RTE_MEMPOOL_CACHE_MAX_SIZE)
        mb_mempool_cache_size = (uint32_t)mb_cache_size;
    else
        rte_exit(EXIT_FAILURE, "mbcache must be >= 0 and <= %d\n",
             RTE_MEMPOOL_CACHE_MAX_SIZE);
}

static void
parse_pkt_burst(const char *optarg, bool is_rx_burst, uint32_t *burst_sz)
{
    struct rte_eth_dev_info dev_info;
    unsigned long pkt_burst;
    uint16_t burst_size;
    char *end = NULL;
    int ret;

    /* parse decimal string */
    pkt_burst = strtoul(optarg, &end, 10);
    if ((optarg[0] == '\0') || (end == NULL) || (*end != '\0'))
        return;

    if (pkt_burst > MAX_PKT_BURST) {
        RTE_LOG(INFO, L3FWD, "User provided burst must be <= %d. Using default value %d\n",
            MAX_PKT_BURST, *burst_sz);
        return;
    } else if (pkt_burst > 0) {
        *burst_sz = (uint32_t)pkt_burst;
        return;
    }

    if (is_rx_burst) {
        /* If user gives a value of zero, query the PMD for its recommended
         * Rx burst size.
         */
        ret = rte_eth_dev_info_get(0, &dev_info);
        if (ret != 0)
            return;
        burst_size = dev_info.default_rxportconf.burst_size;
        if (burst_size == 0) {
            RTE_LOG(INFO, L3FWD, "PMD does not recommend a burst size. Using default value %d. "
                "User provided value must be in [1, %d]\n",
                rx_burst_size, MAX_PKT_BURST);
            return;
        } else if (burst_size > MAX_PKT_BURST) {
            RTE_LOG(INFO, L3FWD, "PMD recommended burst size %d exceeds maximum value %d. "
                "Using default value %d\n",
                burst_size, MAX_PKT_BURST, rx_burst_size);
            return;
        }
        *burst_sz = burst_size;
        RTE_LOG(INFO, L3FWD, "Using PMD-provided RX burst value %d\n", burst_size);
    } else {
        RTE_LOG(INFO, L3FWD, "User provided TX burst is 0. Using default value %d\n",
            *burst_sz);
    }
}

static const char short_options[] =
    "p:"    /* portmask */
    "L"     /* legacy enable long prefix match */
    "E"     /* legacy enable exact match */
    ;

#define CMD_LINE_OPT_CONFIG "config"
#define CMD_LINK_OPT_ETH_LINK_SPEED "eth-link-speed"
#define CMD_LINE_OPT_RX_QUEUE_SIZE "rx-queue-size"
#define CMD_LINE_OPT_ETH_DEST "eth-dest"
#define CMD_LINE_OPT_NO_NUMA "no-numa"
#define CMD_LINE_OPT_IPV6 "ipv6"
#define CMD_LINE_OPT_MAX_PKT_LEN "max-pkt-len"
#define CMD_LINE_OPT_HASH_ENTRY_NUM "hash-entry-num"
#define CMD_LINE_OPT_PARSE_PTYPE "parse-ptype"
#define CMD_LINE_OPT_DISABLE_RSS "disable-rss"
#define CMD_LINE_OPT_RELAX_RX_OFFLOAD "relax-rx-offload"
#define CMD_LINE_OPT_PKT_RX_BURST "rx-burst"
#define CMD_LINE_OPT_MB_CACHE_SIZE "mbcache"

enum {
    /* long options mapped to a short option */

    /* first long only option value must be >= 256, so that we won't
     * conflict with short options */
    CMD_LINE_OPT_MIN_NUM = 256,
    CMD_LINE_OPT_CONFIG_NUM,
    CMD_LINK_OPT_ETH_LINK_SPEED_NUM,
    CMD_LINE_OPT_RX_QUEUE_SIZE_NUM,
    CMD_LINE_OPT_ETH_DEST_NUM,
    CMD_LINE_OPT_NO_NUMA_NUM,
    CMD_LINE_OPT_IPV6_NUM,
    CMD_LINE_OPT_MAX_PKT_LEN_NUM,
    CMD_LINE_OPT_HASH_ENTRY_NUM_NUM,
    CMD_LINE_OPT_PARSE_PTYPE_NUM,
    CMD_LINE_OPT_DISABLE_RSS_NUM,
    CMD_LINE_OPT_RELAX_RX_OFFLOAD_NUM,
    CMD_LINE_OPT_PKT_RX_BURST_NUM,
    CMD_LINE_OPT_MB_CACHE_SIZE_NUM,
};

static const struct option lgopts[] = {
    {CMD_LINE_OPT_CONFIG, 1, 0, CMD_LINE_OPT_CONFIG_NUM},
    {CMD_LINK_OPT_ETH_LINK_SPEED, 1, 0, CMD_LINK_OPT_ETH_LINK_SPEED_NUM},
    {CMD_LINE_OPT_RX_QUEUE_SIZE, 1, 0, CMD_LINE_OPT_RX_QUEUE_SIZE_NUM},
    {CMD_LINE_OPT_ETH_DEST, 1, 0, CMD_LINE_OPT_ETH_DEST_NUM},
    {CMD_LINE_OPT_NO_NUMA, 0, 0, CMD_LINE_OPT_NO_NUMA_NUM},
    {CMD_LINE_OPT_IPV6, 0, 0, CMD_LINE_OPT_IPV6_NUM},
    {CMD_LINE_OPT_MAX_PKT_LEN, 1, 0, CMD_LINE_OPT_MAX_PKT_LEN_NUM},
    {CMD_LINE_OPT_HASH_ENTRY_NUM, 1, 0, CMD_LINE_OPT_HASH_ENTRY_NUM_NUM},
    {CMD_LINE_OPT_PARSE_PTYPE, 0, 0, CMD_LINE_OPT_PARSE_PTYPE_NUM},
    {CMD_LINE_OPT_RELAX_RX_OFFLOAD, 0, 0, CMD_LINE_OPT_RELAX_RX_OFFLOAD_NUM},
    {CMD_LINE_OPT_DISABLE_RSS, 0, 0, CMD_LINE_OPT_DISABLE_RSS_NUM},
    {CMD_LINE_OPT_PKT_RX_BURST,   1, 0, CMD_LINE_OPT_PKT_RX_BURST_NUM},
    {CMD_LINE_OPT_MB_CACHE_SIZE,   1, 0, CMD_LINE_OPT_MB_CACHE_SIZE_NUM},
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
                lgopts, &option_index)) != EOF) {

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
        case CMD_LINE_OPT_CONFIG_NUM:
            ret = parse_config(optarg);
            if (ret) {
                fprintf(stderr, "Invalid config\n");
                print_usage(prgname);
                return -1;
            }
            lcore_params = 1;
            break;

        case CMD_LINK_OPT_ETH_LINK_SPEED_NUM:
            speed_num = atoi(optarg);
            if ((speed_num == RTE_ETH_SPEED_NUM_10M) ||
                (speed_num == RTE_ETH_SPEED_NUM_100M)) {
                fprintf(stderr, "Unsupported fixed speed\n");
                print_usage(prgname);
                return -1;
            }
            if (speed_num >= 0 && rte_eth_speed_bitflag(speed_num, 0) > 0)
                port_conf.link_speeds = rte_eth_speed_bitflag(speed_num, 0);
            break;
        case CMD_LINE_OPT_RX_QUEUE_SIZE_NUM:
            parse_queue_size(optarg, &nb_rxd, 1);
            break;

        case CMD_LINE_OPT_PKT_RX_BURST_NUM:
            parse_pkt_burst(optarg, true, &rx_burst_size);
            break;

        case CMD_LINE_OPT_MB_CACHE_SIZE_NUM:
            parse_mbcache_size(optarg);
            break;

        case CMD_LINE_OPT_ETH_DEST_NUM:
            parse_eth_dest(optarg);
            break;

        case CMD_LINE_OPT_NO_NUMA_NUM:
            numa_on = 0;
            break;

        case CMD_LINE_OPT_IPV6_NUM:
            ipv6 = 1;
            break;

        case CMD_LINE_OPT_MAX_PKT_LEN_NUM:
            max_pkt_len = parse_max_pkt_len(optarg);
            break;

        case CMD_LINE_OPT_HASH_ENTRY_NUM_NUM:
            fprintf(stderr, "Hash entry number will be ignored\n");
            break;

        case CMD_LINE_OPT_PARSE_PTYPE_NUM:
            printf("soft parse-ptype is enabled\n");
            parse_ptype = 1;
            break;

        case CMD_LINE_OPT_RELAX_RX_OFFLOAD_NUM:
            printf("Rx offload is relaxed\n");
            relax_rx_offload = 1;
            break;

        case CMD_LINE_OPT_DISABLE_RSS_NUM:
            printf("RSS is disabled\n");
            disable_rss = 1;
            break;

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
init_mem(uint16_t portid, unsigned int nb_mbuf)
{
    struct lcore_conf *qconf;
    int socketid;
    unsigned lcore_id;
    char buf[64];

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

        if (pktmbuf_pool[socketid] == NULL) {
            snprintf(buf, sizeof(buf), "mbuf_pool_%d", socketid);

            pktmbuf_pool[socketid] = rte_pktmbuf_pool_create(buf, nb_mbuf, mb_mempool_cache_size, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
            if (pktmbuf_pool[portid][socketid] == NULL) {
                rte_exit(EXIT_FAILURE, "Cannot init mbuf pool on socket %d\n", socketid);
            } else {
                printf("Allocated mbuf pool on socket %d\n", socketid);
            }
        }

        qconf = &lcore_conf[lcore_id];
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

static void
poll_resource_setup(void)
{
    uint8_t socketid;
    uint16_t nb_rx_queue, queue;
    struct rte_eth_dev_info dev_info;
    uint32_t nb_lcores;
    struct lcore_conf *qconf;
    uint16_t queueid = 0, portid;
    uint16_t nb_ports;
    unsigned int lcore_id = 0;
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
        struct rte_eth_conf local_port_conf = port_conf;

        /* skip ports that are not enabled */
        if ((enabled_port_mask & (1 << portid)) == 0) {
            printf("Skipping disabled port %d\n", portid);
            continue;
        }

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

        local_port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;

        if (disable_rss == 1 || dev_info.max_rx_queues == 1)
            local_port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;

        if (local_port_conf.rx_adv_conf.rss_conf.rss_hf != port_conf.rx_adv_conf.rss_conf.rss_hf) {
            printf("Port %u modified RSS hash function based on hardware support,"
                "requested:%#"PRIx64" configured:%#"PRIx64"\n",
                portid,
                port_conf.rx_adv_conf.rss_conf.rss_hf,
                local_port_conf.rx_adv_conf.rss_conf.rss_hf);
        }

        /* Relax Rx offload requirement */
        if ((local_port_conf.rxmode.offloads & dev_info.rx_offload_capa) !=
            local_port_conf.rxmode.offloads) {
            printf("Port %u requested Rx offloads 0x%"PRIx64
                " does not match Rx offloads capabilities 0x%"PRIx64"\n",
                portid, local_port_conf.rxmode.offloads,
                dev_info.rx_offload_capa);
            if (relax_rx_offload) {
                local_port_conf.rxmode.offloads &= dev_info.rx_offload_capa;
                printf("Warning: modified Rx offload to 0x%"PRIx64
                        " based on device capability\n",
                        local_port_conf.rxmode.offloads);
            }
        }

        ret = rte_eth_dev_configure(portid, nb_rx_queue, 0, &local_port_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%d\n",
                ret, portid);

        ret = rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "Cannot get MAC address: err=%d, port=%d\n",
                ret, portid);

        /*
         * prepare src MACs for each port.
         */
        rte_ether_addr_copy(&ports_eth_addr[portid],
            (struct rte_ether_addr *)(val_eth + portid) + 1);

        /* init memory */
        ret = init_mem(0, NB_MBUF(nb_ports));
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "init_mem failed\n");
    }

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;
        qconf = &lcore_conf[lcore_id];
        printf("\nInitializing rx queues on lcore %u ... ", lcore_id);
        fflush(stdout);
        /* init RX queues */
        for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
            struct rte_eth_conf local_conf;
            struct rte_eth_rxconf rxq_conf;

            portid = qconf->rx_queue_list[queue].port_id;
            queueid = qconf->rx_queue_list[queue].queue_id;

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

            ret = rte_eth_dev_conf_get(portid, &local_conf);
            if (ret != 0)
                rte_exit(EXIT_FAILURE,
                    "Error during getting device (port %u) configuration: %s\n",
                    portid, strerror(-ret));

            rxq_conf = dev_info.default_rxconf;
            rxq_conf.offloads = local_conf.rxmode.offloads;
            if (!per_port_pool)
                ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd,
                        socketid, &rxq_conf,
                        pktmbuf_pool[0][socketid]);
            else
                ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd,
                        socketid, &rxq_conf,
                        pktmbuf_pool[portid][socketid]);
            if (ret < 0)
                rte_exit(EXIT_FAILURE,
                    "\nrte_eth_rx_queue_setup: err=%d, port=%d\n",
                    ret, portid);
        }
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

    /* init EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
    argc -= ret;
    argv += ret;

    force_quit = false;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* pre-init dst MACs for all ports to 02:00:00:00:00:xx */
    for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
        dest_eth_addr[portid] =
            RTE_ETHER_LOCAL_ADMIN_ADDR + ((uint64_t)portid << 40);
        *(uint64_t *)(val_eth + portid) = dest_eth_addr[portid];
    }

    /* parse application arguments (after the EAL ones) */
    ret = parse_args(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid App parameters\n");

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
    }

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;
        qconf = &lcore_conf[lcore_id];
        for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
            portid = qconf->rx_queue_list[queue].port_id;
            queueid = qconf->rx_queue_list[queue].queue_id;
            if (prepare_ptype_parser(portid, queueid) == 0)
                rte_exit(EXIT_FAILURE, "ptype check fails\n");
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
