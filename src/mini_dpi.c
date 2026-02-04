// Mini DPI main: RX on lcore 0, worker on lcore 1
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <rte_atomic.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ring.h>

#include "app_common.h"
#include "fqdn_list.h"
#include "thread_rx.h"
#include "thread_classifier.h"

#define RX_RING_SIZE 1024
#define NUM_MBUFS    8192
#define MBUF_CACHE   256

#define DEFAULT_FRAG_TIMEOUT_MS 30000
#define DEFAULT_MAX_PRINT 1024
#define RX_TO_CLASSIFIER_RING_SIZE 4096
#define PAYLOAD_POOL_SIZE 8192

volatile bool force_quit = false;

static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        force_quit = true;
    }
}

static void
print_usage(const char *prog)
{
    printf("Usage: %s [EAL args] -- [--port N] [--auto-port] [--list-ports] [--frag-timeout-ms N] [--print-max N] [--print-payloads] [--debug-dump N]\n", prog);
}

static int
parse_app_args(int argc, char **argv, struct app_cfg *cfg)
{
    static struct option long_opts[] = {
        {"port", required_argument, NULL, 'p'},
        {"auto-port", no_argument, NULL, 'a'},
        {"list-ports", no_argument, NULL, 'l'},
        {"frag-timeout-ms", required_argument, NULL, 't'},
        {"print-max", required_argument, NULL, 'm'},
        {"print-payloads", no_argument, NULL, 'P'},
        {"debug-dump", required_argument, NULL, 'd'},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int opt_idx = 0;

    optind = 1;
    while ((opt = getopt_long(argc, argv, "", long_opts, &opt_idx)) != -1) {
        switch (opt) {
        case 'p':
            cfg->port_id = (uint16_t)atoi(optarg);
            break;
        case 'a':
            cfg->auto_port = true;
            break;
        case 'l':
            cfg->list_ports = true;
            break;
        case 't':
            cfg->frag_timeout_ms = (uint32_t)atoi(optarg);
            break;
        case 'm':
            cfg->max_print_bytes = (uint32_t)atoi(optarg);
            break;
        case 'P':
            cfg->print_payloads = true;
            break;
        case 'd':
            cfg->debug_dump_limit = (uint32_t)atoi(optarg);
            break;
        case 'h':
        default:
            print_usage(argv[0]);
            return -1;
        }
    }

    return 0;
}

static void
list_ports(void)
{
    uint16_t nb_ports = rte_eth_dev_count_avail();
    printf("Available ports: %u\n", nb_ports);
    for (uint16_t port = 0; port < nb_ports; port++) {
        struct rte_eth_dev_info info;
        char name[RTE_ETH_NAME_MAX_LEN] = {0};
        if (rte_eth_dev_get_name_by_port(port, name) != 0)
            snprintf(name, sizeof(name), "port%u", port);
        if (rte_eth_dev_info_get(port, &info) != 0)
            snprintf(name, sizeof(name), "port%u", port);
        printf("  port %u: name=%s driver=%s\n",
               port, name, info.driver_name ? info.driver_name : "unknown");
    }
}

static int
select_auto_port(uint16_t *out_port)
{
    uint16_t nb_ports = rte_eth_dev_count_avail();
    for (uint16_t port = 0; port < nb_ports; port++) {
        struct rte_eth_dev_info info;
        char name[RTE_ETH_NAME_MAX_LEN] = {0};
        if (rte_eth_dev_get_name_by_port(port, name) != 0)
            name[0] = '\0';
        if (rte_eth_dev_info_get(port, &info) != 0)
            continue;

        if ((info.driver_name && strstr(info.driver_name, "pcap")) ||
            (name[0] != '\0' && strstr(name, "pcap"))) {
            *out_port = port;
            return 0;
        }
    }
    return -1;
}

static int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf = {0};
    const uint16_t rx_rings = 1, tx_rings = 0;
    int ret;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    ret = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (ret < 0)
        return ret;

    ret = rte_eth_rx_queue_setup(port, 0, RX_RING_SIZE,
                                 rte_eth_dev_socket_id(port),
                                 NULL, mbuf_pool);
    if (ret < 0)
        return ret;

    ret = rte_eth_dev_start(port);
    if (ret < 0)
        return ret;

    rte_eth_promiscuous_enable(port);
    return 0;
}

int
main(int argc, char **argv)
{
    struct app_cfg cfg = {
        .port_id = 0,
        .frag_timeout_ms = DEFAULT_FRAG_TIMEOUT_MS,
        .max_print_bytes = DEFAULT_MAX_PRINT,
        .debug_dump_limit = 0,
        .auto_port = false,
        .list_ports = false,
        .print_payloads = false,
    };

    struct app_stats stats;
    rte_atomic64_init(&stats.rx_pkts);
    rte_atomic64_init(&stats.rx_drop);
    rte_atomic64_init(&stats.worker_in);
    rte_atomic64_init(&stats.worker_out);
    for (unsigned int i = 0; i < FQDN_COUNT; i++)
        rte_atomic64_init(&stats.fqdn[i]);

    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "EAL init failed\n");

    argc -= ret;
    argv += ret;

    if (parse_app_args(argc, argv, &cfg) != 0)
        rte_exit(EXIT_FAILURE, "Invalid arguments\n");

    list_ports();
    if (cfg.list_ports)
        return 0;

    if (cfg.auto_port) {
        if (select_auto_port(&cfg.port_id) != 0)
            rte_exit(EXIT_FAILURE, "auto-port: no pcap port found\n");
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create(
        "MBUF_POOL", NUM_MBUFS, MBUF_CACHE, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    if (port_init(cfg.port_id, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", cfg.port_id);

    struct rte_ring *cls_ring = rte_ring_create(
        "rx_to_classifier", RX_TO_CLASSIFIER_RING_SIZE,
        rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (cls_ring == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create ring: %s\n", rte_strerror(errno));

    struct rte_mempool *payload_pool = rte_mempool_create(
        "payload_pool", PAYLOAD_POOL_SIZE,
        sizeof(struct payload_item), 0, 0,
        NULL, NULL, NULL, NULL,
        rte_socket_id(), 0);
    if (payload_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create payload pool: %s\n", rte_strerror(errno));

    struct rx_ctx rx_ctx = {
        .port_id = cfg.port_id,
        .cls_ring = cls_ring,
        .payload_pool = payload_pool,
        .cfg = cfg,
        .stats = &stats,
    };

    struct classifier_ctx cls_ctx = {
        .ring = cls_ring,
        .payload_pool = payload_pool,
        .stats = &stats,
        .max_print_bytes = cfg.max_print_bytes,
        .print_payloads = cfg.print_payloads,
    };

    unsigned int rx_lcore = 1;
    unsigned int cls_lcore = 2;
    if (!rte_lcore_is_enabled(rx_lcore) || !rte_lcore_is_enabled(cls_lcore))
        rte_exit(EXIT_FAILURE, "lcore %u/%u not enabled; use -l 0-2\n", rx_lcore, cls_lcore);

    rte_eal_remote_launch(thread_rx_main, &rx_ctx, rx_lcore);
    rte_eal_remote_launch(thread_classifier_main, &cls_ctx, cls_lcore);

    printf("Reassembly reader started on port %u\n", cfg.port_id);
    printf("frag-timeout-ms=%u, print-max=%u bytes\n", cfg.frag_timeout_ms, cfg.max_print_bytes);
    printf("payload_print=%s\n", cfg.print_payloads ? "on" : "off");
    if (cfg.debug_dump_limit > 0)
        printf("debug-dump enabled: max %" PRIu32 " packets for non-IPv4 packets\n", cfg.debug_dump_limit);

    uint64_t last_tsc = rte_get_tsc_cycles();
    uint64_t tsc_hz = rte_get_tsc_hz();

    while (!force_quit) {
        uint64_t now = rte_get_tsc_cycles();
        if (now - last_tsc >= tsc_hz) {
            uint64_t rx = rte_atomic64_read(&stats.rx_pkts);
            uint64_t drop = rte_atomic64_read(&stats.rx_drop);
            uint64_t win = rte_atomic64_read(&stats.worker_in);
            uint64_t wout = rte_atomic64_read(&stats.worker_out);
            printf("rx=%" PRIu64 " drop=%" PRIu64 " worker_in=%" PRIu64 " worker_out=%" PRIu64,
                   rx, drop, win, wout);
            for (unsigned int i = 0; i < FQDN_COUNT; i++) {
                printf(" %s=%" PRIu64, fqdn_name((enum fqdn_id)i),
                       rte_atomic64_read(&stats.fqdn[i]));
            }
            putchar('\n');
            last_tsc = now;
        }
        rte_delay_us_sleep(1000);
    }

    rte_eal_wait_lcore(rx_lcore);
    rte_eal_wait_lcore(cls_lcore);

    rte_eth_dev_stop(cfg.port_id);
    rte_eth_dev_close(cfg.port_id);
    rte_eal_cleanup();

    return 0;
}
