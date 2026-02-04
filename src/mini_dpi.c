// DPDK IPv4 reassembly + TCP/UDP payload printer
// Focused, minimal program for pcap/af_packet ingestion.
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

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#define RX_RING_SIZE 1024
#define NUM_MBUFS    8192
#define MBUF_CACHE   256
#define BURST_SIZE   32

#define FRAG_BUCKETS  1024
#define FRAG_BUCKET_ENTRIES 16
#define FRAG_MAX_FLOWS 4096
#define DEFAULT_FRAG_TIMEOUT_MS 30000

#define DEFAULT_MAX_PRINT 1024

static volatile bool force_quit = false;

struct app_cfg {
    uint16_t port_id;
    uint32_t frag_timeout_ms;
    uint32_t max_print_bytes;
    uint32_t debug_dump_limit;
    bool auto_port;
    bool list_ports;
};

static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        force_quit = true;
    }
}

static void
usage(const char *prog)
{
    printf("Usage: %s [EAL args] -- [--port N] [--auto-port] [--list-ports] [--frag-timeout-ms N] [--print-max N] [--debug-dump N]\n", prog);
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
        case 'd':
            cfg->debug_dump_limit = (uint32_t)atoi(optarg);
            break;
        case 'h':
        default:
            usage(argv[0]);
            return -1;
        }
    }

    return 0;
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

static int
get_ipv4_hdr(struct rte_mbuf *m, struct rte_ipv4_hdr **ip_hdr, uint32_t *l2_len)
{
    uint8_t *data = rte_pktmbuf_mtod(m, uint8_t *);
    uint32_t pkt_len = rte_pktmbuf_pkt_len(m);

    if (pkt_len < sizeof(struct rte_ipv4_hdr))
        return -1;

    if ((data[0] >> 4) == 4) {
        *l2_len = 0;
        *ip_hdr = (struct rte_ipv4_hdr *)data;
        return 0;
    }

    if (pkt_len >= sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)) {
        struct rte_ether_hdr *eth = (struct rte_ether_hdr *)data;
        uint16_t etype = rte_be_to_cpu_16(eth->ether_type);
        if (etype == RTE_ETHER_TYPE_IPV4) {
            *l2_len = sizeof(struct rte_ether_hdr);
            *ip_hdr = (struct rte_ipv4_hdr *)(data + sizeof(struct rte_ether_hdr));
            return 0;
        }
    }

    /* Heuristic scan: handle pcap variants with small per-packet prefixes. */
    uint32_t max_scan = RTE_MIN(pkt_len - (uint32_t)sizeof(struct rte_ipv4_hdr), 32u);
    for (uint32_t off = 0; off <= max_scan; off++) {
        struct rte_ipv4_hdr *cand = (struct rte_ipv4_hdr *)(data + off);
        if ((cand->version_ihl >> 4) != 4)
            continue;
        uint8_t ihl = (uint8_t)((cand->version_ihl & 0x0F) * 4);
        if (ihl < sizeof(struct rte_ipv4_hdr))
            continue;
        uint16_t tot = rte_be_to_cpu_16(cand->total_length);
        if (tot < ihl)
            continue;
        if (off + tot > pkt_len)
            continue;
        *l2_len = off;
        *ip_hdr = cand;
        return 0;
    }

    return -1;
}

static void
print_payload(struct rte_mbuf *m, uint32_t offset, uint32_t len, uint32_t max_print)
{
    uint32_t to_print = len;
    if (max_print > 0 && to_print > max_print)
        to_print = max_print;

    uint8_t scratch[64];
    uint32_t printed = 0;

    while (printed < to_print) {
        uint32_t chunk = RTE_MIN((uint32_t)sizeof(scratch), to_print - printed);
        if (rte_pktmbuf_read(m, offset + printed, chunk, scratch) == NULL) {
            printf("[payload read error]\n");
            return;
        }

        for (uint32_t i = 0; i < chunk; i++) {
            unsigned char c = scratch[i];
            if (c >= 32 && c <= 126)
                putchar(c);
            else
                printf(".%02x", c);
        }
        printed += chunk;
    }

    if (len > to_print)
        printf(" ... (%" PRIu32 " bytes total)", len);

    putchar('\n');
}

static void
handle_l4_and_print(struct rte_mbuf *m, struct rte_ipv4_hdr *ip_hdr, uint32_t l2_len, uint32_t max_print)
{
    uint8_t ihl_bytes = (uint8_t)((ip_hdr->ihl & 0x0F) * 4);
    uint16_t ip_total_len = rte_be_to_cpu_16(ip_hdr->total_length);

    if (ihl_bytes < sizeof(struct rte_ipv4_hdr) || ip_total_len < ihl_bytes) {
        printf("IPv4 header invalid\n");
        return;
    }

    uint32_t l3_len = ip_total_len;
    uint32_t l4_offset = l2_len + ihl_bytes;
    uint32_t l4_len = l3_len - ihl_bytes;
    uint8_t proto = ip_hdr->next_proto_id;

    if (proto == IPPROTO_TCP) {
        struct rte_tcp_hdr tcp_hdr;
        if (rte_pktmbuf_read(m, l4_offset, sizeof(tcp_hdr), &tcp_hdr) == NULL) {
            printf("TCP header read failed\n");
            return;
        }

        uint8_t tcp_hdr_len = (uint8_t)(((tcp_hdr.data_off & 0xF0) >> 4) * 4);
        if (tcp_hdr_len < sizeof(struct rte_tcp_hdr) || l4_len < tcp_hdr_len) {
            printf("TCP header invalid\n");
            return;
        }

        uint32_t payload_offset = l4_offset + tcp_hdr_len;
        uint32_t payload_len = l4_len - tcp_hdr_len;

        printf("TCP payload_len=%" PRIu32 ": ", payload_len);
        if (payload_len > 0)
            print_payload(m, payload_offset, payload_len, max_print);
        else
            putchar('\n');
    } else if (proto == IPPROTO_UDP) {
        struct rte_udp_hdr udp_hdr;
        if (rte_pktmbuf_read(m, l4_offset, sizeof(udp_hdr), &udp_hdr) == NULL) {
            printf("UDP header read failed\n");
            return;
        }

        uint16_t udp_len = rte_be_to_cpu_16(udp_hdr.dgram_len);
        if (udp_len < sizeof(struct rte_udp_hdr) || l4_len < sizeof(struct rte_udp_hdr)) {
            printf("UDP header invalid\n");
            return;
        }

        uint32_t payload_offset = l4_offset + sizeof(struct rte_udp_hdr);
        uint32_t ip_payload_len = l4_len - sizeof(struct rte_udp_hdr);
        uint32_t payload_len = RTE_MIN((uint32_t)(udp_len - sizeof(struct rte_udp_hdr)), ip_payload_len);

        printf("UDP payload_len=%" PRIu32 ": ", payload_len);
        if (payload_len > 0)
            print_payload(m, payload_offset, payload_len, max_print);
        else
            putchar('\n');
    } else {
        printf("proto %u not handled\n", proto);
    }
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
        rte_eth_dev_info_get(port, &info);
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
        rte_eth_dev_info_get(port, &info);

        if ((info.driver_name && strstr(info.driver_name, "pcap")) ||
            (name[0] != '\0' && strstr(name, "pcap"))) {
            *out_port = port;
            return 0;
        }
    }
    return -1;
}

static void
dump_first_bytes(struct rte_mbuf *m, uint32_t max_bytes)
{
    uint32_t len = rte_pktmbuf_pkt_len(m);
    uint32_t to_dump = RTE_MIN(len, max_bytes);
    uint8_t scratch[64];
    uint32_t dumped = 0;

    printf("pkt_len=%" PRIu32 " first_bytes=", len);
    while (dumped < to_dump) {
        uint32_t chunk = RTE_MIN((uint32_t)sizeof(scratch), to_dump - dumped);
        if (rte_pktmbuf_read(m, dumped, chunk, scratch) == NULL) {
            printf("[read_error]\n");
            return;
        }
        for (uint32_t i = 0; i < chunk; i++)
            printf("%02x", scratch[i]);
        dumped += chunk;
    }
    if (len > to_dump)
        printf("...");
    putchar('\n');
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
    };

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

    uint64_t tsc_hz = rte_get_tsc_hz();
    uint64_t frag_cycles = (tsc_hz / 1000) * cfg.frag_timeout_ms;

    struct rte_ip_frag_tbl *frag_tbl = rte_ip_frag_table_create(
        FRAG_BUCKETS, FRAG_BUCKET_ENTRIES, FRAG_MAX_FLOWS,
        frag_cycles, rte_socket_id());
    if (frag_tbl == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create frag table: %s\n", rte_strerror(errno));

    struct rte_ip_frag_death_row death_row;
    memset(&death_row, 0, sizeof(death_row));

    printf("Reassembly reader started on port %u\n", cfg.port_id);
    printf("frag-timeout-ms=%u, print-max=%u bytes\n", cfg.frag_timeout_ms, cfg.max_print_bytes);
    if (cfg.debug_dump_limit > 0)
        printf("debug-dump enabled: max %" PRIu32 " packets for non-IPv4 packets\n", cfg.debug_dump_limit);

    while (!force_quit) {
        struct rte_mbuf *pkts[BURST_SIZE];
        uint16_t nb_rx = rte_eth_rx_burst(cfg.port_id, 0, pkts, BURST_SIZE);

        if (nb_rx == 0) {
            rte_delay_us_sleep(1000);
            continue;
        }

        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_mbuf *m = pkts[i];
            struct rte_ipv4_hdr *ip_hdr = NULL;
            uint32_t l2_len = 0;

            if (get_ipv4_hdr(m, &ip_hdr, &l2_len) != 0) {
                if (cfg.debug_dump_limit > 0) {
                    static uint32_t dumped = 0;
                    if (dumped < cfg.debug_dump_limit) {
                        dump_first_bytes(m, 64);
                        dumped++;
                    }
                }
                printf("pkt: not ipv4\n");
                rte_pktmbuf_free(m);
                continue;
            }

            uint8_t ihl_bytes = (uint8_t)((ip_hdr->ihl & 0x0F) * 4);
            if (ihl_bytes < sizeof(struct rte_ipv4_hdr)) {
                printf("pkt: ipv4 header invalid\n");
                rte_pktmbuf_free(m);
                continue;
            }

            m->l2_len = (uint16_t)l2_len;
            m->l3_len = ihl_bytes;

            if (rte_ipv4_frag_pkt_is_fragmented(ip_hdr)) {
                struct rte_mbuf *reassembled = rte_ipv4_frag_reassemble_packet(
                    frag_tbl, &death_row, m, rte_get_tsc_cycles(), ip_hdr);

                if (reassembled == NULL)
                    continue; // fragment queued or dropped; mbuf consumed

                m = reassembled;

                if (get_ipv4_hdr(m, &ip_hdr, &l2_len) != 0) {
                    printf("reassembled pkt: not ipv4\n");
                    rte_pktmbuf_free(m);
                    continue;
                }

                ihl_bytes = (uint8_t)((ip_hdr->ihl & 0x0F) * 4);
                if (ihl_bytes < sizeof(struct rte_ipv4_hdr)) {
                    printf("reassembled pkt: ipv4 header invalid\n");
                    rte_pktmbuf_free(m);
                    continue;
                }

                m->l2_len = (uint16_t)l2_len;
                m->l3_len = ihl_bytes;
            }

            handle_l4_and_print(m, ip_hdr, l2_len, cfg.max_print_bytes);
            rte_pktmbuf_free(m);
        }

        rte_ip_frag_free_death_row(&death_row, BURST_SIZE);
    }

    rte_ip_frag_free_death_row(&death_row, BURST_SIZE);
    rte_ip_frag_table_destroy(frag_tbl);

    rte_eth_dev_stop(cfg.port_id);
    rte_eth_dev_close(cfg.port_id);
    rte_eal_cleanup();

    return 0;
}
