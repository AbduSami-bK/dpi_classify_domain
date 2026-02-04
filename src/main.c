// With help from ChatGPT 5.2

// Standard Libs
#define _GNU_SOURCE
// #include <assert.h>
// #include <errno.h>
#include <getopt.h>
#include <inttypes.h>
// #include <limits.h>
#include <signal.h>
// #include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
// #include <stdlib.h>
#include <string.h>
// #include <sys/queue.h>
#include <sys/types.h> // for ssize_t
// #include <sys/param.h>

// External imported libs
// #include <cmdline_parse.h>
// #include <cmdline_parse_etheraddr.h>
// #include <hs.h>
// #include <rte_branch_prediction.h>
// #include <rte_byteorder.h>
// #include <rte_common.h>
// #include <rte_cpuflags.h>
#include <rte_cycles.h>
// #include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
// #include <rte_interrupts.h>
#include <rte_ip.h>
// #include <rte_ip_frag.h>
// #include <rte_launch.h>
#include <rte_lcore.h>
// #include <rte_log.h>
// #include <rte_lpm.h>
// #include <rte_lpm6.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
// #include <rte_memcpy.h>
// #include <rte_memory.h>
#include <rte_mempool.h>
// #include <rte_per_lcore.h>
#include <rte_prefetch.h>
// #include <rte_vect.h>
// #include <rte_random.h>
// #include <rte_string_fns.h>
#include <rte_tcp.h>
#include <rte_udp.h>

// Local files
// #include "thread_rx.h"
// #include "thread_classifier.h"

#define RX_RING_SIZE 1024
#define MAX_PKT_BURST 32

/* allow max jumbo frame 9.5 KB */
#define JUMBO_FRAME_MAX_SIZE 0x2600
#define MAX_JUMBO_PKT_LEN 9600

// extern
static volatile bool force_quit = false;

static const char short_options[] =
    "";

static const struct option long_options[] = {
    {NULL, 0, 0, 0}};

/*
 * This expression is used to calculate the number of mbufs needed
 * depending on user input, taking  into account memory for rx and
 * tx hardware rings, cache per lcore and mtable per port per lcore.
 * RTE_MAX is used to ensure that NB_MBUF never goes below a minimum
 * value of 8192
 */
#define NB_MBUF(nports) RTE_MAX(                                                                           \
    (nports * nb_rx_queue * nb_rxd + nports * nb_lcores * MAX_PKT_BURST + nb_lcores * MEMPOOL_CACHE_SIZE), \
    (unsigned)8192)

#define MBUF_CACHE 250

static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit...\n", signum);
        force_quit = true;
    }
}

// Hard-coded FQDN-list
#define FQDN_LIST                     \
    X(GOOGLE, "google.com", "Google") \
    X(YOUTUBE, "youtube.com", "YT")   \
    X(FACEBOOK, "facebook.com", "FB") \
    X(GITHUB, "github.com", "GH")
enum fqdn_id
{
#define X(id, str, name) id##_id,
    FQDN_LIST
#undef X
    UNKNOWN
};
// Since only one thread is writing the counters, don't need to make this atomic yet.
// extern
static volatile uint64_t fqdn_counters[UNKNOWN + 1] = {0};

static const char *fqdn_list[] = {
#define X(id, str, name) str,
    FQDN_LIST
#undef X
};
static const uint8_t fqdn_str_len[] = {
#define X(id, str, name) sizeof(str),
    FQDN_LIST
#undef X
};
static const uint8_t fqdn_enum_list[] = {
#define X(id, str, name) id##_id,
    FQDN_LIST
#undef X
};

struct pkt_ctx
{
    bool fqdn_found;
};

int match_found(unsigned int id, unsigned long long from, unsigned long long to, unsigned int flags, struct pkt_ctx *context)
{
    if (context->fqdn_found == true // Already found in this packet
        || id >= UNKNOWN) {         // Unknown id
        return 0;
    }
    context->fqdn_found = true;

    ++(fqdn_counters[id]);
    return 0;
}

static void print_stats(void)
{
    for (int i = 0; i < UNKNOWN; i++) {
        printf("%s:%lu\t", fqdn_list[i], fqdn_counters[i]);
    }
    printf("UnMatched:%lu\n", fqdn_counters[UNKNOWN]);
}

static int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf = {0};
    int ret;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    ret = rte_eth_dev_configure(port, 1, 0, &port_conf);
    if (ret < 0)
        return ret;

    ret = rte_eth_rx_queue_setup(port, 0, RX_RING_SIZE, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
    if (ret < 0)
        return ret;

    ret = rte_eth_dev_start(port);
    if (ret < 0)
        return ret;

    ret = rte_eth_dev_count_avail();
    if (ret == 0)
        return -1;

    rte_eth_promiscuous_enable(port);
    return 0;
}

int main(int argc, char **argv)
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_panic("EAL init failed\n");
    }
    argc -= ret;
    argv += ret;

    ret = rte_eal_has_hugepages();
    if (unlikely(ret < 0)) {
        rte_panic("EAL no free hugepages\n");
    }

    force_quit = false;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NB_MBUF, MBUF_CACHE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    if (port_init(port_id, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", port_id);

    // rte_eal_remote_launch(thread_rx, NULL, lcore_id);
    // rte_eal_remote_launch(thread_classifier, NULL, lcore_id);

    /* HyperScan Init
    hs_database_t *hs_fqdn_db;
    hs_compile_error_t *compile_err;
    hs_scratch_t *scratch_space = NULL;
    hs_error_t err;

    struct pkt_ctx mbuf_context[MAX_PKT_BURST];
    for (uint16_t i = 0; i < MAX_PKT_BURST; ++i) {
        mbuf_context[i].fqdn_found = false;
    }

    hs_set_allocator(rte_malloc, rte_free);
    err = hs_compile_lit_multi(fqdn_list, 0, fqdn_enum_list, fqdn_str_len, 4, HS_MODE_BLOCK, NULL, &hs_fqdn_db, &compile_err);
    if (err != HS_SUCCESS) {
        printf("HyperScan Init failed!");
        return EXIT_FAILURE;
    }
    hs_free_compile_error(compile_err);
    err = hs_alloc_scratch(hs_fqdn_db, &scratch_space);
    if (err != HS_SUCCESS) {
        printf("HyperScan Init failed!");
        return EXIT_FAILURE;
    }   // */

    // printf("Started RX loop on lcore:%u port:%u queueL%u\n", lcore_id, port_id, queue_id);
    printf("Started RX loop on port:%u queueL%u\n", port_id, queue_id);
    uint64_t rx_pkt_cnt = 0;
    uint64_t t0 = rte_rdtsc();

    while (!force_quit) {
        struct rte_mbuf *pkts[MAX_PKT_BURST];
        uint16_t nb_rx = rte_eth_rx_burst(port_id, queue_id, pkts, MAX_PKT_BURST);
        char *payload[MAX_PKT_BURST];
        uint16_t pkts_len[MAX_PKT_BURST];

        if (nb_rx == 0)
        {
            continue;
        }

        for (uint16_t i = 0; i < nb_rx; ++i) {
            // pkts_data[i] = rte_pktmbuf_mtod(pkts[i], char *);
            // pkts_len[i] = rte_pktmbuf_pkt_len(pkts[i]);

            rte_mbuf_prefetch_part1(pkts[i]);

            // Strip All vLANs
            while (rte_vlan_strip(pkts[i]) != -1) {;}

            // Ethernet Layer
            struct rte_ether_hdr *ether_hdr = rte_pktmbuf_mtod(pkts[i], struct rte_ether_hdr *);
            uint16_t ether_type = ether_hdr->ether_type = rte_be_to_cpu_16(ether_hdr->ether_type);
            printf("DEBUG: Packet %u, ether_type=0x%04x\n", i, ether_type);

            // IP Layer
            switch (ether_type) {
                case RTE_ETHER_TYPE_IPV4: {
                    struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)ether_type + 1; // rte_pktmbuf_mtod_offset(pkts[i], struct rte_ipv4_hdr *, sizeof (struct rte_ether_hdr));
                    switch (ipv4_hdr->next_proto_id) {
                        case IPPROTO_TCP: {
                            struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)ipv4_hdr + 1; // ((unsigned char *)ipv4_hdr + sizeof(struct rte_ipv4_hdr));
                            payload[i] = (char *)tcp_hdr + sizeof(struct rte_tcp_hdr);
                            pkts_len[i] = rte_be_to_cpu_16(ipv4_hdr->total_length) - sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_tcp_hdr);
                            break;
                        }
                        case IPPROTO_UDP: {
                            struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)ipv4_hdr + 1; // ((unsigned char *)ipv4_hdr + sizeof(struct rte_ipv4_hdr));
                            payload[i] = (char *)udp_hdr + sizeof(struct rte_udp_hdr);
                            pkts_len[i] = rte_be_to_cpu_16(udp_hdr->dgram_len) - sizeof(struct rte_udp_hdr);
                            break;
                        }
                    }
                    break;
                }
                case RTE_ETHER_TYPE_IPV6: {
                    struct rte_ipv6_hdr *ipv6_hdr = rte_pktmbuf_mtod_offset(pkts[i], struct rte_ipv6_hdr *, sizeof(struct rte_ether_hdr));
                    payload[i] = (char *)ipv6_hdr + sizeof(struct rte_ipv6_hdr);
                    // pkts_len[i] = rte_be_to_cpu_16(ipv6_hdr->payload);
                    break;
                }
                default:
                    // Other packet types not handled
            }
        }

        /* Search with HyperScan
        hs_error_t err = hs_scan_vector(hs_fqdn_db, payload, pkts_len[(len > 256 ? 256 : len)], nb_rx, 0, scratch_space, match_found, mbuf_context);
        for (uint16_t i = 0; i < nb_rx; ++i) {
            // hs_error_t err = hs_scan(hs_fqdn_db, data, (len > 256 ? 256 : len), 0, scratch_space, match_found, mbuf_context[0]);
            if (mbuf_context[i].fqdn_found == false)
                ++fqdn_counters[UNKNOWN];
            else
                mbuf_context[i].fqdn_found = false; // Reset for next loop
        }
        /*/
        // Search with memmem()
        for (uint16_t i = 0; i < nb_rx; ++i) {
            ssize_t scan_len = (pkts_len[i] < 256 ? pkts_len[i] : 256);
            bool found = false;
            for (int j = 0; j < UNKNOWN; ++j) {
                if (memmem(payload[i], scan_len, fqdn_list[j], fqdn_str_len[j])) {
                    ++fqdn_counters[j];
                    found = true;
                }
            }

            if (!found) {
                ++fqdn_counters[UNKNOWN];
            }
        }
        rte_pktmbuf_free_bulk(pkts, nb_rx); // */

        uint64_t t1 = rte_rdtsc();
        if ((t1 - t0) > 1000) {
            print_stats();
            t0 = t1;
        }
    }
    print_stats();

    /*
    hs_free_scratch(scratch_space);
    hs_free_database(hs_fqdn_db);   // */
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);

    /* Main thread
    while (!force_quit) {
        rte_delay_us_sleep(1 * US_PER_S);
        print_stats();
    } */
    rte_eal_mp_wait_lcore();

    rte_eal_cleanup();
    return EXIT_SUCCESS;
}
