// With help from ChatGPT 5.2
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h> // for ssize_t

#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE 1024
#define NUM_MBUFS    8191
#define MBUF_CACHE   250
#define BURST_SIZE   32

static volatile bool force_quit = false;
static volatile uint64_t Google = 0,
                        YouTube = 0,
                        FaceBook = 0,
                        GitHub = 0,
                        UnKnown = 0;

static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        force_quit = true;
    }
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

    ret = rte_eth_rx_queue_setup(port, 0, RX_RING_SIZE, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
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
    int ret;
    uint16_t port_id = 0;

    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "EAL init failed\n");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    if (port_init(port_id, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", port_id);

    printf("Started RX loop on port %u\n", port_id);

    uint64_t t0 = rte_rdtsc();

    while (!force_quit) {
        struct rte_mbuf *pkts[BURST_SIZE];
        uint16_t nb_rx = rte_eth_rx_burst(port_id, 0, pkts, BURST_SIZE);

        if (nb_rx == 0) {
            continue;
        }

        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_mbuf *m = pkts[i];

            uint8_t *data = rte_pktmbuf_mtod(m, uint8_t *);
            uint16_t len = rte_pktmbuf_pkt_len(m);

            bool found = false;
            if (memmem(data, (len < 256 ? len : 256), "google.com", sizeof ("google.com"))) {   ++Google;   found = true;   }
            if (memmem(data, (len < 256 ? len : 256), "youtube.com", sizeof ("youtube.com"))) { ++YouTube;  found = true;   }
            if (memmem(data, (len < 256 ? len : 256), "facebook.com", sizeof ("facebook.com"))) {   ++FaceBook; found = true;   }
            if (memmem(data, (len < 256 ? len : 256), "github.com", sizeof ("github.com"))) {   ++GitHub;   found = true;   }
            if (!found) ++UnKnown;

        }
        rte_pktmbuf_free_bulk(pkts, nb_rx);

        uint64_t t1 = rte_rdtsc();
        if ((t1 - t0) > 3000) {
            printf("Google:%lu\tYT:%lu\tFB:%lu\tGitHub:%lu\tUnmatched:%lu\n", Google, YouTube, FaceBook, GitHub, UnKnown);
            t0 = t1;
        }
    }
    printf("\nGoogle:%lu\tYT:%lu\tFB:%lu\tGitHub:%lu\tUnmatched:%lu\n", Google, YouTube, FaceBook, GitHub, UnKnown);

    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);

    rte_eal_cleanup();
    return 0;
}
