// Simple DPDK reader: print TCP/UDP payloads from pkts (pcap vdev)
// Created by GitHub Co-pilot Agent to read and print a pcap
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/types.h>
#include <inttypes.h>
#include <string.h>

#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#define RX_RING_SIZE 1024
#define NUM_MBUFS    8192
#define MBUF_CACHE   250
#define BURST_SIZE   32

static volatile bool force_quit = false;

static void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        force_quit = true;
    }
}

static int port_init(uint16_t port, struct rte_mempool *mp) {
    struct rte_eth_conf port_conf = {0};
    const uint16_t rx_rings = 1, tx_rings = 0;
    int ret;
    if (!rte_eth_dev_is_valid_port(port)) return -1;
    ret = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (ret < 0) return ret;
    ret = rte_eth_rx_queue_setup(port, 0, RX_RING_SIZE, rte_eth_dev_socket_id(port), NULL, mp);
    if (ret < 0) return ret;
    ret = rte_eth_dev_start(port);
    if (ret < 0) return ret;
    rte_eth_promiscuous_enable(port);
    return 0;
}

static void print_payload(unsigned char *p, uint32_t len) {
    uint32_t print_len = len < 256 ? len : 256;
    for (uint32_t i = 0; i < print_len; ++i) {
        unsigned char c = p[i];
        if (c >= 32 && c <= 126) putchar(c); else printf(".%02x", c);
    }
    putchar('\n');
}

int main(int argc, char **argv) {
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        fprintf(stderr, "EAL init failed\n");
        return 1;
    }
    argc -= ret; argv += ret;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    struct rte_mempool *mp = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mp) {
        fprintf(stderr, "Failed to create mempool\n");
        return 1;
    }

    uint16_t portid = 0;
    printf("Attempting to init port %u...\n", portid);
    int init_ret = port_init(portid, mp);
    printf("port_init returned %d\n", init_ret);
    if (init_ret != 0) {
        fprintf(stderr, "Failed to init port %u\n", portid);
        return 1;
    }

    printf("simple_reader: started — reading from port %u\n", portid);

    uint64_t total_pkts = 0;

    while (!force_quit) {
        struct rte_mbuf *pkts[BURST_SIZE];
        uint16_t nb_rx = rte_eth_rx_burst(portid, 0, pkts, BURST_SIZE);
        if (nb_rx == 0) {
            rte_delay_us_sleep(1000);
            continue;
        }

        total_pkts += nb_rx;
        printf("... read %lu packets so far\n", total_pkts);

        for (uint16_t i = 0; i < nb_rx; ++i) {
            struct rte_mbuf *m = pkts[i];
            unsigned char *data = rte_pktmbuf_mtod(m, unsigned char *);
            uint32_t tot_len = rte_pktmbuf_pkt_len(m);

            /* DEBUG: Print first 14 bytes as hex */
            printf("Pkt %u: len=%u hex: ", i, tot_len);
            for (int x = 0; x < (tot_len < 14 ? tot_len : 14); ++x)
                printf("%02x ", data[x]);
            printf("\n");

            /* detect IPv4 (raw) or Ethernet+IPv4 */
            unsigned char *ipstart = NULL;
            if (tot_len >= 1 && (data[0] >> 4) == 4) {
                ipstart = data;
            } else if (tot_len >= sizeof(struct rte_ether_hdr)) {
                struct rte_ether_hdr *eth = (struct rte_ether_hdr *)data;
                uint16_t etype = rte_be_to_cpu_16(eth->ether_type);
                if (etype == RTE_ETHER_TYPE_IPV4) ipstart = data + sizeof(struct rte_ether_hdr);
                else printf("etype=%04x (not ipv4)\n", etype);
            }

            if (!ipstart) {
                printf("pkt: not ipv4\n");
                rte_pktmbuf_free(m);
                continue;
            }

            struct rte_ipv4_hdr *ipv4 = (struct rte_ipv4_hdr *)ipstart;
            uint16_t ihl = (ipv4->ihl & 0x0f) * 4;
            uint16_t ip_tot = rte_be_to_cpu_16(ipv4->total_length);
            uint8_t proto = ipv4->next_proto_id;

            unsigned char *l4 = ipstart + ihl;
            uint32_t l4_avail = (ip_tot > ihl) ? (ip_tot - ihl) : 0;

            if (proto == IPPROTO_TCP) {
                if (l4_avail < sizeof(struct rte_tcp_hdr)) {
                    printf("tcp: short\n");
                } else {
                    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4;
                    uint16_t thlen = ((tcp->data_off & 0xF0) >> 4) * 4;
                    unsigned char *payload = l4 + thlen;
                    uint32_t payload_len = l4_avail > thlen ? (l4_avail - thlen) : 0;
                    printf("TCP payload_len=%u: ", payload_len);
                    if (payload_len) print_payload(payload, payload_len);
                }
            } else if (proto == IPPROTO_UDP) {
                if (l4_avail < sizeof(struct rte_udp_hdr)) {
                    printf("udp: short\n");
                } else {
                    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4;
                    unsigned char *payload = l4 + sizeof(struct rte_udp_hdr);
                    uint32_t payload_len = rte_be_to_cpu_16(udp->dgram_len) > sizeof(struct rte_udp_hdr) ? (rte_be_to_cpu_16(udp->dgram_len) - sizeof(struct rte_udp_hdr)) : 0;
                    printf("UDP payload_len=%u: ", payload_len);
                    if (payload_len) print_payload(payload, payload_len);
                }
            } else {
                printf("proto %u not handled\n", proto);
            }

            rte_pktmbuf_free(m);
        }
    }

    rte_eth_dev_stop(portid);
    rte_eth_dev_close(portid);
    rte_eal_cleanup();
    return 0;
}
