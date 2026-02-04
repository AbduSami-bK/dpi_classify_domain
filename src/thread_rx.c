#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_ip6.h>
#include <rte_ip_frag.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "app_main.h"
#include "pkt_helpers.h"
#include "thread_classifier.h"
#include "thread_rx.h"

#define FRAG_BUCKETS  1024
#define FRAG_BUCKET_ENTRIES 16
#define FRAG_MAX_FLOWS 4096

int
thread_rx_main(void *arg)
{
    struct rx_ctx *ctx = (struct rx_ctx *)arg;

    uint64_t tsc_hz = rte_get_tsc_hz();
    uint64_t frag_cycles = (tsc_hz / 1000) * ctx->cfg.frag_timeout_ms;

    struct rte_ip_frag_tbl *frag_tbl = rte_ip_frag_table_create(
        FRAG_BUCKETS, FRAG_BUCKET_ENTRIES, FRAG_MAX_FLOWS,
        frag_cycles, rte_socket_id());
    if (frag_tbl == NULL) {
        printf("worker: cannot create frag table: %s\n", strerror(errno));
        return -1;
    }
    struct rte_ip_frag_death_row death_row;
    memset(&death_row, 0, sizeof(death_row));

    struct rte_mbuf *pkts[BURST_SIZE];

    while (!force_quit) {
        uint16_t nb_rx = rte_eth_rx_burst(ctx->port_id, 0, pkts, BURST_SIZE);
        if (nb_rx == 0) {
            rte_delay_us_sleep(50);
            continue;
        }

        rte_atomic64_add(&ctx->stats->rx_pkts, nb_rx);

        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_mbuf *m = pkts[i];
            struct rte_ipv4_hdr *ip_hdr = NULL;
            uint32_t l2_len = 0;
            struct rte_ipv6_hdr *ip6_hdr = NULL;

            bool is_ipv4 = (get_ipv4_hdr(m, &ip_hdr, &l2_len) == 0);
            bool is_ipv6 = (!is_ipv4 && get_ipv6_hdr(m, &ip6_hdr, &l2_len) == 0);

            if (!is_ipv4 && !is_ipv6) {
                if (ctx->cfg.debug_dump_limit > 0) {
                    static uint32_t dumped = 0;
                    if (dumped < ctx->cfg.debug_dump_limit) {
                        dump_first_bytes(m, 64);
                        dumped++;
                    }
                }
                rte_pktmbuf_free(m);
                rte_atomic64_inc(&ctx->stats->fqdn[FQDN_UNKNOWN]);
                continue;
            }

            uint32_t payload_offset = 0;
            uint32_t payload_len = 0;
            uint8_t proto = 0;

            if (is_ipv4) {
                uint8_t ihl_bytes = (uint8_t)((ip_hdr->ihl & 0x0F) * 4);
                if (ihl_bytes < sizeof(struct rte_ipv4_hdr)) {
                    rte_pktmbuf_free(m);
                    rte_atomic64_inc(&ctx->stats->fqdn[FQDN_UNKNOWN]);
                    continue;
                }

                m->l2_len = (uint16_t)l2_len;
                m->l3_len = ihl_bytes;

                if (rte_ipv4_frag_pkt_is_fragmented(ip_hdr)) {
                    struct rte_mbuf *reassembled = rte_ipv4_frag_reassemble_packet(
                        frag_tbl, &death_row, m, rte_get_tsc_cycles(), ip_hdr);

                    if (reassembled == NULL)
                        continue;

                    m = reassembled;

                    if (get_ipv4_hdr(m, &ip_hdr, &l2_len) != 0) {
                        rte_pktmbuf_free(m);
                        rte_atomic64_inc(&ctx->stats->fqdn[FQDN_UNKNOWN]);
                        continue;
                    }

                    ihl_bytes = (uint8_t)((ip_hdr->ihl & 0x0F) * 4);
                    if (ihl_bytes < sizeof(struct rte_ipv4_hdr)) {
                        rte_pktmbuf_free(m);
                        rte_atomic64_inc(&ctx->stats->fqdn[FQDN_UNKNOWN]);
                        continue;
                    }

                    m->l2_len = (uint16_t)l2_len;
                    m->l3_len = ihl_bytes;
                }

                if (get_l4_payload_bounds(m, ip_hdr, l2_len, &payload_offset, &payload_len, &proto) != 0) {
                    rte_pktmbuf_free(m);
                    rte_atomic64_inc(&ctx->stats->fqdn[FQDN_UNKNOWN]);
                    continue;
                }
            } else {
                m->l2_len = (uint16_t)l2_len;
                m->l3_len = sizeof(struct rte_ipv6_hdr);

                struct rte_ipv6_fragment_ext *frag_hdr = rte_ipv6_frag_get_ipv6_fragment_header(ip6_hdr);
                if (frag_hdr != NULL) {
                    struct rte_mbuf *reassembled = rte_ipv6_frag_reassemble_packet(
                        frag_tbl, &death_row, m, rte_get_tsc_cycles(), ip6_hdr, frag_hdr);

                    if (reassembled == NULL)
                        continue;

                    m = reassembled;

                    if (get_ipv6_hdr(m, &ip6_hdr, &l2_len) != 0) {
                        rte_pktmbuf_free(m);
                        rte_atomic64_inc(&ctx->stats->fqdn[FQDN_UNKNOWN]);
                        continue;
                    }

                    m->l2_len = (uint16_t)l2_len;
                    m->l3_len = sizeof(struct rte_ipv6_hdr);
                }

                if (get_ipv6_payload_bounds(m, ip6_hdr, l2_len, &payload_offset, &payload_len, &proto) != 0) {
                    rte_pktmbuf_free(m);
                    rte_atomic64_inc(&ctx->stats->fqdn[FQDN_UNKNOWN]);
                    continue;
                }
            }

            if (true) {
                struct payload_item *item = NULL;
                if (rte_mempool_get(ctx->payload_pool, (void **)&item) != 0) {
                    rte_atomic64_inc(&ctx->stats->rx_drop);
                    rte_pktmbuf_free(m);
                    rte_atomic64_inc(&ctx->stats->fqdn[FQDN_UNKNOWN]);
                    continue;
                }

                item->mbuf = m;
                item->payload_offset = payload_offset;
                item->payload_len = payload_len;
                item->proto = proto;

                if (rte_ring_enqueue(ctx->cls_ring, item) != 0) {
                    rte_atomic64_inc(&ctx->stats->rx_drop);
                    rte_mempool_put(ctx->payload_pool, item);
                    rte_pktmbuf_free(m);
                    rte_atomic64_inc(&ctx->stats->fqdn[FQDN_UNKNOWN]);
                    continue;
                }

                rte_atomic64_inc(&ctx->stats->worker_in);
            }
        }

        rte_ip_frag_free_death_row(&death_row, BURST_SIZE);
    }

    rte_ip_frag_free_death_row(&death_row, BURST_SIZE);
    rte_ip_frag_table_destroy(frag_tbl);

    return 0;
}
