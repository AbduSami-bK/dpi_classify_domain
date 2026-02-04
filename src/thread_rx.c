#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "app_common.h"
#include "app_main.h"
#include "pkt_helpers.h"
#include "thread_rx.h"

int
worker_main(void *arg)
{
    struct worker_ctx *ctx = (struct worker_ctx *)arg;

    uint64_t tsc_hz = rte_get_tsc_hz();
    uint64_t frag_cycles = (tsc_hz / 1000) * ctx->cfg.frag_timeout_ms;

    ctx->frag_tbl = rte_ip_frag_table_create(
        FRAG_BUCKETS, FRAG_BUCKET_ENTRIES, FRAG_MAX_FLOWS,
        frag_cycles, rte_socket_id());
    if (ctx->frag_tbl == NULL) {
        printf("worker: cannot create frag table: %s\n", strerror(errno));
        return -1;
    }
    memset(&ctx->death_row, 0, sizeof(ctx->death_row));

    struct rte_mbuf *pkts[BURST_SIZE];

    while (!force_quit) {
        uint16_t nb = rte_ring_dequeue_burst(ctx->ring, (void **)pkts, BURST_SIZE, NULL);
        if (nb == 0) {
            rte_delay_us_sleep(100);
            continue;
        }

        rte_atomic64_add(&ctx->stats->worker_in, nb);

        for (uint16_t i = 0; i < nb; i++) {
            struct rte_mbuf *m = pkts[i];
            struct rte_ipv4_hdr *ip_hdr = NULL;
            uint32_t l2_len = 0;

            if (get_ipv4_hdr(m, &ip_hdr, &l2_len) != 0) {
                if (ctx->cfg.debug_dump_limit > 0) {
                    static uint32_t dumped = 0;
                    if (dumped < ctx->cfg.debug_dump_limit) {
                        dump_first_bytes(m, 64);
                        dumped++;
                    }
                }
                rte_pktmbuf_free(m);
                continue;
            }

            uint8_t ihl_bytes = (uint8_t)((ip_hdr->ihl & 0x0F) * 4);
            if (ihl_bytes < sizeof(struct rte_ipv4_hdr)) {
                rte_pktmbuf_free(m);
                continue;
            }

            m->l2_len = (uint16_t)l2_len;
            m->l3_len = ihl_bytes;

            if (rte_ipv4_frag_pkt_is_fragmented(ip_hdr)) {
                struct rte_mbuf *reassembled = rte_ipv4_frag_reassemble_packet(
                    ctx->frag_tbl, &ctx->death_row, m, rte_get_tsc_cycles(), ip_hdr);

                if (reassembled == NULL)
                    continue;

                m = reassembled;

                if (get_ipv4_hdr(m, &ip_hdr, &l2_len) != 0) {
                    rte_pktmbuf_free(m);
                    continue;
                }

                ihl_bytes = (uint8_t)((ip_hdr->ihl & 0x0F) * 4);
                if (ihl_bytes < sizeof(struct rte_ipv4_hdr)) {
                    rte_pktmbuf_free(m);
                    continue;
                }

                m->l2_len = (uint16_t)l2_len;
                m->l3_len = ihl_bytes;
            }

            handle_l4_and_print(m, ip_hdr, l2_len, ctx->cfg.max_print_bytes);
            rte_pktmbuf_free(m);
            rte_atomic64_inc(&ctx->stats->worker_out);
        }

        rte_ip_frag_free_death_row(&ctx->death_row, BURST_SIZE);
    }

    /* Drain any remaining packets on shutdown. */
    while (rte_ring_dequeue_burst(ctx->ring, (void **)pkts, BURST_SIZE, NULL) > 0) {
        for (uint16_t i = 0; i < BURST_SIZE; i++) {
            if (pkts[i] == NULL)
                break;
            rte_pktmbuf_free(pkts[i]);
        }
    }

    rte_ip_frag_free_death_row(&ctx->death_row, BURST_SIZE);
    rte_ip_frag_table_destroy(ctx->frag_tbl);

    return 0;
}
