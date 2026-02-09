#include <errno.h>
#include <search.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <rte_atomic.h>
#include <rte_common.h>
#include <rte_ip.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

#include "app_common.h"
#include "app_main.h"
#include "fqdn_list.h"
#include "pkt_helpers.h"
#include "thread_classifier.h"
#include "thread_rx.h"

#define MAX_SCAN_LEN 256
#define MAX_IOV 8

struct match_ctx {
    struct app_stats *stats;
    uint32_t matched_mask;
};

#ifdef USE_HYPERSCAN
#include <hs.h>

/**
 * @brief Hyperscan callback invoked on each match.
 */
static int
match_found(unsigned int id, unsigned long long from, unsigned long long to,
            unsigned int flags, void *context)
{
    struct match_ctx *ctx = (struct match_ctx *)context;
    uint32_t bit = 1u << id;

    (void)from;
    (void)to;
    (void)flags;

    if (ctx->matched_mask & bit)
        return 0;

    ctx->matched_mask |= bit;

    if (id < FQDN_UNKNOWN)
        rte_atomic64_inc(&ctx->stats->fqdn[id]);

    return 0;
}
#endif

/**
 * @brief Initialize the Hyperscan classifier (or no-op if disabled).
 */
int
hs_classifier_init(struct hs_classifier *cls)
{
    if (cls == NULL)
        return -1;

#ifdef USE_HYPERSCAN
    hs_compile_error_t *compile_err = NULL;
    hs_error_t err;
    const unsigned int count = fqdn_pattern_count();
    unsigned int flags[FQDN_COUNT] = {0};
    unsigned int ids[FQDN_COUNT];
    size_t lens[FQDN_COUNT];
    const char *patterns[FQDN_COUNT];

    /* Build literal pattern list for Hyperscan. */
    for (unsigned int i = 0; i < count; i++) {
        enum fqdn_id id = (enum fqdn_id)i;
        patterns[i] = fqdn_pattern(id);
        ids[i] = i;
        lens[i] = strlen(patterns[i]);
    }

    /* Compile multi-literal database in vectored mode for multi-seg payloads. */
    err = hs_compile_lit_multi(patterns, flags, ids, lens, count,
                               HS_MODE_VECTORED, NULL, &cls->db, &compile_err);
    if (err != HS_SUCCESS) {
        if (compile_err) {
            RTE_LOG(ERR, MINI_DPI, "hyperscan compile failed: %s\n", compile_err->message);
            hs_free_compile_error(compile_err);
        }
        return -1;
    }

    /* Scratch space is per-thread. */
    err = hs_alloc_scratch(cls->db, &cls->scratch);
    if (err != HS_SUCCESS) {
        RTE_LOG(ERR, MINI_DPI, "hyperscan scratch allocation failed\n");
        hs_free_database(cls->db);
        cls->db = NULL;
        return -1;
    }
#else
    (void)cls;
#endif
    return 0;
}

/**
 * @brief Release Hyperscan resources for a classifier.
 */
void
hs_classifier_free(struct hs_classifier *cls)
{
    if (cls == NULL)
        return;

#ifdef USE_HYPERSCAN
    if (cls->scratch)
        hs_free_scratch(cls->scratch);
    if (cls->db)
        hs_free_database(cls->db);
#endif

    cls->scratch = NULL;
    cls->db = NULL;
}

/**
 * @brief Build an I/O vector for a payload across mbuf segments.
 */
static unsigned int
build_payload_iov(struct rte_mbuf *m, uint32_t payload_offset, uint32_t payload_len,
                  const char **data, unsigned int *lengths, unsigned int max_iov)
{
    struct rte_mbuf *seg = m;
    uint32_t offset = payload_offset;
    uint32_t remaining = payload_len;
    unsigned int n = 0;

    /* Walk mbuf segments and build a bounded iov for scanning. */
    while (seg && remaining > 0 && n < max_iov) {
        uint32_t seg_len = seg->data_len;

        if (offset >= seg_len) {
            offset -= seg_len;
            seg = seg->next;
            continue;
        }

        uint32_t avail = seg_len - offset;
        uint32_t take = RTE_MIN(avail, remaining);
        data[n] = (const char *)((const uint8_t *)rte_pktmbuf_mtod(seg, uint8_t *) + offset);
        lengths[n] = take;
        n++;

        remaining -= take;
        offset = 0;
        seg = seg->next;
    }

    return n;
}

/**
 * @brief Scan payload for configured FQDN substrings and update stats.
 */
void
search_payload(struct hs_classifier *cls, struct rte_mbuf *m,
            uint32_t payload_offset, uint32_t payload_len,
            struct app_stats *stats)
{
#ifdef USE_HYPERSCAN
    if (cls == NULL || cls->db == NULL || cls->scratch == NULL || stats == NULL)
        return;

    /* Limit scan length to MAX_SCAN_LEN per requirements. */
    uint32_t to_scan = payload_len;
    if (to_scan > MAX_SCAN_LEN)
        to_scan = MAX_SCAN_LEN;

    if (to_scan == 0) {
        rte_atomic64_inc(&stats->fqdn[FQDN_UNKNOWN]);
        return;
    }

    /* Build an iov so Hyperscan can scan without copying. */
    const char *data[MAX_IOV];
    unsigned int lengths[MAX_IOV];
    unsigned int n = build_payload_iov(m, payload_offset, to_scan, data, lengths, MAX_IOV);

    if (n == 0) {
        rte_atomic64_inc(&stats->fqdn[FQDN_UNKNOWN]);
        return;
    }

    struct match_ctx ctx = {
        .stats = stats,
        .matched_mask = 0,
    };

    /* Scan the payload vector; callback updates counters. */
    hs_error_t err = hs_scan_vector(cls->db, data, lengths, n, 0,
                                    cls->scratch, match_found, &ctx);
    if (err != HS_SUCCESS && err != HS_SCAN_TERMINATED)
        return;

    if (ctx.matched_mask == 0)
        rte_atomic64_inc(&stats->fqdn[FQDN_UNKNOWN]);
#else
    (void)cls;
    if (stats == NULL)
        return;
    /* Fallback path: copy only the first MAX_SCAN_LEN bytes. */
    uint32_t to_scan = payload_len > MAX_SCAN_LEN ? MAX_SCAN_LEN : payload_len;
    if (to_scan == 0) {
        rte_atomic64_inc(&stats->fqdn[FQDN_UNKNOWN]);
        return;
    }

    uint8_t tmp[256];
    if (rte_pktmbuf_read(m, payload_offset, to_scan, tmp) == NULL) {
        rte_atomic64_inc(&stats->fqdn[FQDN_UNKNOWN]);
        return;
    }

    bool matched = false;
    /* Check each substring pattern. */
    for (unsigned int i = 0; i < fqdn_pattern_count(); i++) {
        const char *pat = fqdn_pattern((enum fqdn_id)i);
        size_t len = strlen(pat);
        if (memmem(tmp, to_scan, pat, len)) {
            rte_atomic64_inc(&stats->fqdn[i]);
            matched = true;
        }
    }
    if (!matched)
        rte_atomic64_inc(&stats->fqdn[FQDN_UNKNOWN]);
#endif
}

/**
 * @brief Classifier thread: dequeue payload items, scan, and free.
 */
int
thread_classifier_main(void *arg)
{
    struct classifier_ctx *ctx = (struct classifier_ctx *)arg;
    struct hs_classifier classifier = {0};

    if (hs_classifier_init(&classifier) != 0) {
        RTE_LOG(WARNING, MINI_DPI, "classifier: hyperscan init failed (falling back to memmem if disabled)\n");
    }

    struct payload_item *items[BURST_SIZE];

    while (!force_quit) {
        uint16_t nb = rte_ring_dequeue_burst(ctx->ring, (void **)items, BURST_SIZE, NULL);
        if (nb == 0) {
            rte_delay_us_sleep(50);
            continue;
        }

        for (uint16_t i = 0; i < nb; i++) {
            struct payload_item *item = items[i];
            if (item == NULL)
                continue;

            /* Classify payload and update stats. */
            search_payload(&classifier, item->mbuf,
                            item->payload_offset, item->payload_len,
                            ctx->stats);

            if (item->rx_tsc != 0) {
                /* Accumulate latency in cycles for perf stats. */
                uint64_t delta = rte_get_tsc_cycles() - item->rx_tsc;
                rte_atomic64_add(&ctx->stats->latency_sum_cycles, (int64_t)delta);
                rte_atomic64_inc(&ctx->stats->latency_samples);
            }

            /* if (ctx->print_payloads) {
                if (item->proto == IPPROTO_TCP)
                    printf("TCP payload_len=%" PRIu32 ": ", item->payload_len);
                else if (item->proto == IPPROTO_UDP)
                    printf("UDP payload_len=%" PRIu32 ": ", item->payload_len);
                else
                    printf("L4 payload_len=%" PRIu32 ": ", item->payload_len);

                if (item->payload_len > 0)
                    print_payload_range(item->mbuf, item->payload_offset,
                                        item->payload_len, ctx->max_print_bytes);
                else
                    putchar('\n');
            } */

            /* Return resources to pools. */
            rte_pktmbuf_free(item->mbuf);
            rte_mempool_put(ctx->payload_pool, item);
            rte_atomic64_inc(&ctx->stats->worker_out);
        }
    }

    /* Drain any remaining payload items safely. */
    uint16_t nb;
    do {
        uint16_t nb = rte_ring_dequeue_burst(ctx->ring, (void **)items, BURST_SIZE, NULL);
        for (uint16_t i = 0; i < nb; i++) {
            struct payload_item *item = items[i];
            if (item == NULL)
                continue;
            /* Free any queued items on shutdown. */
            rte_pktmbuf_free(item->mbuf);
            rte_mempool_put(ctx->payload_pool, item);
        }
    } while (nb > 0);

    hs_classifier_free(&classifier);
    return 0;
}
