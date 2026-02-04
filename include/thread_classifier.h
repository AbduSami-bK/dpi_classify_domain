#pragma once

#include <stdint.h>

#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ring.h>

#include "app_common.h"

/* Hyperscan types (optional). */
#ifdef USE_HYPERSCAN
#include <hs.h>
typedef hs_database_t hs_db_t;
typedef hs_scratch_t hs_scratch_typed;
#else
typedef void hs_db_t;
typedef void hs_scratch_typed;
#endif

struct payload_item {
    struct rte_mbuf *mbuf;
    uint32_t payload_offset;
    uint32_t payload_len;
    uint8_t proto;
};

struct classifier_ctx {
    struct rte_ring *ring;
    struct rte_mempool *payload_pool;
    struct app_stats *stats;
    uint32_t max_print_bytes;
};

struct hs_classifier {
    hs_db_t *db;
    hs_scratch_typed *scratch;
};

int hs_classifier_init(struct hs_classifier *cls);
void hs_classifier_free(struct hs_classifier *cls);
void hs_classifier_scan_payload(struct hs_classifier *cls, struct rte_mbuf *m,
                                uint32_t payload_offset, uint32_t payload_len,
                                struct app_stats *stats);
int thread_classifier_main(__rte_unused void *arg);
