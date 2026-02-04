#pragma once

#include <stdint.h>

#include <rte_ring.h>
#include <rte_ip_frag.h>

#include "app_common.h"

/* Forward declarations */
struct app_cfg;
struct app_stats;

#define BURST_SIZE   32

#define FRAG_BUCKETS  1024
#define FRAG_BUCKET_ENTRIES 16
#define FRAG_MAX_FLOWS 4096

struct worker_ctx {
    struct rte_ring *ring;
    struct app_cfg cfg;
    struct app_stats *stats;
    struct rte_ip_frag_tbl *frag_tbl;
    struct rte_ip_frag_death_row death_row;
};

int worker_main(__rte_unused void *arg);
