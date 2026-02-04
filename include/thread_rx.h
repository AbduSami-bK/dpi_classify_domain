#pragma once

#include <stdint.h>

#include <rte_mempool.h>
#include <rte_ring.h>

#include "app_common.h"
#include "thread_classifier.h"

/* Forward declarations */
struct app_cfg;
struct app_stats;

#define BURST_SIZE   32

struct rx_ctx {
    uint16_t port_id;
    struct rte_ring *cls_ring;
    struct rte_mempool *payload_pool;
    struct app_cfg cfg;
    struct app_stats *stats;
};

int thread_rx_main(__rte_unused void *arg);
