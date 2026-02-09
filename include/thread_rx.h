#pragma once

#include <stdint.h>

#include <rte_mempool.h>
#include <rte_ring.h>

#include "app_common.h"
#include "thread_classifier.h"

#define BURST_SIZE   32

/** RX thread context. */
struct rx_ctx {
    uint16_t port_id;
    int port_socket;
    struct rte_ring *cls_ring;
    struct rte_mempool *payload_pool;
    struct app_cfg cfg;
    struct app_stats *stats;
};

/** RX thread entry point. */
int thread_rx_main(__rte_unused void *arg);
