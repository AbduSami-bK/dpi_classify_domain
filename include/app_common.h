#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <rte_atomic.h>

#include "fqdn_list.h"

/** DPDK log type for this app. */
#define RTE_LOGTYPE_MINI_DPI RTE_LOGTYPE_USER1

/** Shared runtime counters. */
struct app_stats {
    rte_atomic64_t rx_pkts;
    rte_atomic64_t rx_bytes;
    rte_atomic64_t rx_drop;
    rte_atomic64_t worker_in;
    rte_atomic64_t worker_out;
    rte_atomic64_t fragments_seen;
    rte_atomic64_t packets_reassembled;
    rte_atomic64_t frag_timeouts;
    rte_atomic64_t frag_drops;
    rte_atomic64_t latency_sum_cycles;
    rte_atomic64_t latency_samples;
    rte_atomic64_t fqdn[FQDN_COUNT];
};

/** App configuration parsed from CLI args. */
struct app_cfg {
    uint16_t port_id;
    uint32_t port_mask;
    uint32_t frag_timeout_ms;
    uint32_t ring_size;
    uint32_t max_print_bytes;
    uint32_t debug_dump_limit;
    bool use_port_mask;
    bool print_payloads;
    bool perf;
};
