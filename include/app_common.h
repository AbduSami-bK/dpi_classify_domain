#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <rte_atomic.h>

struct app_stats {
    rte_atomic64_t rx_pkts;
    rte_atomic64_t rx_drop;
    rte_atomic64_t worker_in;
    rte_atomic64_t worker_out;
};

struct app_cfg {
    uint16_t port_id;
    uint32_t frag_timeout_ms;
    uint32_t max_print_bytes;
    uint32_t debug_dump_limit;
    bool auto_port;
    bool list_ports;
};
