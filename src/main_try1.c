
// Standard dependencies
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>

// External Dependencies
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ip_frag.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>

// Local
#include "thread_rx.h"
#include "thread_classifier.h"

#define MEMPOOL_CACHE_SIZE 256
#define NB_SOCKETS 2
#define PREFETCH_OFFSET 4
#define RTE_TEST_RX_DESC_DEFAULT 4096
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;

/**< allow max jumbo frame of 9.6 KB */
#define MAX_JUMBO_PKT_LEN 9600
#define JUMBO_FRAME_MAX_SIZE   MAX_JUMBO_PKT_LEN / 1000 * 1024

// rte_atomic64_t not needed.
// Since only one thread writes these stats and the other only ever reads. No race condition.
static volatile uint64_t Google, YouTube, FaceBook, GitHub, UnKnown,
    fragments_seen, packets_reassembled, frag_timeouts, frag_drops,
    packets_rx, packets_worker_in, ring_drop;

void
print_stats(void) {
    printf("Packet counts: Total In: %lu\tClassifer_in: %lu\t\n");
}
