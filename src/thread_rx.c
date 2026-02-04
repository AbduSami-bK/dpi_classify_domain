#include <stdbool.h>

#include <rte_common.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "thread_rx.h"

extern bool force_quit;

static int
thread_rx(__rte_unused void *arg) {
    while (!force_quit) {}
    return EXIT_SUCCESS;
}
