/**
 * @file parse_packet.h
 * @author Ibrahim
 * @brief This is the alternate to datapath.c
 * @date 7th April 2020
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <inttypes.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mbuf_ptype.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_byteorder.h>
#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_ring.h>

#define IPV4_PROTO 2048     /**< IPv4 Proto value in decimal */
#define IPV6_PROTO 34525    /**< IPv6 Proto value in decimal */

/**
 * @brief Match packet against IPtables to get what interfaces to forward it to.
 *
 * @param m Packet to extract info and match
 * @param fwd_interfaces ( @return ) Which interfaces to forward it to. Param is an array of size 2.
 *                                  '-1' denotes not to forward.
 */
void
parse_packet(struct rte_mbuf *m, int16_t * fwd_interfaces);
