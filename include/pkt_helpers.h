#pragma once

#include <rte_mbuf.h>
#include <rte_ip.h>

/* Helper functions for IPv4 processing */
int get_ipv4_hdr(struct rte_mbuf *m, struct rte_ipv4_hdr **ip_hdr, uint32_t *l2_len);
void handle_l4_and_print(struct rte_mbuf *m, struct rte_ipv4_hdr *ip_hdr, uint32_t l2_len, uint32_t max_print);
void dump_first_bytes(struct rte_mbuf *m, uint32_t max_bytes);
int get_l4_payload_bounds(struct rte_mbuf *m, struct rte_ipv4_hdr *ip_hdr, uint32_t l2_len,
                          uint32_t *payload_offset, uint32_t *payload_len, uint8_t *proto);
void print_payload_range(struct rte_mbuf *m, uint32_t offset, uint32_t len, uint32_t max_print);
