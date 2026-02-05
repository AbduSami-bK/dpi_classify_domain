#pragma once

#include <rte_mbuf.h>
#include <rte_ip.h>

/**
 * @brief Locate an IPv4 header and return L2 length.
 * @return 0 on success, -1 if no valid IPv4 header found.
 */
int get_ipv4_hdr(struct rte_mbuf *m, struct rte_ipv4_hdr **ip_hdr, uint32_t *l2_len);
/**
 * @brief Locate an IPv6 header and return L2 length.
 * @return 0 on success, -1 if no valid IPv6 header found.
 */
int get_ipv6_hdr(struct rte_mbuf *m, struct rte_ipv6_hdr **ip_hdr, uint32_t *l2_len);

/**
 * @brief Parse L4 header and print payload.
 */
void handle_l4_and_print(struct rte_mbuf *m, struct rte_ipv4_hdr *ip_hdr,
                         uint32_t l2_len, uint32_t max_print);

/**
 * @brief Dump the first bytes of a packet for debugging.
 */
void dump_first_bytes(struct rte_mbuf *m, uint32_t max_bytes);

/**
 * @brief Compute payload offset/length for TCP/UDP packets.
 * @return 0 on success, 1 for unsupported proto, -1 on parse error.
 */
int get_l4_payload_bounds(struct rte_mbuf *m, struct rte_ipv4_hdr *ip_hdr, uint32_t l2_len,
                          uint32_t *payload_offset, uint32_t *payload_len, uint8_t *proto);
/**
 * @brief Compute payload offset/length for IPv6 TCP/UDP packets.
 * @return 0 on success, 1 for unsupported proto, -1 on parse error.
 */
int get_ipv6_payload_bounds(struct rte_mbuf *m, struct rte_ipv6_hdr *ip_hdr, uint32_t l2_len,
                            uint32_t *payload_offset, uint32_t *payload_len, uint8_t *proto);

/**
 * @brief Print a payload range with a printable/hex mix.
 */
void print_payload_range(struct rte_mbuf *m, uint32_t offset, uint32_t len, uint32_t max_print);
