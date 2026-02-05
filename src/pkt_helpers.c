#include <inttypes.h>
#include <stdio.h>
#include <sys/types.h>

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_ip6.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "app_common.h"
#include "pkt_helpers.h"

int
get_ipv4_hdr(struct rte_mbuf *m, struct rte_ipv4_hdr **ip_hdr, uint32_t *l2_len)
{
    uint8_t *data = rte_pktmbuf_mtod(m, uint8_t *);
    uint32_t pkt_len = rte_pktmbuf_pkt_len(m);

    if (pkt_len < sizeof(struct rte_ipv4_hdr))
        return -1;

    if ((data[0] >> 4) == 4) {
        *l2_len = 0;
        *ip_hdr = (struct rte_ipv4_hdr *)data;
        return 0;
    }

    if (pkt_len >= sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)) {
        struct rte_ether_hdr *eth = (struct rte_ether_hdr *)data;
        uint16_t etype = rte_be_to_cpu_16(eth->ether_type);
        if (etype == RTE_ETHER_TYPE_IPV4) {
            *l2_len = sizeof(struct rte_ether_hdr);
            *ip_hdr = (struct rte_ipv4_hdr *)(data + sizeof(struct rte_ether_hdr));
            return 0;
        }
    }

    /* Heuristic scan: handle pcap variants with small per-packet prefixes. */
    uint32_t max_scan = RTE_MIN(pkt_len - (uint32_t)sizeof(struct rte_ipv4_hdr), 32u);
    for (uint32_t off = 0; off <= max_scan; off++) {
        struct rte_ipv4_hdr *cand = (struct rte_ipv4_hdr *)(data + off);
        if ((cand->version_ihl >> 4) != 4)
            continue;
        uint8_t ihl = (uint8_t)((cand->version_ihl & 0x0F) * 4);
        if (ihl < sizeof(struct rte_ipv4_hdr))
            continue;
        uint16_t tot = rte_be_to_cpu_16(cand->total_length);
        if (tot < ihl)
            continue;
        if (off + tot > pkt_len)
            continue;
        *l2_len = off;
        *ip_hdr = cand;
        return 0;
    }

    return -1;
}

int
get_ipv6_hdr(struct rte_mbuf *m, struct rte_ipv6_hdr **ip_hdr, uint32_t *l2_len)
{
    uint8_t *data = rte_pktmbuf_mtod(m, uint8_t *);
    uint32_t pkt_len = rte_pktmbuf_pkt_len(m);

    if (pkt_len < sizeof(struct rte_ipv6_hdr))
        return -1;

    if ((data[0] >> 4) == 6) {
        *l2_len = 0;
        *ip_hdr = (struct rte_ipv6_hdr *)data;
        return 0;
    }

    if (pkt_len >= sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr)) {
        struct rte_ether_hdr *eth = (struct rte_ether_hdr *)data;
        uint16_t etype = rte_be_to_cpu_16(eth->ether_type);
        if (etype == RTE_ETHER_TYPE_IPV6) {
            *l2_len = sizeof(struct rte_ether_hdr);
            *ip_hdr = (struct rte_ipv6_hdr *)(data + sizeof(struct rte_ether_hdr));
            return 0;
        }
    }

    return -1;
}

void
print_payload_range(struct rte_mbuf *m, uint32_t offset, uint32_t len, uint32_t max_print)
{
    uint32_t to_print = len;
    if (max_print > 0 && to_print > max_print)
        to_print = max_print;

    uint8_t scratch[64];
    uint32_t printed = 0;

    while (printed < to_print) {
        uint32_t chunk = RTE_MIN((uint32_t)sizeof(scratch), to_print - printed);
        if (rte_pktmbuf_read(m, offset + printed, chunk, scratch) == NULL) {
            RTE_LOG(WARNING, MINI_DPI, "payload read error\n");
            return;
        }

        for (uint32_t i = 0; i < chunk; i++) {
            unsigned char c = scratch[i];
            if (c >= 32 && c <= 126)
                putchar(c);
            else
                printf(".%02x", c);
        }
        printed += chunk;
    }

    if (len > to_print)
        printf(" ... (%" PRIu32 " bytes total)", len);

    putchar('\n');
}

int
get_l4_payload_bounds(struct rte_mbuf *m, struct rte_ipv4_hdr *ip_hdr, uint32_t l2_len,
                      uint32_t *payload_offset, uint32_t *payload_len, uint8_t *proto)
{
    uint8_t ihl_bytes = (uint8_t)((ip_hdr->ihl & 0x0F) * 4);
    uint16_t ip_total_len = rte_be_to_cpu_16(ip_hdr->total_length);

    if (ihl_bytes < sizeof(struct rte_ipv4_hdr) || ip_total_len < ihl_bytes)
        return -1;

    uint32_t l3_len = ip_total_len;
    uint32_t l4_offset = l2_len + ihl_bytes;
    uint32_t l4_len = l3_len - ihl_bytes;

    *proto = ip_hdr->next_proto_id;

    if (*proto == IPPROTO_TCP) {
        struct rte_tcp_hdr tcp_hdr;
        if (rte_pktmbuf_read(m, l4_offset, sizeof(tcp_hdr), &tcp_hdr) == NULL)
            return -1;

        uint8_t tcp_hdr_len = (uint8_t)(((tcp_hdr.data_off & 0xF0) >> 4) * 4);
        if (tcp_hdr_len < sizeof(struct rte_tcp_hdr) || l4_len < tcp_hdr_len)
            return -1;

        *payload_offset = l4_offset + tcp_hdr_len;
        *payload_len = l4_len - tcp_hdr_len;
        return 0;
    }

    if (*proto == IPPROTO_UDP) {
        struct rte_udp_hdr udp_hdr;
        if (rte_pktmbuf_read(m, l4_offset, sizeof(udp_hdr), &udp_hdr) == NULL)
            return -1;

        uint16_t udp_len = rte_be_to_cpu_16(udp_hdr.dgram_len);
        if (udp_len < sizeof(struct rte_udp_hdr) || l4_len < sizeof(struct rte_udp_hdr))
            return -1;

        uint32_t ip_payload_len = l4_len - sizeof(struct rte_udp_hdr);
        uint32_t udp_payload_len = udp_len - sizeof(struct rte_udp_hdr);

        *payload_offset = l4_offset + sizeof(struct rte_udp_hdr);
        *payload_len = RTE_MIN(ip_payload_len, udp_payload_len);
        return 0;
    }

    return 1; /* proto not handled */
}

int
get_ipv6_payload_bounds(struct rte_mbuf *m, struct rte_ipv6_hdr *ip_hdr, uint32_t l2_len,
                        uint32_t *payload_offset, uint32_t *payload_len, uint8_t *proto)
{
    uint32_t l3_offset = l2_len;
    uint32_t l4_offset = l3_offset + sizeof(struct rte_ipv6_hdr);
    uint32_t l4_len = rte_be_to_cpu_16(ip_hdr->payload_len);
    uint8_t next = ip_hdr->proto;

    if (next == IPPROTO_FRAGMENT) {
        struct rte_ipv6_fragment_ext frag_hdr;
        if (rte_pktmbuf_read(m, l4_offset, sizeof(frag_hdr), &frag_hdr) == NULL)
            return -1;
        next = frag_hdr.next_header;
        l4_offset += sizeof(struct rte_ipv6_fragment_ext);
        if (l4_len < sizeof(struct rte_ipv6_fragment_ext))
            return -1;
        l4_len -= sizeof(struct rte_ipv6_fragment_ext);
    }

    *proto = next;

    if (next == IPPROTO_TCP) {
        struct rte_tcp_hdr tcp_hdr;
        if (rte_pktmbuf_read(m, l4_offset, sizeof(tcp_hdr), &tcp_hdr) == NULL)
            return -1;

        uint8_t tcp_hdr_len = (uint8_t)(((tcp_hdr.data_off & 0xF0) >> 4) * 4);
        if (tcp_hdr_len < sizeof(struct rte_tcp_hdr) || l4_len < tcp_hdr_len)
            return -1;

        *payload_offset = l4_offset + tcp_hdr_len;
        *payload_len = l4_len - tcp_hdr_len;
        return 0;
    }

    if (next == IPPROTO_UDP) {
        struct rte_udp_hdr udp_hdr;
        if (rte_pktmbuf_read(m, l4_offset, sizeof(udp_hdr), &udp_hdr) == NULL)
            return -1;

        uint16_t udp_len = rte_be_to_cpu_16(udp_hdr.dgram_len);
        if (udp_len < sizeof(struct rte_udp_hdr) || l4_len < sizeof(struct rte_udp_hdr))
            return -1;

        uint32_t ip_payload_len = l4_len - sizeof(struct rte_udp_hdr);
        uint32_t udp_payload_len = udp_len - sizeof(struct rte_udp_hdr);

        *payload_offset = l4_offset + sizeof(struct rte_udp_hdr);
        *payload_len = RTE_MIN(ip_payload_len, udp_payload_len);
        return 0;
    }

    return 1;
}

void
handle_l4_and_print(struct rte_mbuf *m, struct rte_ipv4_hdr *ip_hdr, uint32_t l2_len, uint32_t max_print)
{
    uint32_t payload_offset = 0;
    uint32_t payload_len = 0;
    uint8_t proto = 0;

    int ret = get_l4_payload_bounds(m, ip_hdr, l2_len, &payload_offset, &payload_len, &proto);
    if (ret != 0) {
        if (ret == 1)
            RTE_LOG(WARNING, MINI_DPI, "proto %u not handled\n", proto);
        else
            RTE_LOG(WARNING, MINI_DPI, "L4 header invalid\n");
        return;
    }

    if (proto == IPPROTO_TCP)
        printf("TCP payload_len=%" PRIu32 ": ", payload_len);
    else
        printf("UDP payload_len=%" PRIu32 ": ", payload_len);

    if (payload_len > 0)
        print_payload_range(m, payload_offset, payload_len, max_print);
    else
        putchar('\n');
}

void
dump_first_bytes(struct rte_mbuf *m, uint32_t max_bytes)
{
    uint32_t len = rte_pktmbuf_pkt_len(m);
    uint32_t to_dump = RTE_MIN(len, max_bytes);
    uint8_t scratch[64];
    uint32_t dumped = 0;

    printf("pkt_len=%" PRIu32 " first_bytes=", len);
    while (dumped < to_dump) {
        uint32_t chunk = RTE_MIN((uint32_t)sizeof(scratch), to_dump - dumped);
        if (rte_pktmbuf_read(m, dumped, chunk, scratch) == NULL) {
            printf("[read_error]\n");
            return;
        }
        for (uint32_t i = 0; i < chunk; i++)
            printf("%02x", scratch[i]);
        dumped += chunk;
    }
    if (len > to_dump)
        printf("...");
    putchar('\n');
}
