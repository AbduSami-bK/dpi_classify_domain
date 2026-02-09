# Implementation Notes

## Drops and Timeouts

- Ring drops occur when the RX thread cannot enqueue a payload item into the classifier ring.
- Payload pool drops occur when the RX thread cannot allocate a payload item.
- Fragment drops/timeouts are tracked from the ip_frag death row (fragments expired and freed).

## Reassembly Approach

- IPv4: `rte_ipv4_frag_reassemble_packet()` with per-thread frag table.
- IPv6: `rte_ipv6_frag_reassemble_packet()` when a fragment extension header is present.
- The reassembly key is managed by DPDK (src/dst/ip_id/proto).

## Mbuf Lifecycle

- RX thread owns incoming mbufs.
- After reassembly and L4 parse, the RX thread packages the mbuf in a payload item and enqueues it.
- Classifier thread scans payloads, optionally prints, then frees the mbuf and payload item.

## Use of AI

| Field | Value |
| --- | --- |
| Category | Assistant |
| Name | OpenAI Codex |
| Methodology | Iterative debugging, refactoring, and documentation updates with owner review |
| Deliverables | Code fixes, IPv4/IPv6 reassembly, hyperscan integration, build updates, docs |
| Involvement | High (project handoff for debugging and fixes) |

Note: The project was handed over to the AI assistant for debugging and stabilization.
