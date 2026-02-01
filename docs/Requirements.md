# Program Requirements

## Constraints

- Correct usage of
  - `mbuf` lifecycle
  - EAL
  - mempools
  - `ethdev`
  - rte_ring
- C11
- DPDK >= 22.11
- multi-core. At least 2.

## Deliverables

- [ ] 1 executable: `mini_dpi`
  - [ ] Source code
- [X] CMake files
- [ ] README
  - [ ] exact build commands
  - [ ] exact run commands
    - [ ] EAL args
    - [ ] vdev examples
- [ ] Short implementation notes
  - [ ] where drops occur
  - [ ] why drops occur
  - [ ] how re-assembly is implemented
  - [ ] mbuf lifecycle decisions
  - [ ] Use of AI
    - [ ] Type
      - [ ] Category
      - [ ] Name
    - [ ] Usage Methodology
    - [ ] Generated Deliverables
      - [ ] mention involvement level
- [ ] Performance Test

## Flow

1. Input
    - pcap PMD

        `--vdev net_pcap0,rx_pcap=/root/Packets/in.pcap`

    - af_packet

        `--vdev net_af_packet0,iface=eth0`

    - `--port 0`
    - `--ring-size <n>`
    - `--frag-timeout-ms <n>`

2. 2 stage pipeline
    - `rte_ring` pipeline
3. Rx thread
    1. `rte_eth_rx_burst()`
    2. Parse and identify fragmentation fields
    3. Enqueue mbufs to `ring_rx_to_worker` with `rte_ring_enqueue_burst()`
    4. If ring is full, drop packet & ++ `ring_drop` counter
4. Worker thread
    1. Dequeue from `ring_rx_to_worker` with `rte_ring_dequeue_burst`
    2. IPv4 Reassembly
        1. When `DF==0 && (MF==1 || fragment+-offset != 0)`
        2. Optional: ip_frag lib (`rte_ip_frag_*`) or implement own
        3. Memory safety
        4. Correct usage
        5. Reassembly key: src_ip, dst_ip, ip_id, protocol
        6. Handle out-of-order fragments
        7. Configurable timeout. Default 30 seconds. Expire and free all associated fragments on timeout
        8. Duplicate / overlapping fragments: choose latest one.
        9. Keep statistics:
            1. `fragments_seen`
            2. `packets_reassembled`
            3. `frag_timeouts`
            4. `frag_drops`
    3. Classify payload
        1. TCP & UDP
        2. Scan first 256 payload bytes for:
            1. case "google.com": ++Google
            2. case "youtube.com": ++YouTube
            3. case "facebook.com": ++Facebook
            4. case "github.com": GitHub
            5. default: ++Unknown
        3. Do not copy payload
        4. Handle multi-segment mbufs
    4. Update counters
    5. Free `mbufs`
        1. success
        2. drop
        3. timeout
        4. malformed
5. Every 1 second, Print
    1. `packets_rx`, `packets_worker_in`
    2. `fragments_seen`, `packets_reassembled`, `frag_drops`
    3. `ring_drop`
    4. `Google`, `YouTube`, `Facebook`, `GitHub`, `Unknown`
6. On `SIGINT` || `SIGTERM`
    1. graceful stop
    2. print stats

## Performance Test

- `--perf`
- maximum achievable throughput
- Using `rte_rdtsc()`
- Output:
  - pps
  - Gbps
  - Average latency b/w input packet and classification counter increment in microseconds
- Test with >= 1 Million packets. Loop or synthesize
