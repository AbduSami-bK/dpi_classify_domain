# Copilot Instructions for Mini-DPI

## Quick summary

Mini-DPI is a DPDK-based IPv4 packet classification app: RX thread ingests packets, a worker performs IPv4 reassembly using DPDK's ip_frag API, and a classifier thread scans payloads for hard-coded FQDNs (Hyperscan optional). Communication between threads is via lock‑free `rte_ring` queues.

## Architecture & important patterns 🔧

- **Multi-threaded DPDK application** using lock-free `rte_ring` queues for inter-thread communication
- **RX Thread**: Ingests packets from network interfaces, parses IP headers, identifies fragmentation
- **Worker Thread**: IPv4 reassembly (out-of-order, timeout handling), payload scanning, counter updates
- **Main Thread**: Signals, stats printing (1-second intervals), graceful shutdown

## Key Dependencies & Building

### Required Tools

- DPDK 25.11+ (libdpdk-dev)
- CMake 3.26.5+
- GCC 11.5.0+
- Hyperscan (included as git submodule in `/hyperscan/`)
- Ragel 7.0.0.12, RDMA-Core-devel, Boost 1.75+

### Build Workflow

```bash
mkdir build && cd build
cmake -G Ninja ..        # Uses DeepSeek-converted CMakeLists.txt
ninja                    # Produces build/mini_dpi, build/mini_dpi-shared, build/mini_dpi-static
```

**Key CMake patterns:**
- Build options: `BUILD_SHARED`, `BUILD_STATIC` (default both ON)
- Debug flags: `-O0 -g -g3 -ggdb -pg`; Release: `-O3`
- Output directory: `${CMAKE_BINARY_DIR}/build/`

**Build gotchas (practical tips):**
- Add `${CMAKE_SOURCE_DIR}/include` to `target_include_directories()` so project headers like `thread_rx.h` resolve.
- DPDK headers may use `ssize_t`; include `<sys/types.h>` in files that include DPDK headers to avoid errors.
- If linker errors say undefined references, ensure the .c implementing the function is added to `SRCS-y` in `CMakeLists.txt`.

## Critical Architecture Patterns

### 1. mbuf (Memory Buffer) Lifecycle

- **Creation**: Allocated in pool (`rte_pktmbuf_pool_create`) during initialization
- **RX**: Bursts received via `rte_eth_rx_burst(MAX_PKT_BURST=32)`
- **Enqueue**: Pushed to `ring_rx_to_worker` via `rte_ring_enqueue_burst()` (drop if full)
- **Worker**: Dequeued, reassembled (if fragmented), classified, freed
- **Critical**: Unowned mbufs cause memory leaks; all paths must free (success, drop, timeout, malformed)

### 2. IPv4 Reassembly Strategy

- **Trigger**: `DF==0 && (MF==1 || fragment_offset != 0)`
- **Key**: `(src_ip, dst_ip, ip_id, protocol)` for identifying fragments
- **Out-of-order handling**: Keep unordered fragments; merge on arrival of missing offsets
- **Timeout**: Configurable (default 30s); expire & free all fragments on timeout
- **Overlapping/Duplicate**: Accept latest fragment
- **Track stats**: `fragments_seen`, `packets_reassembled`, `frag_timeouts`, `frag_drops`

### 3. Pattern Matching & FQDN Detection

- **Engine**: Hyperscan (`hs_scan_vector()` for multi-segment mbufs)
- **Compiled patterns**: Hard-coded strings (google.com, youtube.com, facebook.com, github.com)
- **Callback**: `match_found()` increments counter, receives match ID & payload position
- **Constraint**: Scan first 256 bytes of payload only; do NOT copy payload
- **Multi-segment handling**: Hyperscan API handles non-contiguous mbuf chains

### 4. Macro-based FQDN Configuration (X-Macro Pattern)

```c
#define FQDN_LIST \
    X(GOOGLE,   "google.com",   "Google") \
    X(YOUTUBE,  "youtube.com",  "YT")
enum fqdn_id { #define X(id, str, name) id##_id, FQDN_LIST #undef X UNKNOWN };
static const char *fqdn_list[] = { #define X(id, str, name) str, FQDN_LIST #undef X };
```
**Rationale**: Single source of truth; automatic enum/list/name generation (from Gemini 3 discussion on preprocessor patterns).

### 5. Ring & Queue Management
- **Lock-free design**: No mutexes; single RX thread enqueues, single worker dequeues
- **Drop handling**: If `rte_ring_enqueue_burst()` fails, increment `ring_drop` counter
- **Ring size**: Configurable via command-line `--ring-size`; default TBD

## Development Workflows

### Testing

- **Packet generation**: [test/test_pkt_gen.py](test/test_pkt_gen.py) generates fragmented IPv4 packets with embedded FQDNs (ChatGPT 5.2, Scapy-based)

### Common Commands

- **Run from pcap**: `./build/build/mini_dpi --vdev net_pcap0,rx_pcap=/path/to/file.pcap`
- **Run from interface**: `./build/build/mini_dpi --vdev net_af_packet0,iface=ens9 -l 0`
- **Port binding**: Requires `vfio_pci` driver binding; adjust EAL args `-l` (lcores) and `-a` (port address)
- **Graceful exit**: Ctrl+C (SIGINT/SIGTERM), prints final stats

### Configuration

- [config/config.yaml](config/config.yaml): Log level only (0=Debug to 7=Error)
- TODO: Move hard-coded FQDNs (currently in `include/fqdn_list.h`) to a runtime YAML configuration for easier updates.

## Code Style & Patterns

- **Language**: C11 (enforced in CMakeLists.txt)
- **Comments**: Document "why" behind design decisions, not obvious logic
- **Documentation**: Incomplete [docs/code_style.md](docs/code_style.md); see [docs/implementation_notes.md](docs/implementation_notes.md) for gaps
- **Naming**: `thread_*`, `rte_*` (DPDK functions), `fqdn_*` (pattern matching)

## Incomplete Sections & Next Steps

These sections require implementation before v1.0:

1. **[docs/implementation_notes.md](docs/implementation_notes.md)**: Document "Drops" (where/why), reassembly algorithm details, mbuf lifecycle decisions
2. **Config file integration**: Move FQDNs from macros to YAML (v0.9)
3. **Thread implementations**: Worker (`src/thread_rx.c`) and classifier (`src/thread_classifier.c`) are implemented. Classifier supports Hyperscan (when built with `USE_HYPERSCAN`) and falls back to `memmem` if not available.
4. **Unit test completion**: `test/unit_tests.c` is scaffolded; add cases for fragmentation, timeouts, reassembly, and counter correctness. Consider adding a CI job to run a smoke test using `test/test.pcap`.
5. **Performance testing**: Benchmark throughput, latency, drop rate

## External References

- [DPDK Programmer's Guide](https://doc.dpdk.org/) — mbuf, rte_ring, ethdev, ip_frag
- [Hyperscan User Guide](https://intel.github.io/hyperscan/) — `hs_scan_vector()`, scratch allocation, compile error handling
- [Ragel State Machine Compiler](https://www.colm.net/open-source/ragel/) — optional for protocol parsing

## AI Involvement Tracker

| Tool | Generated Content | Methodology |
|------|-------------------|-------------|
| ChatGPT 5.2 | [src/main.c](src/main.c) skeleton | DPDK sample app generation |
| DeepSeek | [CMakeLists.txt](CMakeLists.txt) | Makefile → CMake conversion |
| ChatGPT 5.2 | [test/test_pkt_gen.py](test/test_pkt_gen.py) | Scapy packet generation |
| Gemini 3 | [src/main.c](src/main.c) | X-macro pattern discussion & pattern matching perf |
