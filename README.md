# Mini-DPI

A minimal DPDK-based DPI pipeline that reassembles IPv4/IPv6 packets, extracts TCP/UDP payloads,
and classifies them by FQDN using Hyperscan (or memmem fallback).

## Features

- DPDK RX + multi-core pipeline
- IPv4 + IPv6 reassembly (ip_frag)
- TCP/UDP payload scanning (first 256 bytes)
- Hyperscan support (system package preferred)
- Performance stats (pps, gbps, avg latency)

## Build

```bash
sudo dnf install gcc gcc-c++ cmake ninja-build pkgconfig hyperscan hyperscan-devel
mkdir -p build
cd build
cmake -G Ninja ..
ninja
```

## Run

```bash
./build/build/mini_dpi -l 0-2 --vdev 'net_pcap0,rx_pcap=test/test.pcap' \
  -- --port 0 --ring-size 4096 --frag-timeout-ms 30000
```

```bash
./build/build/mini_dpi -l 0-2 --vdev 'net_af_packet0,iface=eth0' \
  -- --port 0 --ring-size 4096 --frag-timeout-ms 30000
```

## App Args

- `--port N` DPDK port (default 0)
- `--port-mask HEX` port mask (must select exactly one port)
- `--ring-size N` ring size between RX and classifier
- `--frag-timeout-ms N` reassembly timeout
- `--print-payloads` print TCP/UDP payloads
- `--print-max N` limit payload print bytes
- `--perf` print pps/gbps/avg latency
- `--debug-dump N` dump first N non-IPv4/IPv6 packets (debug)

When `--perf` is enabled, the app exits after ~1M classified packets and prints a final summary.

## DPDK Setup Notes

- Allocate hugepages and mount hugetlbfs (required for most DPDK PMDs).
- Bind NICs to DPDK-compatible drivers where needed.
- Ensure your user has permission to access hugepages and NICs.

## Notes

- Use `-l 0-2` to enable main + RX + classifier cores.
- Hyperscan uses system packages when available.

## Dependencies

- DPDK (>= 22.11)
- GCC, CMake, Ninja
- Hyperscan (optional)

## Licenses

See `LICENSE` and `NOTICE.md`.
