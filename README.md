# Mini-DPI

A minimal DPDK-based DPI pipeline that reassembles IPv4/IPv6 packets, extracts TCP/UDP payloads,
and classifies them by FQDN using Hyperscan (or memmem fallback).

## Features

- DPDK RX + multi-core pipeline
- IPv4 + IPv6 reassembly (ip_frag)
- TCP/UDP payload scanning (first 256 bytes)
- Hyperscan support (system package preferred)
- Optional payload printing
- Performance stats (pps, gbps, avg latency)

## Build

```bash
mkdir -p build
cd build
cmake -G Ninja -DUSE_HYPERSCAN=ON -DUSE_SYSTEM_HYPERSCAN=ON ..
ninja
```

If Hyperscan is not available:

```bash
cmake -G Ninja -DUSE_HYPERSCAN=OFF ..
```

## Run

### Pcap PMD

```bash
./build/mini_dpi --cfg-file /root/dpi_classify_domain/config/mini_dpi.cfg
```

### AF_PACKET

```bash
./build/mini_dpi -l 0-2 \
  --vdev 'net_af_packet0,iface=eth0' \
  -- --cfg-file /root/dpi_classify_domain/config/mini_dpi.cfg --port 0 --ring-size 4096 --frag-timeout-ms 30000
```

## App Args

- `--port N` DPDK port
- `--auto-port` select pcap vdev automatically
- `--list-ports` list available ports
- `--ring-size N` ring size between RX and classifier
- `--frag-timeout-ms N` reassembly timeout
- `--print-payloads` print TCP/UDP payloads
- `--print-max N` limit payload print bytes
- `--perf` print pps/gbps/avg latency
- `--log-file PATH` write errors to a log file (default: stderr)
- `--debug-dump N` dump first N non-IPv4/IPv6 packets (debug)
- `--cfg-file PATH` load configuration file (CLI overrides config)
- `--log-level LEVEL` set log level (emerg|alert|crit|err|warning|notice|info|debug)

When `--perf` is enabled, the app exits after ~1,000,000 classified packets and prints a final summary.

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
