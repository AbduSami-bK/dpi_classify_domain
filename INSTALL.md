# Installation

## Prerequisites

- DPDK >= 22.11 (pkg-config provides `libdpdk`)
- CMake >= 3.26
- Ninja
- GCC >= 11
- Hyperscan (optional for faster matching)

On Rocky Linux:

```bash
# base build tools
dnf install -y gcc gcc-c++ cmake ninja-build pkgconfig

# optional: Hyperscan
dnf install -y hyperscan hyperscan-devel
```

## Build

```bash
mkdir -p build
cd build
cmake -G Ninja -DUSE_HYPERSCAN=ON -DUSE_SYSTEM_HYPERSCAN=ON ..
ninja
```

If Hyperscan is not available, use:

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

### Optional flags

- `--print-payloads` prints TCP/UDP payloads to stdout
- `--print-max N` limits bytes printed per packet
- `--perf` prints pps/gbps/avg latency in the stats line
- `--log-file PATH` writes error logs to a file (default: stderr)
- `--cfg-file PATH` load configuration file (CLI overrides config)
- `--log-level LEVEL` set log level (emerg|alert|crit|err|warning|notice|info|debug)

## Config File

Edit `config/mini_dpi.cfg` before running. It supports both EAL args and app args.
