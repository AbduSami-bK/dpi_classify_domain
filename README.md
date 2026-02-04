# Mini-DPI

This is a mini DPI project, done as a hiring task for a firm.
The program reads IP packets and counts the packets related to four hard-coded websites.

## Pre-requisites

This program is built using:

- DPDK  25.11.
- CMake 3.26.5
- GCC   11.5.0
- OS    Rocky Linux 9.7
- Linux Kernel  5.14.0-611
- libc  2.34
- Boost 1.75 (>= 1.61)
- Ragel 7.0.0.12
- RDMA-Core-devel (Lib-ibVerbs) 57.0

Make sure your system has these or later versions of these.
Commands to check versions:

```bash
cmake --version
gcc --version
cat /etc/os-release
ldd --version
dnf list installed kernel boost-devel ragel rdma-core-devel
```

Tested with vfio_pci on "82540EM Gigabit Ethernet Controller 100e" by libvirtd (non-iommu mode)

## How to build

[TODO] _exact build commands_

1. Make sure all the listed pre-requisites are installed in you system. The listed version or later.
2. Setup DPDK
    1. Hugepages
    2. [Optional] Isolate CPUs for performance
        1. Reboot
    3. Bind interfaces.
3. `mkdir build`
5. `cd build`
4. `cmake -G Ninja ..`
6. `ninja`

## How to run

- `./build/build/dpi_classify_domain -l 0 -a 00:09.0`
- `./build/build/dpi_classify_domain -l 0 --vdev net_af_packet0,iface=ens9`
- Ctrl+C to close.
