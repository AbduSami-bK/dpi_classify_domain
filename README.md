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
- Hyperscan (optional, for fast FQDN matching)

Make sure your system has these or later versions of these.
Commands to check versions:

```bash
cmake --version
gcc --version
cat /etc/os-release
ldd --version
dnf list installed kernel boost-devel ragel rdma-core-devel
dnf list installed hyperscan hyperscan-devel
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

## [Delete] Project plan

1. Get DPDK sample app to ingest packets from pcap
2. Save global rx stats
3. Write unit tests for stats
4. Write a Cmake file to compile and test
5. Update README with build and run commands.
6. Write a Changelog.md
7. Merge v0.1 to master
8. Ingest packets from port
9. Exit on signals
10. Create a sample pcap with FQDN packets
11. Parse IP layer
12. Merge v0.2 to master
13. Detect fragmentation
14. ReAssemble
15. fragmentation stats
16. Unit tests
17. Merge v0.3 to master
18. Out of order fragments
19. ReAssembly timeout
20. Unit tests
21. Merge v0.4 to master
22. Parse TCP & UDP upto first 256 byte payloads
23. Unit tests
24. Merge v0.5 to master
25. Configure Hyperscan
26. Hard-coded FQDN counters.
27. Unit tests
28. Merge v0.6 to master
29. Performance test
30. Write implementation notes
31. Merge v0.7 to master
32. Correct lifecycles
33. Get reviewed by AI
34. Performance optimizations
35. Merge v0.8 to master
36. Move hard-coded FQDNs to config file
37. Unit tests
38. Merge v0.9 to master
39. Let program take config file path as cmd input
40. Unit tests
41. Merge v1 to master
