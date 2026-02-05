# Third-Party Notices

This project uses or links against the following third-party components:

## DPDK

- License: BSD-3-Clause
- Source: https://www.dpdk.org/
- Used for packet IO, mbuf handling, and IPv4/IPv6 reassembly.

## Hyperscan

- License: BSD-3-Clause
- Source: https://github.com/intel/hyperscan
- Used for fast literal matching in payloads (optional).

## Example/Reference Code

- DPDK example code (ip_reassembly, packet_ordering, etc.) informed parts of the structure.
- Sample code in `src/hyperscan_dpdk_example.c` references public examples.

Each component is governed by its own license. Please consult the respective
upstream repositories for full license texts.
