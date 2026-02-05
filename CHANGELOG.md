# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]
- Added RX and classifier threads with ring handoff.
- Implemented IPv4 and IPv6 reassembly using DPDK ip_frag.
- Added Hyperscan (system) support with memmem fallback.
- Added per-domain counters and performance metrics.
- Added optional payload printing.

## [0.1.0] - 2026-02-05
- Initial working `mini_dpi` pipeline with DPDK + pcap PMD.
