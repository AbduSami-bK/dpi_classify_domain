#!/usr/bin/env python3
# By ChatGPT 5.2
from scapy.all import *
import random

random.seed(1337)

OUTPUT_PCAP = "test.pcapng"
FRAG_SIZE = 300

SRC_IP4 = "10.0.0.1"
DST_IP4 = "10.0.0.2"
SRC_IP6 = "2001:db8::1"
DST_IP6 = "2001:db8::2"

stats = {
    "total_fragments": 0,
    "total_packets": 0,
    "Google": 0,
    "FB": 0,
    "YT": 0,
    "GH": 0,
}

packets = []

def record(*domains):
    global stats
    stats["total_packets"] += 1
    for domain in domains:
        if domain in stats:
            stats[domain] += 1
        else:
            print(f"Error: {domain} not in stats")

def ipv4(pkt):
    return fragment(pkt, FRAG_SIZE)

def ipv6(pkt):
    raw = bytes(pkt[UDP].payload)
    frag_id = random.randint(0, 2**32 - 1)
    frags = []
    offset = 0
    while raw:
        chunk = raw[:FRAG_SIZE]
        raw = raw[FRAG_SIZE:]
        m = 1 if raw else 0
        fh = IPv6ExtHdrFragment(id=frag_id, offset=offset >> 3, m=m)
        frags.append(
            IPv6(src=SRC_IP6, dst=DST_IP6) / fh /
            UDP(sport=1234, dport=80) / Raw(chunk)
        )
        offset += len(chunk)
    return frags

### CASE 1: IPv4 fragmented, domain early (count)
p = b"A"*40 + b"google.com" + b"B"*400
record("Google")
packets += ipv4(IP(src=SRC_IP4, dst=DST_IP4)/UDP()/Raw(p))

### CASE 2: IPv4 fragmented, domain after 256 (don’t count)
p = b"A"*300 + b"facebook.com" + b"B"*200
record()
packets += ipv4(IP(src=SRC_IP4, dst=DST_IP4)/UDP()/Raw(p))

### CASE 3: No domains at all
p = b"X"*500
record()
packets += ipv4(IP(src=SRC_IP4, dst=DST_IP4)/UDP()/Raw(p))

### CASE 4: Two different domains in same packet
p = b"A"*30 + b"google.com----youtube.com" + b"B"*300
record("Google", "YT")
packets += ipv4(IP(src=SRC_IP4, dst=DST_IP4)/TCP()/Raw(p))

### CASE 5: Same domain twice (count once)
p = b"A"*20 + b"github.com---github.com" + b"B"*300
record("GH")
packets += ipv4(IP(src=SRC_IP4, dst=DST_IP4)/TCP()/Raw(p))

### CASE 6: Unfragmented packet with domain
p = b"A"*10 + b"facebook.com" + b"B"*50
record("FB")
packets.append(IP(src=SRC_IP4, dst=DST_IP4)/UDP()/Raw(p))

### CASE 7: Upper-case domain (don’t count)
p = b"A"*20 + b"GOOGLE.COM" + b"B"*200
record()
packets += ipv4(IP(src=SRC_IP4, dst=DST_IP4)/UDP()/Raw(p))

### CASE 8: Unicode noise around ASCII domain
p = "测试".encode("utf-8") + b"google.com" + "结束".encode("utf-8") + b"B"*200
record("Google")
packets += ipv4(IP(src=SRC_IP4, dst=DST_IP4)/UDP()/Raw(p))

### CASE 9: IPv6 fragmented, domain early
p = b"A"*50 + b"youtube.com" + b"B"*300
record("YT")
packets += ipv6(IPv6(src=SRC_IP6, dst=DST_IP6)/UDP()/Raw(p))

### CASE 10: IPv6 fragmented, domain after 256
p = b"A"*280 + b"github.com" + b"B"*100
record()
packets += ipv6(IPv6(src=SRC_IP6, dst=DST_IP6)/UDP()/Raw(p))

### CASE 11: googleAcom (should NOT count)
p = b"A"*40 + b"googleAcom" + b"B"*300
record()
packets += ipv4(IP(src=SRC_IP4, dst=DST_IP4)/UDP()/Raw(p))

### CASE 12: google\.com (escaped dot, should NOT count)
p = b"A"*40 + b"google\\.com" + b"B"*300
record()
packets += ipv4(IP(src=SRC_IP4, dst=DST_IP4)/UDP()/Raw(p))

### CASE 13: Domain split across fragments, within first 256 (COUNT)
# Place "google.com" such that it straddles fragment boundary
prefix_len = FRAG_SIZE - 5  # force split
p = b"A" * prefix_len + b"google.com" + b"B" * 200
record("Google")
packets += ipv4(IP(src=SRC_IP4, dst=DST_IP4)/UDP()/Raw(p))

### CASE 14: Domain starts before 256, ends after (DO NOT COUNT)
start = 250
p = b"A" * start + b"google.com" + b"B" * 200
record()
packets += ipv4(IP(src=SRC_IP4, dst=DST_IP4)/UDP()/Raw(p))

### CASE 15: google\x2ecom (COUNT)
p = b"A"*40 + b"google\x2ecom" + b"B"*300
record("Google")
packets += ipv4(IP(src=SRC_IP4, dst=DST_IP4)/UDP()/Raw(p))

### CASE 16: google\x00.com (DO NOT COUNT)
p = b"A"*40 + b"google\x00.com" + b"B"*300
record()
packets += ipv4(IP(src=SRC_IP4, dst=DST_IP4)/UDP()/Raw(p))

### CASE 17: google．com (U+FF0E, DO NOT COUNT)
p = b"A"*40 + "google．com".encode("utf-8") + b"B"*300
record()
packets += ipv4(IP(src=SRC_IP4, dst=DST_IP4)/UDP()/Raw(p))

### CASE 18: Overlapping fragments, last wins (COUNT github.com)
ip = IP(src=SRC_IP4, dst=DST_IP4, id=0xdead)
udp = UDP(sport=1111, dport=2222)

# First fragment contains google.com (should be overwritten)
p1 = ip/udp/Raw(b"A"*40 + b"google.com" + b"B"*300)

# Second fragment overlaps same offset, contains github.com
p2 = ip/udp/Raw(b"A"*40 + b"github.com" + b"C"*300)
frags = fragment(p1, FRAG_SIZE)
overlap_frags = fragment(p2, FRAG_SIZE)
# Same offsets → overwrite
packets += frags[:1] + overlap_frags[:1] + frags[1:]
record("GH")

### CASE 19: Duplicate identical fragment (COUNT once)
payload = b"A"*40 + b"google.com" + b"B"*300
ip = IP(src=SRC_IP4, dst=DST_IP4, id=0xbeef)/UDP()/Raw(payload)
frags = fragment(ip, FRAG_SIZE)
packets += frags + frags  # duplicate fragments
record("Google")

### CASE 20: Out-of-order fragments (COUNT facebook.com)
p = b"A"*40 + b"facebook.com" + b"B"*300
frags = fragment(IP(src=SRC_IP4, dst=DST_IP4, id=0x1234)/UDP()/Raw(p), FRAG_SIZE)
packets += frags[::-1]  # reverse order
record("FB")

### CASE 21: Same IP ID, different src IPs (COUNT BOTH)
p1 = b"A"*40 + b"google.com" + b"B"*300
p2 = b"A"*40 + b"github.com" + b"C"*300
frags1 = fragment(IP(src="10.0.0.1", dst=DST_IP4, id=999)/UDP()/Raw(p1), FRAG_SIZE)
frags2 = fragment(IP(src="10.0.0.2", dst=DST_IP4, id=999)/UDP()/Raw(p2), FRAG_SIZE)
packets += frags1 + frags2
record("Google")
record("GH")

### CASE 22: Same IP ID, TCP vs UDP (COUNT BOTH)
p = b"A"*40 + b"youtube.com" + b"B"*300
frags_tcp = fragment(IP(src=SRC_IP4, dst=DST_IP4, id=555)/TCP()/Raw(p), FRAG_SIZE)
frags_udp = fragment(IP(src=SRC_IP4, dst=DST_IP4, id=555)/UDP()/Raw(p), FRAG_SIZE)
packets += frags_tcp + frags_udp
record("YT")
record("YT")

### CASE 23: Missing middle fragment (DROP)
p = b"A"*40 + b"google.com" + b"B"*600
frags = fragment(IP(src=SRC_IP4, dst=DST_IP4, id=777)/UDP()/Raw(p), FRAG_SIZE)
packets += [frags[0], frags[-1]]  # drop middle fragment

wrpcapng(OUTPUT_PCAP, packets)

for stat, count in stats.items():
    print(f"{stat:16s}: {count}")
print(f"Total fragments written: {len(packets)}")
print(f"PCAP: {OUTPUT_PCAP}")
