#!/usr/bin/env python3
from scapy.all import Ether, IP, UDP, TCP, Raw, wrpcap

packets = []

# Simple unfragmented packets with domains
packets.append(Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / 
               IP(src="10.0.0.1", dst="10.0.0.2") / 
               UDP() / 
               Raw(b"A"*40 + b"google.com" + b"B"*200))

packets.append(Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / 
               IP(src="10.0.0.1", dst="10.0.0.2") / 
               TCP() / 
               Raw(b"X"*50 + b"youtube.com" + b"Y"*150))

packets.append(Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / 
               IP(src="10.0.0.1", dst="10.0.0.2") / 
               UDP() / 
               Raw(b"Z"*100 + b"facebook.com" + b"W"*100))

packets.append(Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / 
               IP(src="10.0.0.1", dst="10.0.0.2") / 
               TCP() / 
               Raw(b"Q"*60 + b"github.com" + b"R"*150))

wrpcap("simple.pcapng", packets)
print("Written simple.pcapng with 4 unfragmented packets containing google.com, youtube.com, facebook.com, github.com")
