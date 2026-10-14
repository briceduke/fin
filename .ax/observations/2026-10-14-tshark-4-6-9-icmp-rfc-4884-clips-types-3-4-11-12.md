---
id: 2026-10-14-tshark-4-6-9-icmp-rfc-4884-clips-types-3-4-11-12
kind: observation
date: 2026-10-14
method: live tshark 4.6.9 empty WIRESHARK_CONFIG_DIR vs packet-icmp.c dissect_icmp; IPv6 embed flow 0x0100 lengths 0,1-13,14 and flow 1 length 1
---

tshark 4.6.9 ICMP RFC 4884 clips types 3/4/11/12 when byte 5 is nonzero and ntohs at offset 10 exceeds length*4
