---
id: 2026-10-14-tshark-4-6-9-ipv6-routing-type-2-and-4
kind: observation
date: 2026-10-14
method: live tshark 4.6.9 empty WIRESHARK_CONFIG_DIR vs packet-ipv6.c dissect_routing6_mipv6 and dissect_routing6_srh
---

tshark 4.6.9 IPv6 routing type 2 and 4 throw BoundsError on a short type-specific tvbuff so ip.src stays blank
