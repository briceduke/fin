---
id: 2026-10-14-tshark-4-6-9-ipv6-routing-types-3-5-6-and-hopopt-dstopts
kind: observation
date: 2026-10-14
method: live tshark 4.6.9 empty WIRESHARK_CONFIG_DIR vs packet-ipv6.c dissect_routing6_rpl, dissect_routing6_crh, and dissect_opts
---

tshark 4.6.9 IPv6 routing types 3/5/6 and hopopt/dstopts throw BoundsError past the type/option tvbuff so ip.src stays blank
