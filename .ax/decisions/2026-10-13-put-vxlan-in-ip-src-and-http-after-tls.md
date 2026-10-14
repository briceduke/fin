---
id: 2026-10-13-put-vxlan-in-ip-src-and-http-after-tls
kind: decision
date: 2026-10-13
supersedes:
  - 2026-10-10-move-ip-src-cases-ahead-of-the-chunk-split
---

## Context
The locked build order put ICMP, tunnels, and fragments on the TLS step, and never placed HTTP. VXLAN changes ip.src. HTTP is a stream field like the TLS server name.

## Options
- Leave VXLAN on the TLS step and leave HTTP unscheduled
- Walk VXLAN in the ip.src step, and put HTTP after TLS server names

## Choice
Build the diff harness, then the sequential reader, then ip.src including VXLAN, then the chunk split, then TLS server names, then HTTP.

## Why
VXLAN UDP 4789 yields an inner Ethernet that can carry ip.src, so it belongs with the first field. HTTP needs reassembly and is the second stream field after TLS. The earlier order still holds for the checker, sequential reader, chunk split, and TLS.
