---
id: 2026-10-19-chunk-only-classic-pcap
kind: decision
date: 2026-10-19
supersedes:
  - 2026-10-19-prove-pcapng-seam-endian-with-the-previous-chunk
---

## Context
PR #9 split both pcap and pcapng. pcapng hopped block lengths in parallel, then peeled frames in file order because SHB/IDB state is serial. A later SHB can switch endian; offset abutment can still prove a wrong hop (`00 01 00 00` is 65536 BE and 256 LE). The measured 2× walk win was on a classic pcap. `fin -e ip.src` still walks merged frames on one core.

## Options
- Keep parallel pcapng hops, peel, and the endian seam check
- Chunk only classic pcap; pcapng calls read_capture

## Choice
Chunk only classic pcap; pcapng uses read_capture.

## Why
Pcapng frame extraction is already serial after the hop. Parallel hops added a second parser, an endian seam, and a crafted mixed-endian file for a walk that is 5% of ip.src. Classic pcap has a global layout, so parallel records are the speed win. If pcapng is split later, abutment is not enough: hop endian must match unless the start is an SHB.
