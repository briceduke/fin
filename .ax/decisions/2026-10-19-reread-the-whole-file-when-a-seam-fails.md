---
id: 2026-10-19-reread-the-whole-file-when-a-seam-fails
kind: decision
date: 2026-10-19
---

## Context
A failed seam can be the whole file or the gap between the last proved stop and the next proved start. A gap is not a capture: it has no pcap header and no pcapng section or interface blocks.

## Options
- Reread only the unproved gap with a second parser
- Discard the parallel frames and call read_capture on the whole file

## Choice
A failed seam discards the parallel frames and returns read_capture on the whole file.

## Why
read_capture is the fallback and the reference. A partial reread would grow a second parser for slices that are not files. Whole-file fallback is slower on a miss and still matches tshark faults and ip.src.
