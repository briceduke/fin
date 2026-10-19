---
id: 2026-10-19-on-a-74-mb-million-packet-ethernet-file-a
kind: observation
date: 2026-10-19
method: release bench --chunked, one warmup, median of three, 19 Oct 2026, 4 VM cores
---

On a 74 MB million-packet Ethernet file, a 4-core in-memory chunked walk was 0.007s against 0.016s sequential.
