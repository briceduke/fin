---
id: 2026-10-19-simplified-pcap-only-chunking-is-0-004s-against-0-009s-sequential
kind: observation
date: 2026-10-19
method: release bench --chunked, cargo clean between builds, two runs each side, 4 VM cores
---

simplified pcap-only chunking is 0.004s against 0.009s sequential on the 74 MB file, matching the pre-cut chunked walk
