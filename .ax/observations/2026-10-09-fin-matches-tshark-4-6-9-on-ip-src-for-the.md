---
id: 2026-10-09-fin-matches-tshark-4-6-9-on-ip-src-for-the
kind: observation
date: 2026-10-09
method: byte compare of field output, median of 3 warm runs, stdout discarded
---

fin matches tshark 4.6.9 on ip.src for the million-packet plain and QinQ files, and on 1,252 TLS server names in bigFlows.pcap. TLS names: fin 0.226s, tshark 7.872s, about 35x.
