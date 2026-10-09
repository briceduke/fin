# fin

fin is an open-source packet analyzer.

The command line takes the same flags and the same filter syntax as tshark, so existing scripts keep working. A field query reads only the bytes that field needs. The speed comes from that reader. Turning off extra protocols inside tshark only saves about a third, because tshark still pays its per-packet engine. Every result is checked, byte for byte, against tshark.

The figures below are from preliminary experiments on 9 Oct 2026. They are not a product benchmark, and the reader that produced the fin column has been removed.

On a real capture of a busy office network, `bigFlows.pcap` (368 MB, 791,615 packets), tshark 4.6.9 takes **7.87 seconds** to list TLS server names. The throwaway reader took **0.226 seconds** and printed the same 1,252 names. That is **35 times** faster, about 1.6 GB/s on this file.

fin can index an archive of captures, so one connection can be pulled out of a terabyte of traffic in milliseconds. It can also export packets to Parquet, where they can be queried with SQL.

The desktop app runs on the same engine. It has a packet list, a detail view, a hex view, and a filter bar. It decodes only what is on screen, so a 50 GB capture opens as fast as a small one.

## Preliminary experiments

9 Oct 2026. TShark 4.6.9 (`v4.6.9-0-g2d548b197c75`). Intel Core i9-14900HX, 32 GB RAM, Windows 11. One warmup, then the median of three runs. Stdout discarded. tshark was passed `-n`.

| Query | Capture | tshark | throwaway reader |
| --- | --- | ---: | ---: |
| TLS server name | bigFlows.pcap, 368 MB, 791,615 packets | 7.87 s | 0.226 s |
| `ip.src` | 1,000,000 plain Ethernet + IPv4 + UDP packets, 74 MB | 7.97 s | 0.056 s |
| `ip.src` | 1,000,000 QinQ + IPv4 + UDP packets, 82 MB | 8.83 s | 0.057 s |

The throwaway reader's `ip.src` output matched tshark on both million-packet files, including QinQ, where the address is not at a fixed offset in the frame. The TLS names matched, including tshark's choice to leave a retransmitted ClientHello blank.

The same `ip.src` query inside tshark costs the same as printing the packet number. Disabling UDP, TCP, DNS, HTTP, TLS, and data saves 22%. The long notes are `study/mechanism.md`, `study/benchmark.md`, and `study/spike.md`.
