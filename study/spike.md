# Reader spike

Preliminary experiment, 9 Oct 2026. The reader was a throwaway spike and is not in the tree. Same machine and timing method as `study/benchmark.md`: one warmup, median of three runs, stdout discarded with `cmd > NUL`. tshark invocations pass `-n`.

## ip.src

Byte-identical to `tshark -n -T fields -e ip.src` on:

- `study/corpus/eth-ipv4-udp.pcap` (1,000,000 packets)
- `study/corpus/eth-qinq-ipv4-udp.pcap` (1,000,000 packets)
- both 100-packet siblings

QinQ uses ethertypes `0x88a8` then `0x8100`. The IPv4 source is at frame offset 34, not 26.

| File | throwaway reader | tshark median from the baseline |
| --- | ---: | ---: |
| plain | 0.0561 s | 7.970 s |
| QinQ | 0.0570 s | 8.829 s |

An earlier timing on a quieter machine was 0.0480 s and 0.0494 s. The table uses the run from the same session as the TLS timing.

## TLS server names

Capture: `study/corpus/real/bigFlows.pcap`.

- Source: `https://s3.amazonaws.com/tcpreplay-pcap-files/bigFlows.pcap`
- Real traffic from a private network's internet access point, 26 Feb 2013, five minutes
- 791,615 packets, 368,083,648 bytes, Ethernet, classic pcap

Query: `tls.handshake.extensions_server_name`.

| Tool | median |
| --- | ---: |
| tshark 4.6.9 | 7.8721 s |
| throwaway reader | 0.2260 s |

7.8721 / 0.2260 = 34.8. File bytes / 0.2260 s = 1.63 GB/s.

Output was byte-identical: 791,615 lines, 1,252 non-empty names. A first build printed 10 extra names. Each of those frames is a suspected TCP retransmission of a ClientHello tshark had already accepted (seq 1, port 443). The spike kept the first segment and left the repeat blank, which matched tshark.
