# tshark 4.6.9 baseline

Preliminary experiment, 9 Oct 2026. These timings are tshark only. They are not a fin benchmark.

- **Machine:** Intel Core i9-14900HX, 32 GB RAM, Windows 11
- **tshark -v:** TShark (Wireshark) 4.6.9 (v4.6.9-0-g2d548b197c75).
- **Binary:** `C:\Program Files\Wireshark\tshark.exe` (not on PATH). editcap from the same install.
- **When:** 2026-10-09, after the corpus in `study/corpus.md` was written.
- **Method:** one process at a time. Every invocation passed `-n`. One untimed warmup per (file, query), then three timed runs. Median wall-clock from a `System.Diagnostics.Stopwatch` around `cmd.exe`; stdout discarded with `> NUL` except the noted stdout-to-file extra. Packets/sec = packet count / median seconds. First-run stderr was empty.

Queries:

| Name | Flags |
| --- | --- |
| stock | `-n -T fields -e ip.src` |
| only-lower | `-n -T fields -e ip.src --only-protocols eth,ip` (QinQ: `eth,vlan,ip`, plus a second `eth,ip` run) |
| disable-upper | `-n -T fields -e ip.src --disable-protocol udp --disable-protocol tcp --disable-protocol dns --disable-protocol http --disable-protocol tls --disable-protocol data` |
| floor | `-n -T fields -e frame.number` |
| ceiling | `-n -V` on a 20,000-packet prefix (`editcap -r … 1-20000`), then the prefix was deleted |
| stock-with-stdout | stock on `eth-ipv4-udp.pcap` only, stdout written to a file and then deleted |

## eth-ipv4-udp.pcap (1,000,000 packets)

| query | median s | packets/s | notes |
| --- | ---: | ---: | --- |
| stock | 7.9700 | 125,471 | stdout discarded |
| only-lower | 5.7895 | 172,727 | `--only-protocols eth,ip` |
| disable-upper | 6.2305 | 160,501 | |
| floor | 7.9328 | 126,058 | `-e frame.number` |
| ceiling | 3.4168 | 5,853 | `-V` on 20,000-packet prefix |
| stock-with-stdout | 6.2622 | 159,689 | stdout 13,472,986 bytes (12.8 MiB); file not kept |

Three-run spreads were small (stock 7.969–8.119 s; only-lower 5.705–5.913 s). only-lower is 27% faster than stock; disable-upper is 22% faster. floor matches stock (0.5% apart). `-V` on 20k packets is 5,853 packets/s, about 21× slower per packet than stock.

stock-with-stdout ran after the other queries on this file (cache already warm) and wrote 12.8 MiB of `ip.src` lines. It was faster than stock-to-NUL, so formatting that one field and writing it to disk is not what made stock slow relative to only-lower.

## eth-qinq-ipv4-udp.pcap (1,000,000 packets)

| query | median s | packets/s | notes |
| --- | ---: | ---: | --- |
| stock | 8.8286 | 113,269 | stdout discarded; `ip.src` populated |
| only-lower | 2.7516 | 363,423 | `--only-protocols eth,vlan,ip`; **ip.src empty (0/50 sample); not a win** |
| only-lower-no-vlan | 2.7099 | 369,018 | `--only-protocols eth,ip`; **ip.src empty (0/50 sample); not a win** |
| disable-upper | 7.0574 | 141,696 | |
| floor | 8.7398 | 114,420 | |
| ceiling | 3.9466 | 5,068 | `-V` on 20,000-packet prefix |

Stock still prints `ip.src` through QinQ. `--only-protocols eth,vlan,ip` does not: a 50-packet sample on this file had 0 nonempty `ip.src` lines. On the 100-packet sibling, `frame.protocols` was `eth:ethertype:data` (outer ethertype 0x88a8 never became `vlan`). The ~2.75 s times are a truncated walk, not a faster `ip.src` query.

disable-upper still produces `ip.src` and is 20% faster than stock. floor is 1% faster than stock.

## mixed.pcap (1,000,000 packets)

| query | median s | packets/s | notes |
| --- | ---: | ---: | --- |
| stock | 5.6736 | 176,254 | half the packets are ARP (no `ip.src`) |
| only-lower | 4.3207 | 231,446 | `--only-protocols eth,ip` |
| disable-upper | 4.8607 | 205,732 | |
| floor | 6.6181 | 151,101 | slower than stock |
| ceiling | 2.7773 | 7,201 | `-V` on 20,000-packet prefix |

only-lower is 24% faster than stock; disable-upper is 14% faster. floor is slower than stock on this file (every packet still emits `frame.number`; stock emits an address on only half).

## real/challenge01_ooo_stream.pcapng (1,670 packets)

Too small to rank against the million-packet synthetics (threshold was 50,000 packets). Timed once through the same queries so the number exists. Wall-clock is process-startup-sized (~0.13 s).

| query | median s | packets/s | notes |
| --- | ---: | ---: | --- |
| stock | 0.1336 | 12,496 | too small to rank |
| only-lower | 0.1228 | 13,600 | |
| disable-upper | 0.1243 | 13,430 | |
| floor | 0.1349 | 12,383 | |
| ceiling | 0.5876 | 2,842 | `-V` on the full 1,670-packet file |

## Reading the thesis

The thesis said stock `-e ip.src` is close to a full walk, and that `--only-protocols` / `--disable-protocol` on upper protocols is faster if upper dissectors dominate.

On this UDP-payload corpus, stock is close to the **floor**, not the **ceiling**. On `eth-ipv4-udp.pcap`, stock (7.97 s, 125k packets/s) and `-e frame.number` (7.93 s, 126k packets/s) are the same. `-V` on a 20k prefix is 5.9k packets/s, about 21× slower per packet. Stock is not a verbose tree dump.

Upper dissectors do cost time, and the flags that still return `ip.src` are faster: only-lower 27% / disable-upper 22% on the plain file; disable-upper 20% on QinQ; only-lower 24% / disable-upper 14% on mixed. That is a real but minority slice of the stock time. Most of the 8 s on the plain million-packet file is still there after UDP/TCP/DNS/HTTP/TLS/data are disabled, so the time is elsewhere (frame/eth/ip work, the packet loop, field extraction, I/O). Writing 12.8 MiB of `ip.src` lines was not slower than discarding stdout.

QinQ `--only-protocols eth,vlan,ip` looks like a large win (2.75 s) but drops `ip.src` to empty, so it is not evidence for the thesis. `--disable-protocol` on upper protocols is the fair QinQ comparison, and it matches the plain-file pattern: faster, not dominant.

The real capture is 1,670 packets and does not count in this ranking.
