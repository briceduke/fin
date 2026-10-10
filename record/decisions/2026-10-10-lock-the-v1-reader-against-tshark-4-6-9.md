---
id: 2026-10-10-lock-the-v1-reader-against-tshark-4-6-9
kind: decision
date: 2026-10-10
---

## Context

The study showed that a query-specific reader can match tshark 4.6.9 and run far ahead of it. The throwaway reader is gone. A later session that links epan, guesses past a header it did not walk, or treats a personal tshark profile as the oracle will ship a different tool.

On an empty config directory, tshark 4.6.9 has `nameres.network_name` off. `-e ip.src` and the summary line are the same numeric addresses with `-n` and without it.

## Options

- Link epan and special-case the hot fields
- One sequential reader for every query
- A plan the reader walks, chunks for header queries, and a count for any frame the plan cannot prove

## Choice

The v1 reader compiles one plan, matches tshark 4.6.9 on claimed paths, and counts any frame it cannot prove.

## Why

The oracle is tshark 4.6.9. The README and `fin --version` say so. When that version moves, snapshot its TCP and UDP port tables again. The test harness points tshark at an empty config directory so a personal preferences file cannot change resolution, reassembly, or ports.

`-n` may be present or absent. Fin prints numeric addresses and does not look up names. `-N` is unclaimed, so passing it is an error. An unknown field or flag is an error. Repeated values are comma-separated, in tshark's order. `-E` is an error. `-Y` is unclaimed. The only claimed `-o` is `tcp.reassemble_out_of_order:TRUE`.

v1 claims `ip.src` and `tls.handshake.extensions_server_name`. IPv4 and IPv6 are both walks. `ipv6.src` is not claimed yet.

A query compiles to one data plan: an ordered node list, the extracts, a stream bit, and a reorder bit. Layout nodes are tables. Parser nodes are functions. One loop walks the plan. Frames go in (link type, timestamp, original length, captured bytes). Typed rows come out. An empty cell is a value. The CLI renders `-T fields`. pcap and pcapng are adapters. stdin and live capture use the sequential reader later.

Entrypoints are Ethernet, classic SLL, and SLL2. Any other link type is unclaimed. VLAN and QinQ are shims. IPv6 extension headers are walked. The Authentication Header uses 4-byte length units and has its own test. ESP stops the walk. The walker steps by the packet's captured length, even when that length exceeds the snaplen or the original length. Timestamps are not a sync check.

ICMP errors carry a second `ip.src`. Walk types 3, 4, 5, 11, and 12, and ICMPv6 types 1, 2, 3, and 4. Skip the 8-byte ICMP header, read one embedded IP header when it is fully present, and append its source. Do not walk further inside it. Echo is not an error. When `tcp.port` is claimed later, that node walks one layer further.

IP fragments keep `ip.src`, because that header is complete. A stream field on a fragment is unclaimed. Fin does not reassemble IP.

TCP TLS follows the tshark 4.6.9 port order. If the SYN was seen, the client port is ignored. Otherwise the lower port is tried, then the higher one. A TLS port that gets its turn means the flow is TLS. If a non-TLS dissector is in the way and a later step could still be TLS, count the frame. The heuristic runs only when tshark would reach it, and a match sticks to the flow. `tcp.try_heuristic_first` is unclaimed. The port table is a snapshot from this tshark, stored in the repo, not a live call. Non-443 TLS ports are in the corpus.

A server name uses in-order reassembly of one TLS record. The cell is written on the frame that completes the record. A retransmit of bytes already consumed is blank. A gap stays blank. The reorder flag uses the same buffer and the same completing-frame rule.

UDP is not parsed as QUIC or DTLS in v1. Count a datagram that contains a QUIC Initial (long header, Initial type), even when that Initial is not first. Count a DTLS handshake record. Short-header QUIC and DTLS application data are blank and are not counted. Decrypting QUIC Initials is the first work after v1: initial keys, CRYPTO frames, reassembly across Initials, then the same ClientHello parser.

A frame is counted only when a claimed field sits in bytes the plan did not walk. The run still prints rows. The cell holds only proved values. Stderr says the lines may differ, names the first few frames and a reason, and the process exits nonzero when the count is greater than zero. On a counted frame, fin's values are a subset of tshark's. Fin may drop a value. It may not add one. Every differing line in the corpus is a counted frame. The tunnel list includes VXLAN 4789, GENEVE, GTP, Teredo, and the other places tshark finds an inner IP.

The file is mapped and split into chunks. Classic pcap: every core reads the 24-byte header, and chunk 0 starts at byte 24. pcapng: cores hop blocks in parallel, seams are proved from offset 0, setup blocks are merged in file order per section, then cores peel. A new section header resets interface ids. A packet uses the section that precedes it. A failed seam is rescanned with the sequential reader. That is slower, and it is still correct. Classic pcap resync steps one byte. pcapng resync steps 4 bytes and checks the length at both ends of a block. An 8-packet chain only exists to avoid fallbacks.

Header-only plans do not route. Stream plans send each chunk's TCP packets, as offset and length, to the owner of that direction-symmetric 5-tuple. Interface id and VLAN are not part of the key. The owner reads batches in chunk order, including a done mark for an empty batch. Both directions share an owner. Each direction has its own sequence buffer. Frame numbers are per-chunk counts, prefix-summed after the seams are proved. Rows merge in file order.

The index, Parquet export, and the desktop app consume rows later. They are not part of this reader.
