---
id: 2026-11-02-truncate-jumbo-hop-dest-when-2-opt-len-overruns
kind: decision
date: 2026-11-02
---

## Context
Cursor review on PR #20: hop_dest returned Next after jumbo's 4-byte read when that read filled or passed this header, and never checked offset+2+opt_len against the captured payload. tshark 4.6.9 dissect_opts proto_tree_add_none_formats the option as 2+opt_len from the hop/dest tvb before dissect_opt_jumbo; that BoundsError skips ipv6_dissect_next. Live tshark 4.6.9 (v4.6.9-0-g2d548b197c75, empty WIRESHARK_CONFIG_DIR): Ethernet IPv6 hopopt/dstopts hdrlen 0, jumbo opt_len 255, jumbo opt_len 41 with this IPv4/UDP size, four Pad1 then jumbo opt_len 255, and five Pad1 then jumbo as the last header byte (length byte is IPv4 0x45) print a blank ip.src. Jumbo opt_len 4 as the first TLV of an 8-byte header still prints 10.9.9.9.

## Options
- Port each tshark 4.6.9 hop/dest option throw, including jumbo's 2+opt_len item
- Treat jumbo whose 2+opt_len overruns the captured payload the same way PadN already does, and keep leftover-after-jumbo counting

## Choice
A jumbo option whose 2 + opt_len overruns the captured payload is truncated like PadN.

## Why
This PR counts uncertain IPv6 option throws instead of matching each type. Jumbo is already special-cased because a valid 4-byte payload still walks next. PadN already returns Truncated when 2+opt_len overruns capture; applying that same bound before jumbo's 4-byte leftover check stops an inner ip.src tshark omitted, and jumbo opt_len 4 as the first TLV of an 8-byte header still walks.
