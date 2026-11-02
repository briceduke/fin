---
id: 2026-11-02-count-leftover-hop-dest-tlvs-after-jumbo
kind: decision
date: 2026-11-02
---

## Context
Cursor review on PR #20: hop_dest returned Next on jumbo (0xc2) and walked inner ip.src after leftover TLVs in the same hop-by-hop or dest-options header. tshark 4.6.9 still walks those leftovers; a throwing CALIPSO skips ipv6_dissect_next. Jumbo as the first TLV of an 8-byte header is consumed by tshark's 4-byte jumbo read.

## Options
- Port tshark 4.6.9 per-option leftover throws (CALIPSO, APN6, TEL, router-alert)
- Count any leftover TLV bytes after jumbo's 4-byte read in the same header, and keep walking when that read fills the header

## Choice
Leftover TLVs after a jumbo 4-byte read in the same hop/dest header are counted; jumbo that fills the header still walks next.

## Why
This PR counts uncertain IPv6 option throws instead of matching each type. Widening the leftover-after-jumbo set avoids printing an inner ip.src tshark omitted. The 8-byte first-TLV jumbo path stays proved because tshark's 4-byte read consumes that leftover.
