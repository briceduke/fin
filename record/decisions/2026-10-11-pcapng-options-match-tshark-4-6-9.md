---
id: 2026-10-11-pcapng-options-match-tshark-4-6-9
kind: decision
date: 2026-10-11
---

## Context

Cursor review on PR #3 found six more tshark 4.6.9 mismatches in pcapng option and fault handling: exact lengths for if_tsresol and if_tsoffset, option-area overrun, if_filter length 0, signed time_t wrap, and exit 3 vs 14. Two earlier rounds patched the same class case by case.

## Options

- Keep adding one-off length checks per review comment
- Port tshark 4.6.9 pcapng.c option processing as one table, and decide exit 3 vs 14 from whether a packet block has been reached

## Choice

Pcapng options follow tshark 4.6.9 pcapng.c, and a fault exits 3 before any packet block and 14 after.

## Why

tshark stores uint8 and int64 options only at exact length, fails overrun and if_filter length 0, and adds if_tsoffset with wrapping signed time_t. Exit 3 is an open-time stop (no packet block yet); 14 is any stop after a packet block is reached, even if that packet was not printed. UnsupportedLinkType stays 1. A harness differential fuzz against tshark 4.6.9 is the check; the reader does not link the harness.
