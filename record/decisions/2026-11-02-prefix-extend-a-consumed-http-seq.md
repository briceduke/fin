---
id: 2026-11-02-prefix-extend-a-consumed-http-seq
kind: decision
date: 2026-11-02
supersedes:
  - 2026-11-02-same-seq-longer-tcp-is-continuation
---

## Context
http_seen keyed on exact TCP seq and skipped a later longer segment once that seq had completed HTTP. Live tshark 4.6.9 with empty WIRESHARK_CONFIG_DIR and `-o tcp.reassemble_out_of_order:TRUE` treats a *replacement* (35-byte `a.example` then 39-byte `inner.example` at seq 1) as Continuation, but a *prefix extension* (first payload plus more bytes) hands the new suffix to HTTP. A later seq that overlaps already-walked bytes is Continuation. A still-open prefix at that seq still completes.

## Options
- Keep skipping every later longer segment at a consumed seq
- Count overlapping, prefix-extending, and open-partial later segments instead of printing Host
- Track nxtseq per TCP direction: prefix-extend dissects the suffix, replacement and overlapping later seq stay Continuation, and an open prefix at that seq still completes

## Choice
A later TCP segment that prefix-extends a consumed seq is a new HTTP message; a replacement or overlapping later seq is Continuation; an open prefix at that seq still completes.

## Why
Printing Host on a replacement or overlapping later seq is an uncounted add. Skipping a prefix extension without counting drops a Host tshark prints. Completing a 20-byte GET prefix at seq 1 must still print. Live tshark vs Ethernet IPv4 TCP 50000→80 PSH+ACK.
