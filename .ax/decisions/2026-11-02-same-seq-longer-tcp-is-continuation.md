---
id: 2026-11-02-same-seq-longer-tcp-is-continuation
kind: decision
date: 2026-11-02
supersedes:
  - 2026-11-02-dissect-same-seq-tcp-only-when-longer
---

## Context
http_seen dissected a later longer segment at a consumed seq, matching an older reading of tshark 4.6.9 `[TCP Out-Of-Order]`. Live tshark 4.6.9 with empty `WIRESHARK_CONFIG_DIR` and `-o tcp.reassemble_out_of_order:TRUE` hands that overlap to HTTP as Continuation and does not emit `http.host`. Ethernet IPv4 TCP `50000→80`, PSH+ACK, seq 1: `GET / HTTP/1.1\r\nHost: a.example\r\n\r\n` (35 bytes) then the same 5-tuple and seq `GET / HTTP/1.1\r\nHost: inner.example\r\n\r\n` (39 bytes) prints `a.example` then empty. The same extra happened after SYN/SYN-ACK/ACK. A 20-byte partial then the full request at seq 1 still prints on the completing segment. Shorter or equal retransmits stay blank.

## Options
- Keep dissecting a later longer segment at a consumed seq
- Count a later longer segment instead of printing Host
- Skip a later longer segment at a seq that already completed HTTP, and still dissect a still-open partial at that seq

## Choice
A later longer TCP segment at a consumed seq is Continuation with no Host; only a still-open partial at that seq is dissected.

## Why
Printing Host on that overlap is an uncounted add versus the claimed tshark 4.6.9 path. Skipping without counting matches Continuation. A still-open 20-byte prefix then the full request at seq 1 must still print.
