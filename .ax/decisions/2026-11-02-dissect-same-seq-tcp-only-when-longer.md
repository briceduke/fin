---
id: 2026-11-02-dissect-same-seq-tcp-only-when-longer
kind: decision
date: 2026-11-02
supersedes:
  - 2026-11-02-dissect-same-seq-tcp-when-length-differs
---

## Context
http_seen keyed on seq and payload length, so a later shorter segment at that seq was dissected. tshark 4.6.9 treats a shorter same-seq segment as [TCP Retransmission] and does not emit http.host. A longer same-seq GET is [TCP Out-Of-Order] and still prints. Same-length retransmission already stayed blank.

## Options
- Keep dissecting every later segment whose length differs
- Skip every later segment at a consumed seq
- Dissect only when the later segment is longer; skip shorter or equal length without counting

## Choice
A later TCP segment at a consumed seq is dissected only when it is longer; a shorter or equal length is a retransmission with no Host.

## Why
Printing Host on a shorter same-seq GET is an add. Same-seq longer GETs and a full request after a 20-byte partial at seq 1 must still print.
