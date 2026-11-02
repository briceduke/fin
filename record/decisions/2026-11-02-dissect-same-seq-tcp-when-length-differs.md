---
id: 2026-11-02-dissect-same-seq-tcp-when-length-differs
kind: decision
date: 2026-11-02
---

## Context
http_seen keyed only on the TCP 5-tuple and seq, so a later segment at that seq returned without counting. tshark 4.6.9 still dissects it when the length differs ([TCP Out-Of-Order]) and emits http.host. A same-length retransmission stays blank on the second frame.

## Options
- Keep skipping every later segment at a consumed seq
- Count same-seq later segments instead of printing Host
- Key http_seen on seq and payload length so a different length is dissected and a same-length retransmission stays blank

## Choice
A later TCP segment at a consumed seq is dissected when its length differs, and skipped without counting when the length matches.

## Why
A differing row that is not counted is a defect. Same-seq longer GETs and a full request after a 20-byte partial at seq 1 must print Host. Split headers on increasing seq still count.
