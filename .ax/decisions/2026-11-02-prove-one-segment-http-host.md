---
id: 2026-11-02-prove-one-segment-http-host
kind: decision
date: 2026-11-02
---

## Context
Build order step 6 is the first HTTP field, `http.host`, pinned to tshark 4.6.9 with an empty WIRESHARK_CONFIG_DIR. The TLS SNI work already showed that porting every tshark throw and desegment path is an unbounded tail. HTTP has the same shape: header/body desegment, chunked Transfer-Encoding, heuristic ports, HTTP/2, HTTP over TLS, and tunnels such as sFlow.

## Options
- Port tshark 4.6.9 HTTP reassembly, chunked bodies, heuristic conversations, HTTP/2, and TLS decryption case by case until stdout matches on every frame
- Prove `http.host` only for a complete HTTP/1.x message whose headers and body fit in one TCP segment on a snapshotted `http` port, and count every frame whose Host fin cannot prove

## Choice
A one-segment HTTP/1.x message on a snapshotted http TCP port prints http.host; split, TE, heuristic, HTTP/2, HTTP-over-TLS, and unwalked tunnels are counted.

## Why
The two correctness rules already allow a counted miss. One-segment Host on the snapshotted TCP port table is the path tshark 4.6.9 emits without desegment_headers or desegment_body. Everything else is a subset if we print nothing and name the frame.
