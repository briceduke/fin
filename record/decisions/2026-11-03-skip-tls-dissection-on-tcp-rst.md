---
id: 2026-11-03-skip-tls-dissection-on-tcp-rst
kind: decision
date: 2026-11-03
---

## Context
HTTP already skips RST payload because tshark 4.6.9 never hands it to dissect_tcp_payload. TLS still parsed a complete ClientHello on RST and would print SNI tshark omitted.

## Options
- Keep parsing TLS on RST
- Count RST ClientHellos
- Skip TLS on RST, matching tshark 4.6.9

## Choice
TCP RST payload is not TLS, matching tshark 4.6.9 dissect_tcp_payload.

## Why
tshark 4.6.9 prints no tls.handshake.extensions_server_name on RST, RST+ACK, or RST+PSH+ACK. Skipping is cheap to prove and matches HTTP.
