---
id: 2026-11-02-skip-http-dissection-on-tcp-rst
kind: decision
date: 2026-11-02
---

## Context
tcp always handed a non-empty payload to http_from_tcp. tshark 4.6.9 does not dissect HTTP when TH_RST is set, even with a complete GET in the payload, so http.host is blank. Fin printed the Host, an uncounted add.

## Options
- Dissect HTTP on RST and count the frame
- Skip HTTP when TH_RST is set, matching tshark 4.6.9
- Skip HTTP on RST, FIN, and SYN

## Choice
TCP RST skips HTTP dissection, matching tshark 4.6.9, even when the payload is a complete GET.

## Why
PSH+ACK, ACK, FIN, SYN, and SYN+ACK with that same payload still print Host on both. FIN+RST and SYN+RST skip like RST.
