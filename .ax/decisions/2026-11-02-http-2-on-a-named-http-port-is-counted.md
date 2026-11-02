---
id: 2026-11-02-http-2-on-a-named-http-port-is-counted
kind: decision
date: 2026-11-02
supersedes:
  - 2026-11-02-http-2-preface-sticks-named-http
---

## Context
tshark 4.6.9 `dissect_http2_heur_http` claims `kMagicHello` on the 16-byte first line `PRI * HTTP/2.0\r\n`, after one leading CRLF, and on leftover after a complete HTTP/1.x message including leftover treated as body. fin matched only an 18-byte payload-start prefix, so later Hosts printed.

## Options
- Port HTTP/2 dissection and keep http.host blank on that conversation
- Count HTTP/2 on a named http port whenever that 16-byte first line appears at payload start or in leftover, and stop printing later Hosts
- Count only the preface frame and keep dissecting later segments as HTTP/1.x

## Choice
HTTP/2 on a named http port is counted, not proved.

## Why
Printing a later Host is an add. A 16-byte first line, a leading CRLF, leftover after GET/POST/204/NOTIFY, and IPv6/VLAN/src 80/8080 all extra inner.example. Payload-start 24-byte magic still matches.
