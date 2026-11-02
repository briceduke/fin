---
id: 2026-11-02-http-2-preface-sticks-named-http
kind: decision
date: 2026-11-02
---

## Context
`HttpParse::Other` counted a named-`http` payload and did not mark the TCP conversation. tshark 4.6.9 HTTP/2 heuristic claims the preface `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` and the 16-byte `PRI * HTTP/2.0\r\n\r\n` prefix; later segments on that conversation are HTTP/2, so `http.host` is blank. Heuristic ports already stick (`http-heuristic`); named `http` ports did not, so a later GET printed Host.

## Options
- Port HTTP/2 dissection and keep http.host blank on that conversation
- Stick the TCP conversation when a named http payload is an HTTP/2 preface, and count later Hosts
- Count only the preface frame and keep dissecting later segments as HTTP/1.x

## Choice
An HTTP/2 preface on a named http TCP port sticks that conversation so later Hosts are counted, not printed.

## Why
HTTP/2 is counted, not proved. Printing inner.example after Magic is a defect. Opposite-direction GET and a 16-byte prefix without SM have the same extra; same-segment leftover GET after the full preface already stays blank.
