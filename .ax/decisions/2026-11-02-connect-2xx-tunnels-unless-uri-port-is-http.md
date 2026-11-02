---
id: 2026-11-02-connect-2xx-tunnels-unless-uri-port-is-http
kind: decision
date: 2026-11-02
---

## Context
tshark 4.6.9 dissect_http_tcp calls http_conversation_is_connect after CONNECT whose response_code is 200-299 and hands later segments to http_payload_subdissector using the URI port. When that tcp.port name is not HTTP, http.host is blank. fin printed a later GET Host on CONNECT example.com:22 (and 21/23/25/53/110/143/587/1194/1883/3306/5060/5432/5900/6379), a URI with no port, and 201, with total 0. :443/:80/:8080/:465/:993/:995 later GET still prints on both. Same-segment leftover GET on the 2xx frame still prints on both.

## Options
- Port decode_tcp_ports for every CONNECT URI port so later Hosts match tshark
- After CONNECT plus 2xx, count later Hosts as an unwalked tunnel unless the URI port's tcp.port name is http or tls, and keep leftover on the 2xx frame as HTTP
- Keep printing later Hosts after every CONNECT 2xx

## Choice
After CONNECT plus 2xx, later Hosts are counted http-tunnel unless the URI port's tcp.port name is http or tls.

## Why
v1 does not walk ssh, ftp, or other CONNECT payload dissectors. A counted miss is allowed; printing a Host tshark would not is not. http and tls URI ports still print a later GET because tshark's HTTP dissector or TLS-then-HTTP heuristic does. Same-segment leftover on the 2xx frame is still HTTP because http_conversation_is_connect runs at the start of a later dissect_http_tcp.
