---
id: 2026-10-21-tls-version-sticks-on-the-tcp-conversation
kind: decision
date: 2026-10-21
---

## Context

tshark 4.6.9 keeps `SslSession.version` on the TCP conversation. fin keyed `tls_known` and `tls_claimed` by directed 4-tuple, so a server CCS, alert, app-data, or ServerHello did not unlock the client's next GREASE ClientHello. That miss happened on port 443 and on the unnamed-port heuristic once the peer had claimed TLS.

## Options

- Keep TLS version and claim per TCP direction
- Key `tls_known` and `tls_claimed` by the TCP conversation, both directions, matching tshark

## Choice

tls_known and tls_claimed are keyed by the TCP conversation, both directions, matching tshark 4.6.9 SslSession.

## Why

A directed key blanks the client's GREASE hello after a server-first authoritative record. Reassembly (`tls_need`, `tls_seen`) stays per direction because TCP sequence is one-way.
