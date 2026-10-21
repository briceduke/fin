---
id: 2026-10-21-tls-heuristic-vs-named-port-record-rules
kind: decision
date: 2026-10-21
supersedes:
  - 2026-10-21-tls-record-versions-match-ssl-looks-like-sslv3
---

## Context

tshark 4.6.9's first-packet heuristic `is_sslv3_or_tls` is stricter than `ssl_looks_like_sslv3`. Unnamed ports that reused the named-port record walk printed SNI tshark left blank (CCS/alert/heartbeat prefix, record version 0x0304). After an authoritative SSLv3/TLS 1.0–1.2/TLCP record, tshark calls `dissect_ssl3_record` and still prints SNI from a later GREASE or draft ClientHello.

## Options

- Keep one record-version check for unnamed ports and TLS ports
- Match tshark: `is_sslv3_or_tls` on unnamed ports; `ssl_looks_like_sslv3` on a TLS port until a sticky version, then `dissect_ssl3_record`

## Choice

Unnamed ports use is_sslv3_or_tls; a TLS port uses ssl_looks_like_sslv3 until an authoritative SSLv3/TLS 1.0–1.2/TLCP record, then dissect_ssl3_record.

## Why

Those are the two tshark 4.6.9 gates. Sharing one check either invents SNI on an unnamed port or misses SNI after CCS on 443.
