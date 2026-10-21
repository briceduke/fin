---
id: 2026-10-21-desegment-leftover-shorter-than-a-tls-record-header
kind: decision
date: 2026-10-21
supersedes:
  - 2026-10-21-leftover-garbage-after-a-sticky-tls-record-desegments
---

## Context
record_tail buffered leftover shorter than 5 bytes only when rest[0] was content type 20–26 or the session was already sticky. tshark 4.6.9 dissect_ssl desegments remaining < 5 in the SSL_VER_UNKNOWN default arm before any content-type check, so a TLS-port one-byte 00 then an in-order ClientHello is Continuation Data.

## Options
- Keep the content-type or sticky gate and special-case leftover 00
- Desegment any leftover shorter than a record header once dissect_ssl ran, matching the remaining < 5 check in both arms

## Choice
A claimed TLS conversation desegments leftover shorter than a record header even when the session is unknown and leftover is not a content type.

## Why
tshark 4.6.9 dissect_ssl hits remaining < 5 before ssl_looks_like_sslv3, on TLS ports and already-claimed conversations. Heuristic TLS on an unnamed unclaimed port never entered dissect_ssl, so leftover 00 there is still a new ClientHello. Sticky leftover after CCS/alert/app and empty-HS-then-CCS then GREASE still match.
