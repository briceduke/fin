---
id: 2026-10-21-desegment-any-incomplete-tls-record
kind: decision
date: 2026-10-21
---

## Context
record_tail (was handshake_tail) only buffered a truncated handshake. tshark 4.6.9 dissect_ssl3_record desegments any incomplete record (CCS/alert/app-data/heartbeat) from desegment_offset. A CCS split across two TCP segments never stuck the session, so a later GREASE or 0x0301 ClientHello was left blank without a count.

## Options
- Keep buffering only truncated handshake records
- Desegment any incomplete TLS record the way dissect_ssl3_record does

## Choice
Desegment any incomplete TLS record, not only handshake, matching tshark 4.6.9 dissect_ssl3_record.

## Why
A CCS, alert, or app-data prefix split across segments must stick the session so a later ClientHello prints SNI. A complete CCS then a split ClientHello already matched. Follow dissect_ssl rather than special-casing each content type.
