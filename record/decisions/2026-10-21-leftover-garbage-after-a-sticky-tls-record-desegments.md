---
id: 2026-10-21-leftover-garbage-after-a-sticky-tls-record-desegments
kind: decision
date: 2026-10-21
---

## Context
A length-0 CCS/alert/app-data plus leftover `00`/`01`/`ff` (or a complete CCS plus leftover `00`) made ssl_try_set_version stick, then the next in-order ClientHello printed SNI. tshark 4.6.9 dissect_ssl desegments remaining < 5 after a sticky version even when leftover is not a content type, so the next TCP segment is Ignored Unknown Record.

## Options
- Stop sticking the session whenever leftover is not a content type
- Desegment leftover shorter than a record header after a sticky session, matching dissect_ssl, including leftover that is not a content type

## Choice
A sticky TLS session desegments leftover shorter than a record header even when that leftover is not a content type.

## Why
tshark 4.6.9 reads next_byte (session sticks) then, in dissect_ssl's SSLv3/TLS 1.0–1.2 arm, remaining < 5 sets DESEGMENT_ONE_MORE_SEGMENT. Leftover 00 plus GREASE or 0x0301 becomes Ignored Unknown Record. Leftover that is a valid content type already desegmented. A complete following record still prints. Empty heartbeat leftover under 3 bytes still throws in dissect_ssl3_heartbeat, so that leftover stays unprocessed.
