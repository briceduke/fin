---
id: 2026-10-21-desegment-truncated-handshake-after-a-complete-tls-record
kind: decision
date: 2026-10-21
---

## Context
tshark 4.6.9 `dissect_ssl` walks complete CCS, alert, app-data, and HelloRequest records, then desegments a following truncated handshake in the same TCP payload. fin's `truncated_handshake_need_known` returned None unless the payload started with a handshake record, so the completing segment was parsed as a new payload and left blank.

## Options
- Keep buffering only when the TCP payload starts with a handshake record
- Skip complete records and buffer a following truncated handshake, matching `dissect_ssl`

## Choice
A truncated handshake after a complete CCS, alert, app-data, or HelloRequest is buffered like tshark 4.6.9 dissect_ssl, and the completing segment prints SNI.

## Why
That is an in-order split of one TLS record. A ClientHello that starts the payload still desegments (`split-1`, `split-40`). GREASE after CCS is accepted once the prefix has stuck the session.
