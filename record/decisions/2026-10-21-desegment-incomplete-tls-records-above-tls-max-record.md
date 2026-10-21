---
id: 2026-10-21-desegment-incomplete-tls-records-above-tls-max-record
kind: decision
date: 2026-10-21
---

## Context
record_tail returned None when a TLS record's u16 length was >= TLS_MAX_RECORD (18432). take_record treated that header as terminal. tshark 4.6.9 dissect_ssl3_record desegments any incomplete record after a valid content type, before ssl_check_record_length. A CCS/alert/app-data/heartbeat/handshake of length 18432–65535 with one body byte then an in-order Hello Request plus ClientHello printed SNI on frame 2; tshark's frame 2 Info is TCP only.

## Options
- Keep refusing to desegment records whose u16 length is >= TLS_MAX_RECORD
- Desegment any incomplete TLS record, including u16 length 18432–65535, matching dissect_ssl3_record

## Choice
Desegment an incomplete TLS record even when its u16 length is 18432–65535, matching tshark 4.6.9 dissect_ssl3_record.

## Why
dissect_ssl3_record compares available_bytes to record_length+5 with no TLS_MAX_RECORD gate. ssl_check_record_length runs only after the full record is assembled. Length 18431 already desegmented; 18432 and 65535 must too, on source and dest 443, for CCS, alert, app-data, heartbeat, and handshake.
