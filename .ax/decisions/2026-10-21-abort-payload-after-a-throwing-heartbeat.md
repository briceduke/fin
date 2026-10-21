---
id: 2026-10-21-abort-payload-after-a-throwing-heartbeat
kind: decision
date: 2026-10-21
---

## Context
parse_records kept walking after a complete heartbeat of length 1 or 2. tshark 4.6.9 dissect_ssl3_heartbeat THROW(ReportedBoundsError)s and aborts dissect_ssl, so a following ClientHello in the same payload is not printed. record_tail already left leftover unprocessed at d9c0c70. Length-0 heartbeat then a hello in the same payload still continues.

## Options
- Special-case heartbeat records of length 1 and 2 in parse_records
- Abort parse_records when heartbeat_throws or handshake_throws, matching dissect_ssl abort

## Choice
A heartbeat whose tshark 4.6.9 dissector throws aborts the rest of that payload, matching dissect_ssl.

## Why
dissect_ssl3_heartbeat reads type plus payload_length from the parent tvb and throws on Request/Response when the record is shorter than 3 bytes. THROW aborts dissect_ssl, so later records in this TCP payload are not walked. Length 0 still continues. Length 3 and TLS 1.3 still continue. Empty ServerHello leftover satisfies the parent read, so a following hello in the same payload still prints.
