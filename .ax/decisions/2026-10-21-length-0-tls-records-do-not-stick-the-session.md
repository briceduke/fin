---
id: 2026-10-21-length-0-tls-records-do-not-stick-the-session
kind: decision
date: 2026-10-21
---

## Context
A length-0 CCS, alert, app-data, or heartbeat is Record::Other so parse_records can continue, but that arm still called apply_session_version. tshark 4.6.9 dissect_ssl3_record reads the first body byte before ssl_try_set_version. When the empty record is the whole TCP payload, that read throws (Info [Malformed Packet]) and the session stays unknown, so a GREASE ClientHello on the next payload is continuation data. Fin printed the name. Empty then a 0x0301 hello on the next payload, empty then GREASE in the same payload, and a complete CCS then GREASE still match tshark.

## Options
- Skip apply_session_version for every length-0 Other record, and invent another way to accept in-record GREASE
- Skip apply_session_version only when the length-0 record ends the payload, matching the body-byte read

## Choice
A length-0 CCS, alert, app-data, or heartbeat sticks the TLS session only when a later byte in the same payload is readable.

## Why
That is tshark 4.6.9 ssl_try_set_version: an empty record as the whole payload does not stick, so a later GREASE ClientHello stays blank in both directions. A following byte in this payload is readable, so empty then GREASE in the same record still prints. Empty then a 0x0301 hello and a complete CCS then GREASE still print.
