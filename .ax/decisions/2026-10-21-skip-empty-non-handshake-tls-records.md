---
id: 2026-10-21-skip-empty-non-handshake-tls-records
kind: decision
date: 2026-10-21
---

## Context
take_record treated a length-0 TLS record as terminal: handshake Unproved, anything else Done. handshake_tail already skipped empty records when buffering a truncated handshake, but parse_records never reached a following complete ClientHello in the same TCP payload. tshark 4.6.9 dissect_ssl3_record consumes a length-0 CCS/alert/app-data/heartbeat and continues. Empty handshake then a complete hello in the same payload stays a counted miss.

## Options
- Keep length-0 non-handshake records as Done, so a following ClientHello in the same payload is blank
- Skip a length-0 CCS, alert, app-data, or heartbeat and continue the record walk, matching dissect_ssl

## Choice
Skip a length-0 CCS, alert, app-data, or heartbeat record and keep walking, matching tshark 4.6.9 dissect_ssl.

## Why
Empty CCS/alert/app-data/heartbeat immediately followed by a complete 0x0301 or GREASE ClientHello must print SNI. Two empty CCS records then a hello must too. An empty handshake in the same payload is still Unproved. A following complete hello on the next payload already matched.
