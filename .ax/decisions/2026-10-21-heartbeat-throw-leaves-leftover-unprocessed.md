---
id: 2026-10-21-heartbeat-throw-leaves-leftover-unprocessed
kind: decision
date: 2026-10-21
---

## Context
record_tail special-cased a length-0 heartbeat leftover shorter than 3 bytes. tshark 4.6.9 dissect_ssl3_heartbeat always reads type plus payload_length, then for Request or Response on a record shorter than 3 bytes adds a payload of record_length-3 and throws. Length 1 or 2 plus leftover 00 still desegmented, so the next ClientHello was swallowed. TLS 1.3 skips that dissector, so leftover after an empty heartbeat is desegmented.

## Options
- Special-case heartbeat records of length 1 and 2
- Walk dissect_ssl3_heartbeat: throw when the 3-byte header is missing or a valid type would add a payload past a record shorter than 3 bytes, and skip on TLS 1.3

## Choice
A heartbeat whose tshark 4.6.9 dissector throws leaves leftover unprocessed, matching dissect_ssl3_heartbeat.

## Why
tvb_get_uint8 plus tvb_get_ntohs always run. Request (1) and Response (2) then decode payload; record_length-3 underflows when the record is shorter than 3. Invalid type leftover of 3 bytes does not throw. TLS 1.3 never enters the heartbeat dissector. Handshake leftover after empty ServerHello, short ServerHello, leftover 1-4, 0x0301, and Hello Request then empty ServerHello already matched at 67d2647.
