---
id: 2026-10-21-skip-empty-tls-records-when-desegmenting
kind: decision
date: 2026-10-21
---

## Context
tshark 4.6.9 dissect_ssl consumes a length-0 record (empty handshake, CCS, alert, or app-data) and continues. truncated_handshake_need_known returned None on length 0, so a following truncated ClientHello was not buffered and the completing segment printed a blank instead of SNI.

## Options
- Keep treating a length-0 record as the end of the TLS walk
- Skip empty records the way dissect_ssl does, and buffer a following truncated handshake

## Choice
Skip length-0 TLS records when looking for a truncated handshake, matching tshark 4.6.9 dissect_ssl.

## Why
Empty handshake, CCS, alert, and app-data prefixes with a split ClientHello must print SNI on the completing segment. A following complete ClientHello on the next payload still matches because an empty record alone is not buffered.
