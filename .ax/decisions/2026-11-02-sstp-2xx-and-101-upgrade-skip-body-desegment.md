---
id: 2026-11-02-sstp-2xx-and-101-upgrade-skip-body-desegment
kind: decision
date: 2026-11-02
---

## Context
tshark 4.6.9 dissect_http_message sets try_desegment_body = false for a 2xx to SSTP_DUPLEX_POST and for 1xx, so a 200 whose headers are complete is a complete response even with no Content-Length, a Content-Length larger than this segment, or Transfer-Encoding. That 200 sets next_handle to SSTP. A 101 with Upgrade does the same even when Transfer-Encoding is set. fin returned Unproved or Partial and never called note_http_switch, then printed a later Host tshark left blank.

## Options
- Keep treating those 200 and 101 frames as Unproved and count the later GET
- Treat complete headers as a complete switch for SSTP 2xx and 101 with Upgrade, matching try_desegment_body, and count later Hosts as an unwalked tunnel
- Port the SSTP and upgrade dissectors so later bytes match tshark exactly

## Choice
A 2xx to SSTP_DUPLEX_POST or a 101 with Upgrade whose headers are complete switches leftover Hosts to an unwalked tunnel, even with no body or Transfer-Encoding.

## Why
A counted miss is allowed; printing a Host tshark would not is not. CONNECT plus 200 still does not set next_handle. A 200 with FIN and Content-Length 0 already matched.
