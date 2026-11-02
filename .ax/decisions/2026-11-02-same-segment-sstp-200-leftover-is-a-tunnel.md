---
id: 2026-11-02-same-segment-sstp-200-leftover-is-a-tunnel
kind: decision
date: 2026-11-02
---

## Context
tshark 4.6.9 dissect_http_on_stream switches after a complete SSTP_DUPLEX_POST plus 200, including when that request and 200 share one TCP segment, and hands leftover to next_handle. fin only treated a 200 as SSTP when http_sstp already held the conversation from a previous frame, because sstp_duplex_post was inserted after the contains check. A payload with the SSTP request, the 200, and a later GET printed after.example with total 0.

## Options
- Port the SSTP dissector so leftover Hosts match tshark
- Insert SSTP_DUPLEX_POST before the 200 check so same-segment leftover is counted as an unwalked tunnel
- Keep printing leftover Hosts on the switching frame

## Choice
SSTP_DUPLEX_POST plus 200 in the same TCP segment switches leftover to an unwalked tunnel.

## Why
v1 does not walk SSTP. A counted miss is allowed; printing a Host tshark would not is not. Two-frame SSTP then reverse 200, and CONNECT plus 200 leftover, stay as they were.
