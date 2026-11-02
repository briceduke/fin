---
id: 2026-11-02-count-same-segment-leftover-after-101-sstp-as-a-tunnel
kind: decision
date: 2026-11-02
---

## Context
tshark 4.6.9 dissect_http_on_stream sets startframe/startoffset after a complete 101 with Upgrade or SSTP_DUPLEX_POST plus 200 and hands leftover in that same segment to next_handle or data. fin still walked that leftover as HTTP and printed a later Host on the switching frame, an uncounted extra. Later frames on those conversations were already counted http-tunnel. CONNECT plus 200 leftover still prints on both.

## Options
- Port next_handle so leftover Hosts match tshark exactly
- Drop leftover Hosts after a complete 101 with Upgrade or SSTP 200 in the same segment and count the leftover as an unwalked tunnel
- Keep printing leftover Hosts

## Choice
Leftover bytes in the same TCP segment after a complete 101 with Upgrade or SSTP_DUPLEX_POST plus 200 are counted as an unwalked tunnel.

## Why
v1 does not walk SSTP or the HTTP upgrade dissector. A counted miss is allowed; printing a Host tshark would not is not. CONNECT plus 200 stays HTTP.
