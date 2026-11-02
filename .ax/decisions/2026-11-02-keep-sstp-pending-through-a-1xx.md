---
id: 2026-11-02-keep-sstp-pending-through-a-1xx
kind: decision
date: 2026-11-02
---

## Context
tshark 4.6.9 push_res reuses the same http_req_res_t after a 1xx (response_code < 200), so curr->request_method stays SSTP_DUPLEX_POST and a later 200 still sets next_handle to SSTP. fin cleared http_sstp on every has_response, including 1xx, and then printed a later GET Host that tshark left blank.

## Options
- Keep clearing pending SSTP_DUPLEX_POST on every complete response, including 1xx
- Keep pending SSTP_DUPLEX_POST through a 1xx, and only clear it on status >= 200, matching push_res
- Port the SSTP dissector so later Hosts match tshark exactly

## Choice
A 1xx does not clear a pending SSTP_DUPLEX_POST, so a later 200 still switches leftover Hosts to an unwalked tunnel.

## Why
A counted miss is allowed; printing a Host tshark would not is not. Same-segment 100+200 leftover, a 201/203/204 then 200 then GET, and CONNECT plus 200 stay as they were.
