---
id: 2026-11-02-apply-content-length-on-1xx-204-304
kind: decision
date: 2026-11-02
---

## Context
tshark 4.6.9 dissect_http_message applies have_content_length && transfer_encoding == HTTP_TE_NONE to datalen as min(remaining, content_length) before the RFC no-body arm. That arm sets datalen = 0 for 1xx/204/304 only when there is no Content-Length. fin forced body_need = 0 for those statuses, so leftover after header end was the next HTTP message. A 204 with Content-Length 4 then GET / could print a Host tshark never emitted, or drop one tshark printed, with total 0.

## Options
- Keep body_need 0 for 1xx/204/304 and count leftover as unproved
- Apply Content-Length as min(remaining, CL) on 1xx/204/304, matching dissect_http_message, so leftover after those bytes is the next HTTP message
- Port every tshark no-body exception including HEAD and CONNECT 2xx

## Choice
A 1xx, 204, or 304 Content-Length still consumes min(remaining, CL) body bytes; leftover after those bytes is the next HTTP message.

## Why
The review showed an uncounted extra and an uncounted drop. Matching datalen keeps Host order when the next message starts after the CL body, and still prints Host when remaining is shorter than CL because tshark does not desegment those bodies.
