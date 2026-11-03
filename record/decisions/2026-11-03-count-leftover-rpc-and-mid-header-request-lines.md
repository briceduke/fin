---
id: 2026-11-03-count-leftover-rpc-and-mid-header-request-lines
kind: decision
date: 2026-11-03
---

## Context
PR #21 counted leftover NOTIFY / no-colon / unreadable Content-Length / 1xx-204-304-with-CL after a complete HTTP message. Cursor review found two leftover paths that still return Message with total 0: RPC_IN_DATA / RPC_OUT_DATA / RPC_CONNECT (underscore fails looks_like_unproved_method) and a later message whose headers contain a request or status line (Take::Incomplete then desegment).

## Options
- Port tshark 4.6.9 RPC methods and treat a request or status line in headers as a new HTTP message
- Count those leftover paths as Partial after a complete message
- Leave the uncounted drops

## Choice
Leftover RPC_IN_DATA, RPC_OUT_DATA, RPC_CONNECT, and a later message whose headers contain a request or status line are counted.

## Why
A counted miss is allowed; an uncounted drop is not. GET then POST with a short Content-Length body still desegments. Solo mid-header GET stays Unproved.
