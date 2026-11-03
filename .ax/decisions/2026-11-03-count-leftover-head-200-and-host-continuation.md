---
id: 2026-11-03-count-leftover-head-200-and-host-continuation
kind: decision
date: 2026-11-03
---

## Context
PR #21 counted leftover NOTIFY / no-colon / unreadable Content-Length / 1xx-204-304-with-CL / RPC_* / mid-header request lines after a complete HTTP message. Cursor review found two leftover paths that still return Message with total 0: HEAD then a 200 whose body this reader does not complete (Take::Incomplete after complete, including GET then that HEAD+200, HEAD with no Host, dest 8080, IPv6), and leftover that starts with a header (looks_like_unproved_method rejects colon, so Host: / X-Foo: / FOO:BAR are Take::Other).

## Options
- Port tshark 4.6.9 HEAD-response no-body and continuation-header reassembly so those Hosts print
- Count those leftover paths as Partial after a complete message
- Leave the uncounted drops

## Choice
After a complete HEAD, an incomplete later 200 is counted, and leftover that starts with a header is counted.

## Why
A counted miss is allowed; an uncounted drop is not. Porting HEAD no-body would print leftover GET Hosts tshark treats as Continuation. GET then POST with a short Content-Length body still desegments. HEAD then 200 Content-Length 0 leftover GET still prints every Host. Leftover junk with no colon still prints.
