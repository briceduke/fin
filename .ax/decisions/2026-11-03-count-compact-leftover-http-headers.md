---
id: 2026-11-03-count-compact-leftover-http-headers
kind: decision
date: 2026-11-03
---

## Context
PR #21 counted leftover that starts with a header when the first leftover line has an ASCII space (`Host: n.example`). Cursor review found compact leftover (`Host:n.example`, `Host:\tn.example`, `X-Foo:bar`, `FOO:BAR`, `Content-Length:4` then body then GET, OPTIONS / POST CL 0 / 204 / HEAD then compact Host, a first GET with no Host) still returns Message with total 0: `looks_like_unproved_method` requires `method.len() < line.len()` after splitting on space, so those lines are Take::Other. Decision `2026-11-03-count-leftover-head-200-and-host-continuation` already said leftover that starts with a header is counted; the space check left compact Name:value uncounted.

## Options
- Port tshark 4.6.9 continuation-header reassembly so those Hosts print
- Widen looks_like_unproved_method so a leftover line that starts with a valid header name and colon is Unproved
- Leave the uncounted drops

## Choice
Compact leftover headers with no ASCII space are counted after a complete HTTP message.

## Why
A counted miss is allowed; an uncounted drop is not. Spaced leftover Host already counts. Leftover junk / not-a-header with no colon still prints.
