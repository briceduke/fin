---
id: 2026-11-02-a-no-colon-http-header-line-is-leftover
kind: decision
date: 2026-11-02
---

## Context
A complete header line with no colon set `ignore_headers` and kept walking until a blank line, then leftover was the next HTTP message. tshark 4.6.9 `dissect_http_message` `break`s when `memchr` finds no colon; offset stays on that line. For a request, `datalen` is 0, so leftover starting at the junk line is Continuation (Info `GET / HTTP/1.1 Continuation`). Printing Host from that leftover is an uncounted extra. Live tshark 4.6.9 (`v4.6.9-0-g2d548b197c75`, empty `WIRESHARK_CONFIG_DIR`): `GET` plus `not-a-header` then a pipelined GET prints only `a.example`. Same extra for obs-fold, tab-fold, a space-only line, `X-Foo` with no colon, POST `Content-Length: 0`, `204`, `200` CL 0, two junk lines, src 80, and port 8080. `http.desegment_headers` still needs a later blank line; without one, Host is not emitted. A later *frame* GET after junk-only headers still prints on both. NOTIFY leftover junk is body on both. `:value` and `Foo Bar: x` have a colon and still pipeline.

## Options
- Keep walking to a blank line after a no-colon line and parse leftover as the next HTTP message
- Break the header loop with offset on the no-colon line, prove Host only when a later blank line is present, and treat leftover starting there as Continuation
- Count every frame whose headers contain a no-colon line

## Choice
A complete HTTP header line with no colon breaks the header loop with offset on that line, so leftover is Continuation, not a new message.

## Why
A counted miss is allowed; printing inner.example when tshark prints only a.example is not. tshark 4.6.9 `req_resp_hdrs_do_reassembly` still waits for a blank line, so a junk line with no following blank stays Unproved. A colon continues the header walk, so `:value` and `Foo Bar: x` leftover still print both names.
