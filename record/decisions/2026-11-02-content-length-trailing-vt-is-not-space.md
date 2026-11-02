---
id: 2026-11-02-content-length-trailing-vt-is-not-space
kind: decision
date: 2026-11-02
supersedes:
  - 2026-11-02-parse-content-length-like-tshark-g-ascii-strtoll
---

## Context
`ascii_isspace` treated VT `0x0b` as trailing Content-Length whitespace, so `4\x0b` was length 4 and leftover after those four body bytes was the next HTTP message. tshark 4.6.9 `HDR_CONTENT_LENGTH` is `g_ascii_strtoll` then `*end != '\0' && !g_ascii_isspace(*end)`. On this tshark 4.6.9 (`v4.6.9-0-g2d548b197c75`) GLib 2.80, `g_ascii_isspace(0x0b)` is false, so the length is invalid, a request has body 0, and leftover starting `xxxxGET` is Continuation. Live check: `Content-Length: 4\x0b` then four bytes plus a leftover GET printed `cl.example` on tshark and `cl.example,inner.example` on fin. A byte sweep 0–255 after the digits (CR/LF omitted) found only `0x0b`. Trailing FF, TAB, SP, and NUL still pipeline on both. Leading VT `\x0b4` with a four-byte body still matches because `g_ascii_strtoll` still skips leading VT.

## Options
- Keep treating VT as `g_ascii_isspace` for both leading and trailing
- Match GLib 2.80 `g_ascii_isspace` for trailing (no VT) while still skipping leading VT like `g_ascii_strtoll`
- Count every Content-Length with a trailing VT

## Choice
Trailing Content-Length whitespace matches GLib 2.80 g_ascii_isspace, which rejects VT, while g_ascii_strtoll still skips leading VT.

## Why
Printing inner.example when tshark prints only cl.example is a defect. Invalid length is body 0 on a request, so leftover starting at xxxxGET is Continuation and Host is still proved. Leading VT with a four-byte body must keep parsing as 4.
