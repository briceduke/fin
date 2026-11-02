---
id: 2026-11-02-parse-content-length-like-tshark-g-ascii-strtoll
kind: decision
date: 2026-11-02
---

## Context
tshark 4.6.9 HDR_CONTENT_LENGTH is g_ascii_strtoll on the ENC_ASCII C string. Leading g_ascii_isspace including VT and FF is skipped; after the digits, NUL or g_ascii_isspace is accepted. fin only skipped SP/HTAB and treated trailing NUL or FF as an invalid length, so a request with Content-Length 4 and no body printed Host instead of desegmenting.

## Options
- Match g_ascii_strtoll and the C-string NUL stop exactly
- Count every Content-Length with VT, FF, or NUL as unproved
- Keep the SP/HTAB-only parser

## Choice
Content-Length is g_ascii_strtoll on an ENC_ASCII C string: leading g_ascii_isspace is skipped, and trailing NUL or g_ascii_isspace is accepted.

## Why
A failed parse is body 0 on a request, so Host is proved. Matching tshark on the four-byte length is what keeps fin from printing a Host tshark would blank.
