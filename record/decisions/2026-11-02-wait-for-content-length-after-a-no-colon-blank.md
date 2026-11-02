---
id: 2026-11-02-wait-for-content-length-after-a-no-colon-blank
kind: decision
date: 2026-11-02
---

## Context
`has_blank_line` after a no-colon header line treated any later blank as enough to prove Host, then applied Content-Length from the junk line. tshark 4.6.9 `req_resp_hdrs_do_reassembly` uses that later blank as the header terminator and, when `try_desegment_body` is true, still waits for Content-Length bytes after it. Until those bytes exist, Host is not emitted. Live tshark 4.6.9 (`v4.6.9-0-g2d548b197c75`, empty `WIRESHARK_CONFIG_DIR`): `HTTP/1.1 200 OK` plus `Content-Length: 4` plus `not-a-header` then `xxxxGET` leftover printed a blank Host; fin printed `a.example`. Same extra without the pad, and for `201` / `302` / `404` / `206`, and for `POST` / `GET` with `Content-Length: 4`. A blank immediately after the junk line then four body bytes still matches (both first Host, Info Continuation). `204` / `304` / TCP FIN still match because `try_desegment_body` is false. The original leftover GET after `not-a-header\r\n\r\n` (no Content-Length wait) still matches.

## Options
- Count every no-colon frame that also has Content-Length
- Wait for Content-Length bytes after the later blank when body desegment is on, otherwise prove Host as before
- Keep proving Host from the junk line once any later blank exists

## Choice
A no-colon HTTP header line proves Host only when a later blank exists and, if body desegment is on, Content-Length bytes follow that blank.

## Why
A counted miss is allowed; printing a.example when tshark prints a blank is not. Reassembly looks for a blank, then for Content-Length bytes after it. Dissection still breaks with offset on the junk line, so leftover there stays Continuation. 204, 304, and TCP FIN skip body desegment, so they still print the first Host.
