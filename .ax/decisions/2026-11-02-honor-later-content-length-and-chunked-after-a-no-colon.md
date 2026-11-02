---
id: 2026-11-02-honor-later-content-length-and-chunked-after-a-no-colon
kind: decision
date: 2026-11-02
supersedes:
  - 2026-11-02-wait-for-content-length-after-a-no-colon-blank
---

## Context
The no-colon wait only used Content-Length collected before the junk line. tshark 4.6.9 req_resp_hdrs_do_reassembly keeps walking until the later blank and still honors a Content-Length or Transfer-Encoding: chunked that appears after that no-colon line. Until those body bytes exist, Host is not emitted. Live tshark 4.6.9 (v4.6.9-0-g2d548b197c75, empty WIRESHARK_CONFIG_DIR): POST plus not-a-header then Content-Length: 100 then a leftover GET printed a blank Host; fin printed a.example. Same extra for GET with Content-Length: 4 and no body, two junk lines then Content-Length: 50, an obs-fold extra then Content-Length: 50, NOTIFY/OPTIONS, and Transfer-Encoding: chunked with no body or leftover 1. Complete 0 CRLF then GET still matches (both first Host). A later Content-Length whose bytes are present after the blank still matches. 204 / TCP FIN still match because try_desegment_body is false.

## Options
- Count every no-colon frame that also has a later Content-Length or Transfer-Encoding
- Scan remaining headers after the junk line for Content-Length and Transfer-Encoding: chunked, wait for those body bytes when body desegment is on, otherwise prove Host as before
- Keep using only Content-Length collected before the junk line

## Choice
After a no-colon HTTP header line, Host waits for a later Content-Length or chunked body after the blank, matching tshark 4.6.9 req_resp_hdrs_do_reassembly.

## Why
A counted miss is allowed; printing a.example when tshark prints a blank is not. Reassembly walks every header line until the blank, including after a no-colon line. Dissection still breaks with offset on the junk line, so leftover there stays Continuation. 204 and TCP FIN skip body desegment, so they still print the first Host. Complete last-chunk 0 then leftover GET still prints the first Host.
