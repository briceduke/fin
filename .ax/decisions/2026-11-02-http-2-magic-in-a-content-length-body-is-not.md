---
id: 2026-11-02-http-2-magic-in-a-content-length-body-is-not
kind: decision
date: 2026-11-02
---

## Context
looks_like_http2_preface(after_headers) was true when a Content-Length body started with PRI * HTTP/2.0\r\n. That set http2 and parse_http_pending broke before leftover, so a pipelined GET after those 24 body bytes was dropped with total 0. tshark 4.6.9 dissect_http_message clips datalen to Content-Length, then dissect_http_on_stream walks leftover as the next HTTP message.

## Options
- Treat a Content-Length body that starts with the HTTP/2 preface as HTTP/2 and count leftover
- Only treat leftover after the Content-Length body as an HTTP/2 preface
- Count any pipeline that follows a Magic body

## Choice
An HTTP/2 preface is leftover after the Content-Length body, not the body bytes themselves.

## Why
A differing row that is not counted is a defect. GET/PUT/OPTIONS/POST and 200/204 with Content-Length 24 Magic plus leftover GET must print both Hosts. GET Content-Length 0 leftover preface is still HTTP/2 because leftover is not a bounded body.
