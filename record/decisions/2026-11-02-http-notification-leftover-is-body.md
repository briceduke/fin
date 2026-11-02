---
id: 2026-11-02-http-notification-leftover-is-body
kind: decision
date: 2026-11-02
---

## Context
`LineKind::Request` with no Content-Length uses body 0, so leftover in this segment was parsed as the next HTTP message. tshark 4.6.9 `is_http_request_or_reply` sets NOTIFY, SUBSCRIBE, and UNSUBSCRIBE (including the `M-` prefix) to `MEDIA_CONTAINER_HTTP_NOTIFICATION`. That type is not `HTTP_REQUEST`, so `dissect_http_message` takes the default datalen arm (`reported_datalen = -1`): leftover bytes are the notification body, not a pipelined request. `req_resp_hdrs_do_reassembly` also passes `desegment_until_fin` only for `HTTP_RESPONSE`, so a notification without Content-Length is complete in this segment. Printing a Host tshark did not is a defect. `Content-Length: 0` leftover still pipelines on both. SEARCH and POLL leftover still match because those are `HTTP_REQUEST` with body 0.

## Options
- Port tshark notification body handling and treat leftover as body, printing only the first Host
- Count the whole notification frame and print blank
- Keep parsing leftover as a pipelined request

## Choice
A NOTIFY, SUBSCRIBE, or UNSUBSCRIBE without Content-Length, including the M- prefix, consumes leftover as body, not a pipelined request.

## Why
A counted miss is allowed; printing inner.example when tshark prints only n.example is not. Content-Length still sets datalen, so CL 0 leftover still prints both names.
