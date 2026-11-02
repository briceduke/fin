---
id: 2026-11-02-unproved-http-suffix-marks-that-tcp-direction
kind: decision
date: 2026-11-02
---

## Context
HttpParse::Unproved on a prefix-extend suffix stored open=true so a later same-seq prefix-extend can complete, but it did not mark the TCP direction. http_overlap then treated the next in-order payload as Fresh. tshark 4.6.9 desegments that incomplete suffix with the next segment.

## Options
- Port tshark http.desegment_headers reassembly and print the concatenated Host
- Leave the next in-order payload as Fresh
- Mark that TCP direction so the next in-order payload is counted continuation

## Choice
An Unproved prefix-extend suffix marks that TCP direction so the next in-order payload is counted continuation.

## Why
A counted miss is allowed; printing a Host tshark left Continuation is not, and dropping a concatenated Host without counting is not. A later longer prefix-extend at the same seq still completes. Completing only the Host value is a counted miss. Live tshark 4.6.9.
