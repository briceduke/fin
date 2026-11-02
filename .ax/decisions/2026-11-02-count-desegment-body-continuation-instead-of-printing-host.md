---
id: 2026-11-02-count-desegment-body-continuation-instead-of-printing-host
kind: decision
date: 2026-11-02
---

## Context
HttpParse::Unproved counted the incomplete frame and did not mark the TCP direction. Message after a complete request plus Take::Incomplete neither counted nor marked. tshark 4.6.9 http.desegment_body keeps the next in-order payload on that direction as continuation, so a later GET that looks like a new request printed Host. Opposite-direction GET, SSTP 2xx, 101 with Upgrade, and HEAD 200 still match because try_desegment_body is already false there or the GET is the other direction.

## Options
- Port tshark body reassembly and emit Host only when the message completes
- Mark that TCP direction on Unproved, Partial, and incomplete Message so later same-direction payloads are counted continuation, with a same-seq longer segment still dissected
- Count every later payload on the conversation, both directions

## Choice
An incomplete HTTP message marks that TCP direction so a later payload there is counted continuation, not a new Host.

## Why
A counted miss is allowed; printing a Host tshark would not is not. Same-seq longer still prints, matching [TCP Out-Of-Order]. Opposite-direction GET after that 200 still prints.
