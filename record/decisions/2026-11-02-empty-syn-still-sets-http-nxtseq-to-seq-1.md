---
id: 2026-11-02-empty-syn-still-sets-http-nxtseq-to-seq-1
kind: decision
date: 2026-11-02
---

## Context
tcp() returned on an empty TCP payload, so an empty SYN never reached note_http_next. tshark 4.6.9 still sets nxtseq to seq+1 because SYN consumes a sequence number at Len=0. A later GET on that direction that is not at nxtseq printed http.host here and a blank there, with no count.

## Options
- Count every GET after an empty SYN instead of matching tshark
- Record nxtseq as seq+1 on empty SYN, matching tshark
- Leave empty SYN ignored and treat later GETs as Unproved

## Choice
An empty-payload TCP SYN still sets that direction's HTTP nxtseq to seq+1.

## Why
Printing Host at the SYN seq or seq+2 is an uncounted add. GET at seq+1 still matches. SYN with payload keeps seq+len+1. Live tshark 4.6.9 vs Ethernet IPv4/IPv6 TCP 50000→80/8080/3128.
