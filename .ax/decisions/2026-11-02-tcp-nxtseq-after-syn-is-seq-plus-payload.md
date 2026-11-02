---
id: 2026-11-02-tcp-nxtseq-after-syn-is-seq-plus-payload
kind: decision
date: 2026-11-02
---

## Context
note_http_next set nxtseq to seq+len. tshark 4.6.9 TCP nxtseq after SYN is seq+len+1 because SYN consumes a sequence number. A later GET at seq+len printed Host here and was Continuation there. A GET at seq+len+1 was a gap here and in-order HTTP there.

## Options
- Count every SYN-plus-payload follow-up instead of matching tshark
- Add one for SYN and FIN
- Add one only when the TCP SYN flag is set

## Choice
A TCP SYN payload sets HTTP nxtseq to seq plus length plus one; FIN without SYN does not.

## Why
Printing Host at seq+len after SYN is an uncounted add. Skipping seq+len+1 without a count is a drop. GET+FIN with no SYN still matches seq+len. Empty SYN then data at seq 1 still matches. Live tshark 4.6.9 vs Ethernet IPv4/IPv6 TCP 50000→80/8080.
