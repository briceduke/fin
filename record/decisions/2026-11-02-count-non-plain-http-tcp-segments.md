---
id: 2026-11-02-count-non-plain-http-tcp-segments
kind: decision
date: 2026-11-02
supersedes:
  - 2026-11-02-hand-http-the-suffix-from-nxtseq
---

## Context
http_from_tcp ported tshark 4.6.9 `-o tcp.reassemble_out_of_order:TRUE` nxtseq suffix and prefix-extend proving across many PR #15 rounds. That path printed Host on overlaps that are not one-segment HTTP/1.x messages. v1 HTTP already counts split, TE, heuristic, HTTP/2, TLS, and unwalked tunnels. TLS already counts out-of-order and keeps its own in-order stitch. Printing a Host tshark omitted is an uncounted add; counting a Host tshark printed is a counted miss.

## Options
- Keep handing HTTP the suffix from nxtseq and re-parsing open prefix-extends
- Count any TCP segment that is not a plain in-order first payload, and keep SYN+1 and RST skip so a GET at the SYN seq cannot print
- Share one TCP nxtseq machine with TLS

## Choice
A non-plain HTTP TCP segment is counted; a gap or contained retransmission stays blank; SYN and RST still set nxtseq to seq+1.

## Why
One-segment Host does not need suffix dissection. An overlap-extend that tshark would print becomes a counted miss. Poisoning http_desegment on extend stops a later in-order GET from printing a Host tshark treated as continuation. TLS keeps tls_need; unifying SYN+1 with TLS is how those bugs return.
