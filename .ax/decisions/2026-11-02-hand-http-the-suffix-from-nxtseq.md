---
id: 2026-11-02-hand-http-the-suffix-from-nxtseq
kind: decision
date: 2026-11-02
supersedes:
  - 2026-11-02-prefix-extend-a-consumed-http-seq
---

## Context
http_overlap treated a TCP gap as Fresh and skipped any overlap that was not a same-seq prefix of the walked payload. Live tshark 4.6.9 with empty WIRESHARK_CONFIG_DIR and `-o tcp.reassemble_out_of_order:TRUE` does not dissect HTTP when the previous segment was not captured. It hands HTTP the new suffix from nxtseq when a later segment overlaps already-walked bytes but extends past nxtseq, including a same-seq replacement of `X`×35 plus a GET. An Unproved prefix-extend suffix must stay open so a later longer prefix-extend can complete that GET.

## Options
- Count the three families instead of matching tshark
- Keep Skip for non-prefix overlap and gaps; only prefix-extend prints Host
- Hand tshark's nxtseq suffix to HTTP, skip a gap, and keep an Unproved suffix open so a later prefix-extend can complete

## Choice
A TCP segment that extends past nxtseq dissects only the new suffix; a gap after nxtseq is not HTTP; a truncated suffix stays open so a later prefix-extend can complete.

## Why
Printing Host on a gap is an uncounted add. Skipping an overlap whose suffix is a complete GET drops a Host tshark prints. Storing open=false on an Unproved prefix-extend suffix Suffix-skips the completing frame from the truncated middle. Live tshark vs Ethernet IPv4 TCP 50000→80 PSH+ACK.
