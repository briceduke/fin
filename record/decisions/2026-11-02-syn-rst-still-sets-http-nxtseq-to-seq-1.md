---
id: 2026-11-02-syn-rst-still-sets-http-nxtseq-to-seq-1
kind: decision
date: 2026-11-02
---

## Context
tcp() skipped HTTP nxtseq when RST was set, so an empty SYN+RST never consumed a sequence number and a SYN+RST payload never reached note_http_next. tshark 4.6.9 still sets tcp.nxtseq to seq+1 (Len=0) and seq+len+1 with data, but RST skips dissect_tcp_payload, so HTTP's in-order seq stays seq+1. A later GET not at that seq printed http.host here with no count.

## Options
- Record HTTP nxtseq as seq+len+1 on SYN+RST with data, matching tcp.nxtseq, and count the in-order GET at that seq
- Record SYN+RST as seq+1 even with payload, matching tshark HTTP, and skip RST dissection
- Count every GET after SYN+RST instead of matching tshark

## Choice
A TCP SYN still sets HTTP nxtseq to seq+1 when RST is set; RST payload is not HTTP and does not add its length.

## Why
tshark 4.6.9 `dissect_tcp_rst_payload` never hands RST bytes to HTTP, so OOO maxnextseq stays seq+1. GET at seq+1 still prints. GET at seq, seq+2, seq+len, seq+len+1, or seq+len+2 after SYN+RST with data is not HTTP.
