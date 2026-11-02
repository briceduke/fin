---
id: 2026-11-02-read-every-capture-sequentially
kind: decision
date: 2026-11-02
supersedes:
  - 2026-10-19-chunk-only-classic-pcap
  - 2026-10-19-prove-a-chunk-start-by-abutment
  - 2026-10-19-reread-the-whole-file-when-a-seam-fails
---

## Context

Classic pcap chunking split a mapped file across cores, proved seams by abutment, and fell back to read_capture on a failed seam. The measured win was 4.2 ms on a million-packet walk. fin still walked ip.src on one core after merging frames. The extra parser, tests, and three in-force decisions are not worth that.

## Options

- Keep pcap-only chunking and the abutment/fallback rules
- Read every capture sequentially with read_capture

## Choice

v1 reads every capture sequentially; classic pcap is not split across cores.

## Why

read_capture is the reference and already the pcapng, stdin, and fallback path. Dropping the parallel walk removes the seam prover, the chunk tests, and a second pcap parser. Fin still maps regular files. A later session that reintroduces cores starts from this sequential reader, not from abutment.
