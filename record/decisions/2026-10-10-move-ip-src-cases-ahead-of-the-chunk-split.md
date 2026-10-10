---
id: 2026-10-10-move-ip-src-cases-ahead-of-the-chunk-split
kind: decision
date: 2026-10-10
supersedes:
  - 2026-10-10-build-the-reader-in-checkable-layers
---

## Context

The build order is harness, sequential reader, ip.src, chunk split, then TLS server name. ICMP errors, tunnels, and fragments were listed only on the TLS step. They change `ip.src`. The chunk step had no stress cases. Step 3 also left out entry points the reader claims.

## Options

- Leave those cases on the TLS step
- Move the ip.src cases to step 3, and stress the chunk split on its own step

## Choice

Build the diff harness, then the sequential reader, then ip.src, then the chunk split, then TLS server names.

## Why

The diff harness and the corpus come first. They run tshark and fin side by side under an empty tshark config directory. Two checks ride along: every differing line is a counted frame, and fin's values on a counted frame are a subset of tshark's.

The sequential reader is next. It stays forever as the seam-mismatch fallback, and it is the reference output.

Then the plan and walker for `ip.src`. The path is Ethernet, classic SLL, SLL2, VLAN, QinQ, IPv4, IPv6, and IPv6 extension headers. The test files include ICMP errors, tunnels, and fragments. Those decide the second address and what gets counted.

Then the chunk split, diffed against the sequential reader. Any difference is a split bug. A test-only setting forces tiny chunks, so every file has hundreds of seams. The corpus includes captures whose packets contain fake-looking headers, such as a pcap file being downloaded. That is the check that a guessed boundary cannot pass the seam proof.

TLS server name is last. It adds reassembly, connection routing, and the port table. Its corpus includes non-443 TLS ports and the Authentication Header length case. The AH case stays here because it only matters for reaching TCP. STARTTLS and a ClientHello that spans two records are in this step too.

Each step is checked against the one before it.
