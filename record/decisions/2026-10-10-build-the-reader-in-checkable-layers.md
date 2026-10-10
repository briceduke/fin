---
id: 2026-10-10-build-the-reader-in-checkable-layers
kind: decision
date: 2026-10-10
---

## Context

Matching tshark is the product. A later session that starts with the TLS parser, or that checks the chunk split by eye, will not know which layer broke.

## Options

- Start with the TLS server-name parser
- Start with the chunked reader
- Stack the work so each layer is checked against the one before it

## Choice

Build the diff harness, then the sequential reader, then ip.src, then the chunk split, then TLS server names.

## Why

The diff harness and the corpus come first. They run tshark and fin side by side under an empty tshark config directory. Two checks ride along: every differing line is a counted frame, and fin's values on a counted frame are a subset of tshark's. The checker exists before the code it checks.

The sequential reader is next. It is the simplest correct version, and it stays forever as the fallback when a chunk seam does not prove. It is also the reference output.

Then the plan and walker for `ip.src`, across Ethernet, SLL, VLAN, IPv4, and IPv6.

Then the chunk split, diffed against the sequential reader. Any difference is a split bug.

TLS server name is last. It is the step that adds reassembly, connection routing, and the port table. The corpus for that step includes non-443 TLS ports, ICMP errors, fragments, tunnels, and the Authentication Header length case.

Each step is checked against the one before it.
