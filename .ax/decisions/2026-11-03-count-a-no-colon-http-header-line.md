---
id: 2026-11-03-count-a-no-colon-http-header-line
kind: decision
date: 2026-11-03
supersedes:
  - 2026-11-02-a-no-colon-http-header-line-is-leftover
---

## Context
PR #15 proved tshark HTTP quirks so more Hosts would print. v1 already allows a counted miss. Wave 2 counts those quirks instead of keeping the ports.

## Options
- Keep proving the quirk so more Hosts match tshark on junk payloads
- Count the frame and print nothing when the outcome is that quirk
- Drop HTTP Host entirely

## Choice
A complete HTTP header line with no colon is counted instead of treating leftover as Continuation.

## Why
req_resp_hdrs_do_reassembly exists to print Host on junk lines. Counting the frame cannot print a Host tshark omitted.
