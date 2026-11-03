---
id: 2026-11-03-count-later-content-length-after-a-no-colon-line
kind: decision
date: 2026-11-03
supersedes:
  - 2026-11-02-honor-later-content-length-and-chunked-after-a-no-colon
---

## Context
PR #15 proved tshark HTTP quirks so more Hosts would print. v1 already allows a counted miss. Wave 2 counts those quirks instead of keeping the ports.

## Options
- Keep proving the quirk so more Hosts match tshark on junk payloads
- Count the frame and print nothing when the outcome is that quirk
- Drop HTTP Host entirely

## Choice
A no-colon HTTP payload is counted even when a later Content-Length or chunked body is present.

## Why
The chunked scan after junk existed to prove Host once reassembly completed. A counted miss is allowed.
