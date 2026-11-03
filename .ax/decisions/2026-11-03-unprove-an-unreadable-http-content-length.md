---
id: 2026-11-03-unprove-an-unreadable-http-content-length
kind: decision
date: 2026-11-03
supersedes:
  - 2026-11-02-content-length-trailing-vt-is-not-space
---

## Context
PR #15 proved tshark HTTP quirks so more Hosts would print. v1 already allows a counted miss. Wave 2 counts those quirks instead of keeping the ports.

## Options
- Keep proving the quirk so more Hosts match tshark on junk payloads
- Count the frame and print nothing when the outcome is that quirk
- Drop HTTP Host entirely

## Choice
A Content-Length that is not SP/HT digits is unreadable and the HTTP message is counted.

## Why
The GLib 2.80 isspace replica existed so 4-VT would not print an extra Host. Unproving the message also cannot print that Host.
