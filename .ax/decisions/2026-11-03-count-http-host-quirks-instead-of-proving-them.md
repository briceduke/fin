---
id: 2026-11-03-count-http-host-quirks-instead-of-proving-them
kind: decision
date: 2026-11-03
supersedes:
  - 2026-11-02-apply-content-length-on-1xx-204-304
---

## Context
PR #15 proved tshark HTTP quirks so more Hosts would print. v1 already allows a counted miss. Wave 2 counts those quirks instead of keeping the ports.

## Options
- Keep proving the quirk so more Hosts match tshark on junk payloads
- Count the frame and print nothing when the outcome is that quirk
- Drop HTTP Host entirely

## Choice
v1 http.host counts a no-colon header line, leftover NOTIFY, unreadable Content-Length, and a 1xx/204/304 that carries Content-Length.

## Why
A counted miss is allowed; an extra Host is not. Deleting the no-colon chunked scan, the notification leftover-as-body arm, and the GLib VT replica removes code that existed only to print Hosts on junk. ICY stays a status line so an SSTP 2xx still switches.
