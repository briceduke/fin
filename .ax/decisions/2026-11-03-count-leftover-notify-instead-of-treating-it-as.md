---
id: 2026-11-03-count-leftover-notify-instead-of-treating-it-as
kind: decision
date: 2026-11-03
supersedes:
  - 2026-11-02-http-notification-leftover-is-body
---

## Context
PR #15 proved tshark HTTP quirks so more Hosts would print. v1 already allows a counted miss. Wave 2 counts those quirks instead of keeping the ports.

## Options
- Keep proving the quirk so more Hosts match tshark on junk payloads
- Count the frame and print nothing when the outcome is that quirk
- Drop HTTP Host entirely

## Choice
NOTIFY, SUBSCRIBE, and UNSUBSCRIBE payloads are counted instead of consuming leftover as notification body.

## Why
Those methods are not the v1 one-segment GET/POST claim. Counting avoids printing a pipelined Host tshark treated as body.
