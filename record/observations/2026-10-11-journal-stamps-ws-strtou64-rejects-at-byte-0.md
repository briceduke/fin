---
id: 2026-10-11-journal-stamps-ws-strtou64-rejects-at-byte-0
kind: observation
date: 2026-10-11
method: tshark 4.6.9 on journal extras plus wsutil/strtoi.c
---

journal stamps: ws_strtou64 rejects +/– at byte 0, then strtoull skips whitespace, accepts a later sign, and wraps –1 to u64::MAX; overflow is missing
