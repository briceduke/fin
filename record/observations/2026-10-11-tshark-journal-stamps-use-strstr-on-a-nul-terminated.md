---
id: 2026-10-11-tshark-journal-stamps-use-strstr-on-a-nul-terminated
kind: observation
date: 2026-10-11
method: pcapng.c 3050-3051 vs crafted FOO=bar\0__REALTIME_TIMESTAMP=8
---

tshark journal stamps use strstr on a NUL-terminated stripped entry, so a key after an embedded NUL is invisible
