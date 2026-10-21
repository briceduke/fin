---
id: 2026-10-21-buffer-only-the-truncated-tls-handshake
kind: decision
date: 2026-10-21
---

## Context
take_tls_need re-parsed the whole stitched TCP prefix. A complete ClientHello plus a truncated next handshake counted frame 1 (names dropped) and frame 2 emitted every ClientHello in the buffer. tshark 4.6.9 prints each name on the segment that completed that hello, and sets desegment_offset at the incomplete record.

## Options
- Keep concatenating the whole payload and re-parsing it on the completing segment
- Emit proved ClientHello names on this frame and buffer only bytes from the truncated record onward

## Choice
Print ClientHello SNI on the frame that completed that hello, and buffer only the truncated handshake record as tshark 4.6.9 desegment_offset does.

## Why
Two split hellos must print one name per completing segment. Re-parsing the prefix reprints a hello that already finished, including when the next record is GREASE.
