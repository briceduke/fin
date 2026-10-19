---
id: 2026-10-19-prove-pcapng-seam-endian-with-the-previous-chunk
kind: decision
date: 2026-10-19
---

## Context
A later SHB can switch endian. An 8-block chain from the true next byte can still succeed with the opening endian when a length is valid both ways (`00 01 00 00` is 65536 BE and 256 LE). Offset abutment then proves the seam, and the later chunk peels the wrong blocks.

## Options
- Re-hop the later chunk with the previous chunk's ending endian
- Treat a hop-endian mismatch as an unproved seam and return read_capture, unless the start is a section header

## Choice
A pcapng seam is unproved when the later chunk hops with a different endian than the previous chunk ended with, unless the start is a section header.

## Why
read_capture is already the fallback. Re-hopping would keep the parallel frames on this file, but it is another parser path. A section header carries its own byte-order magic, so that start can switch endian.
