---
id: 2026-10-13-print-every-counted-frame-on-stderr
kind: decision
date: 2026-10-13
---

## Context
The reader lock said stderr names the first few counted frames. The ip.src slice needs every counted frame in the checker: check_pair parses counted <frame> <reason> lines. A summary of the first few would hide later faults.

## Options
- Keep a short stderr summary of the first few frames
- Print every counted line, then a total

## Choice
Stderr prints every counted line with frame and reason, then a total, and the process exits nonzero when any frame was counted.

## Why
The checker matches on those lines. A total that used the counted prefix would be parsed as a frame number, so the total line is 	otal N. Exit 0 only when nothing was counted and the file had no reader fault.
