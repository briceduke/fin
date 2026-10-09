---
id: 2026-10-09-measure-tshark-before-any-decoder
kind: decision
date: 2026-10-09
---

## Context

The product bet is that tshark does more work per packet than the query needs, and that a compatible tool can be much faster. That bet is unverified. Process weight is low, so the lifecycle is one measurement gate, not a phase process.

## Options

- Start the Rust decoder and optimize later
- Study and benchmark tshark first, then build only what the numbers justify

## Choice

The first work is a tshark behavior study and performance baseline, before any decoder.

## Why

Correctness is judged against tshark, and the speed claim needs a number to beat. Synthetic captures explain the mechanism. Real captures keep the number honest. The decoder starts only after those results say what to build.
