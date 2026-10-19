---
id: 2026-10-19-prove-a-chunk-start-by-abutment
kind: decision
date: 2026-10-19
---

## Context
The v1 lock said classic pcap resyncs one byte, pcapng resyncs four, and an 8-packet chain exists only to avoid fallbacks. A later session could treat that chain as the proof and emit frames from a payload that only looks like headers.

## Options
- Treat an 8-record or 8-block chain as a proved start
- Prove a start only when it is the byte where the previous chunk stopped, and use the chain only to nominate a start

## Choice
A chunk start is proved only when it is the byte where the previous chunk stopped.

## Why
The 8-chain nominates a start so well-formed files rarely fall back. Packet bytes can mimic record headers and pcapng blocks. Abutment from the real file start is the proof. Tests force a fake chain in the payload, assert fallback, and require the frames to equal read_capture.
