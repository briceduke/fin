---
id: 2026-10-09-write-the-analyzer-in-rust
kind: decision
date: 2026-10-09
---

## Context

fin will parse untrusted packet bytes on the hot path. The language choice is Rust or C. A later session that starts a C tree, or another language, would fight the safety and speed target.

## Options

- C, matching Wireshark and libpcap directly
- Rust, with an allocation-free hot path

## Choice

The packet analyzer is implemented in Rust.

## Why

Packet dissection is where memory bugs ship. Rust keeps that path safe without giving up a C-like hot path, as long as decoding does not allocate per field. C stays available only if a measured hotspot cannot be expressed in safe Rust.
