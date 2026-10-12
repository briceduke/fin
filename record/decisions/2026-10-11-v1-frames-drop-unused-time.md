---
id: 2026-10-11-v1-frames-drop-unused-time
kind: decision
date: 2026-10-11
---

## Context

The locked reader listed timestamp and original length on every frame. v1 prints `ip.src` and the TLS server name. The walker steps by captured length. Timestamps are not a sync check. The bytes stay in the file.

## Options

- Keep timestamp and original length on every frame
- Drop them from the v1 frame, and parse them when a later query needs them

## Choice

v1 frames are link type and captured bytes; parse timestamps and original length when a query needs them.

## Why

Those fields are unused by the v1 query. Putting them back is a small isolated parse. Keeping them meant converting ticks, walking journal stamps, and storing extra words on every packet.
