---
id: 2026-10-21-tls-session-version-is-unknown-sticky-or-1-3
kind: decision
date: 2026-10-21
---

## Context
tshark 4.6.9 stores `SslSession.version` as unknown, SSLv3/TLS 1.0–1.2/TLCP, or TLS 1.3. `dissect_ssl3_record` only calls `ssl_try_set_version` when the session is unknown. fin used a bool `known`, so TLS 1.3 and unknown were the same: a TLS 1.3 ServerHello unstuck, then a later 0x0303 CCS/alert/app-data/heartbeat/non-ClientHello handshake re-stuck and a GREASE ClientHello printed SNI. tshark 4.6.9 prints Continuation Data. The same extra name happens after CCS 0x0304 (sets TLS 1.3) then CCS 0x0303, and after a ClientHello with empty `early_data` (forces TLS 1.3) then CCS.

## Options
- Keep `known` as a bool and special-case TLS 1.3 by leaving it false
- Store unknown, a sticky pre-1.3 version, or TLS 1.3, matching tshark 4.6.9 `SslSession.version`

## Choice
SslSession.version is unknown, a sticky pre-1.3 version, or TLS 1.3, so a later 0x0303 record cannot unstick TLS 1.3.

## Why
Record-level `ssl_try_set_version` runs only when the session is unknown. TLS 1.3 stays on `dissect_ssl`'s default arm, so GREASE fails `ssl_looks_like_sslv3`. A following 0x0301 ClientHello still prints. ServerHello `supported_versions` 0x0304, an authoritative 0x0304 record, and ClientHello `early_data` all set TLS 1.3.
