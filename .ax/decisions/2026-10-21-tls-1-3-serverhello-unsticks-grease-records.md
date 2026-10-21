---
id: 2026-10-21-tls-1-3-serverhello-unsticks-grease-records
kind: decision
date: 2026-10-21
---

## Context
tshark 4.6.9 `tls_scan_server_hello` then `ssl_try_set_version` upgrades `SslSession.version` to TLS 1.3 when ServerHello `supported_versions` is 0x0304. Later records take `dissect_ssl`'s default arm and need `ssl_looks_like_sslv3`. fin stuck `known` from the 0x0303 record version and still accepted a GREASE ClientHello.

## Options
- Keep `known` from the SSLv3/TLS 1.0–1.2 record version after any ServerHello
- Scan ServerHello `supported_versions` and unstick when the session becomes TLS 1.3, matching `ssl_try_set_version`

## Choice
A ServerHello supported_versions of TLS 1.3 sets the session like tshark 4.6.9 ssl_try_set_version, so later records need ssl_looks_like_sslv3.

## Why
TLS 1.3 is not in `dissect_ssl`'s SSLv3/TLS 1.0–1.2 switch. A GREASE ClientHello after that ServerHello is continuation data. A following 0x0301 ClientHello still passes `ssl_looks_like_sslv3` and prints SNI.
