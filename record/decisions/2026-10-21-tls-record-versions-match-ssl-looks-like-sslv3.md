---
id: 2026-10-21-tls-record-versions-match-ssl-looks-like-sslv3
kind: decision
date: 2026-10-21
---

## Context

On a TLS port with an unknown session, tshark 4.6.9 decides SSLv3/TLS vs continuation data with `ssl_looks_like_sslv3`, not the `ssl_versions` value string. The first TLS SNI reader accepted GREASE, DTLS, TLS 1.3 drafts, and SSL 2.0 on port 443 and printed SNI tshark left blank.

## Options

- Keep the `ssl_versions` table on a TLS port
- Match `ssl_looks_like_sslv3` exactly: 0x0300–0x0304 and TLCP 0x0101

## Choice

TLS record versions match tshark 4.6.9 ssl_looks_like_sslv3: 0x0300 through 0x0304 plus 0x0101.

## Why

Those are the versions `ssl_looks_like_sslv3` accepts. Anything else is continuation data, so fin must stay blank and not invent a name. The TLS-port path and the heuristic path use the same check.
