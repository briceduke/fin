---
id: 2026-10-21-empty-handshake-next-byte-sticks-the-tls-session
kind: decision
date: 2026-10-21
---

## Context
A length-0 handshake was Unproved and stopped, so a following empty CCS (or complete CCS/alert/app) never stuck. tshark 4.6.9 ssl_try_set_version reads next_byte after the empty handshake header; 0x14 is Finished and authoritative, so a later GREASE ClientHello prints. Empty handshake then a complete hello in the same payload stays a counted miss.

## Options
- Keep stopping without applying ssl_try_set_version, and invent another way to stick from a following CCS
- Apply ssl_try_set_version from next_byte on a length-0 handshake, then still Unproved so a same-payload ClientHello stays a counted miss

## Choice
A length-0 handshake stays Unproved, but ssl_try_set_version reads next_byte as the handshake type so a following CCS can stick.

## Why
That is tshark 4.6.9 dissect_ssl3_record: next_byte after an empty handshake header is the first byte of the following record. Finished (0x14), CertificateURL (0x15), CertificateStatus (0x16), and the other valid types stick SSLv3/TLS 1.0–1.2. A later GREASE hello on the next payload prints. Walking the following ClientHello in this payload would print a name that v1 still counts.
