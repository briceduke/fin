---
id: 2026-10-21-non-clienthello-handshake-sticks-tls-version
kind: decision
date: 2026-10-21
---

## Context

tshark 4.6.9 `ssl_try_set_version` sticks SSLv3/TLS 1.0–1.2/TLCP after `ssl_is_authoritative_version_message`: any valid handshake except ClientHello, or any other valid content type. fin's `sets_known` ignored every handshake record (`content != 0x16`), so a ServerHello (or hello_request, NewSessionTicket, Certificate, ServerHelloDone, Finished) did not unlock `dissect_ssl3_record` and a later GREASE ClientHello printed a blank line.

## Options

- Keep handshake records from sticking, matching the previous CCS-only shortcut
- Stick after any valid non-ClientHello handshake with an SSLv3/TLS 1.0–1.2/TLCP record version, matching `ssl_is_authoritative_version_message`

## Choice

A valid non-ClientHello TLS handshake with SSLv3/TLS 1.0–1.2/TLCP sticks the session the way tshark 4.6.9 ssl_try_set_version does.

## Why

ClientHello's record version is not authoritative, so type 1 must not stick. ServerHello and the other valid handshake types do, including across frames. CCS/alert/app-data/heartbeat already stuck; this is the handshake half of the same tshark gate.
