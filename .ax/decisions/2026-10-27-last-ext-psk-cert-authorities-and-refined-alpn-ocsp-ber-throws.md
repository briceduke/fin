---
id: 2026-10-27-last-ext-psk-cert-authorities-and-refined-alpn-ocsp-ber-throws
kind: decision
date: 2026-10-27
---

## Context
`_ => false` still walked later ClientHellos after last-ext pre_shared_key (41) and certificate_authorities (47). The ALPN arm ja4-read every name so a later empty name aborted. oid_filters stopped after the OID BER header. trusted_ca_keys skipped x509_name DistinguishedName. status_request_v2 advanced 1+2 per item and skipped the OCSP responder/extensions walk. Live tshark 4.6.9 (`v4.6.9-0-g2d548b197c75`, empty `WIRESHARK_CONFIG_DIR`).

## Options
- Leave `_ => false` for 41/47 and the four incomplete arms
- Port tshark 4.6.9 hello-tvb reads: PSK ticket age, DistinguishedName, oid_filters values BER plus ntoh, first-name-only ALPN ja4, and status_request_v2 OCSP walk

## Choice
Match tshark 4.6.9 last-ext throws for pre_shared_key, certificate_authorities, trusted_ca_keys x509_name, and oid_filters values; ALPN ja4 is first-name only; status_request_v2 walks OCSP.

## Why
Those reads are from the ClientHello tvb after ssl_add_vector (min is expert-info only). Matching them aborts later hellos and leftover the way dissect_ssl does, without treating PSK identities length 0/1, certificate_authorities list 0, ALPN later empty names, oid_filters list 0, trusted_ca_keys pre_agreed, or a one-item status_request_v2 OCSP body as a throw.
