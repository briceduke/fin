---
id: 2026-10-27-count-unclear-last-clienthello-extensions
kind: decision
date: 2026-10-27
supersedes:
  - 2026-10-27-distinguishedname-and-oid-filters-oid-ber-values-overrun-the
---

## Context
Cursor reviews kept finding more tshark 4.6.9 `ssl_dissect_hnd_extension` throw sites on the last ClientHello extension (nested DistinguishedName SET/SEQUENCE, BER tag mismatch). Porting BER/X.509/PSK/OCSP/JA4 is an unbounded tail. Live tshark 4.6.9 (`v4.6.9-0-g2d548b197c75`, empty WIRESHARK_CONFIG_DIR). Owner 2026-10-27: count unclear last extensions instead of copying more throws.

## Options
- Keep porting each `ssl_dissect_hnd_extension` throw as reviewers find it
- Count any last ClientHello extension whose throw fin cannot prove, keep only exact fixed-width hello-tvb reads, and drop later SNI in that payload

## Choice
Count a last ClientHello extension whose tshark 4.6.9 throw fin cannot prove, and keep only exact fixed-width hello-tvb reads.

## Why
Fixed-width last-ext reads (max_fragment_length, status_request, cert_type, ec_point_formats, heartbeat, client/server_cert_type, token_binding, record_size_limit, connection_id, compress_certificate, QUIC TP, ESNI, ECH, trusted_ca_keys SHA1) stay exact. Last ALPN, status_request_v2, pre_shared_key, certificate_authorities, oid_filters, and trusted_ca_keys x509_name are counted `tls-hello-ext-uncertain`: fin prints this hello's SNI, drops later hellos/records in the payload, still desegments leftover, and never prints a value tshark did not. Unknown types use tshark's default fitted `ext_len` read and are not counted.
