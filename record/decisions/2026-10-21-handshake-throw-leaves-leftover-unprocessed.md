---
id: 2026-10-21-handshake-throw-leaves-leftover-unprocessed
kind: decision
date: 2026-10-21
---

## Context
record_tail desegmented leftover shorter than a TLS record header after every complete handshake. tshark 4.6.9 THROW(ReportedBoundsError) from a handshake dissector aborts dissect_ssl, so leftover is not desegmented and the next ClientHello is a new record that prints SNI.

## Options
- Special-case the listed empty ServerHello, ticket, retry, Certificate Verify, CertificateURL, Compressed Certificate, and NPN Encrypted Extensions inputs
- Walk each handshake type the way tshark 4.6.9's dissectors do, and skip leftover desegment when an unconditional tvb read would throw

## Choice
A complete handshake whose tshark 4.6.9 dissector throws leaves leftover unprocessed, so the next ClientHello is a new record.

## Why
ssl_add_vector checks offset_end and does not throw, so Hello Request, Certificate, ServerHelloDone, Finished, and a valid ServerHello still desegment leftover. ClientHello reads a subset of the message body. The others read the parent tvb, so leftover bytes can satisfy a short read. Certificate Verify uses the stored session version, so Sticky holds that version.
