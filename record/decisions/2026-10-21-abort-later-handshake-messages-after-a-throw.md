---
id: 2026-10-21-abort-later-handshake-messages-after-a-throw
kind: decision
date: 2026-10-21
---

## Context
parse_handshake_messages walked every handshake message in a TLS record and kept SNI from later ClientHellos. handshake_throws then only aborted leftover records. tshark 4.6.9 THROW(ReportedBoundsError) aborts dissect_ssl at that message, so a following ClientHello in the same record is not printed. Live check: CertificateURL bodies `00` / `00 01` / `00 00 01` / `00 05 00 00 00` and NPN Encrypted Extensions (type 67) bodies `ff` / `7f` / `fe`, then a ClientHello in the same record, print blank. CH then throw then `other.example` prints `www.example.com` only.

## Options
- Keep collecting SNI from every ClientHello in the record and only abort leftover records
- Stop walking handshake messages at the first throw, keep SNI from ClientHellos before it, and still abort leftover records

## Choice
A throwing handshake message aborts later handshake messages in that TLS record, keeping SNI from ClientHellos before the throw.

## Why
ssl_dissect_hnd_cert_url and dissect_ssl3_hnd_encrypted_exts throw on the parent tvb. Empty ServerHello / NST / HRR / Certificate Verify / Compressed Certificate / empty type 67 still continue when the following ClientHello supplies those reads in the same record. Empty CertificateURL then a ClientHello as a second record, and leftover `00 01 00` / `ff ff ff` then a next-frame hello, already abort leftover only.
