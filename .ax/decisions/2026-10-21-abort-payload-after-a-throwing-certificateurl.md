---
id: 2026-10-21-abort-payload-after-a-throwing-certificateurl
kind: decision
date: 2026-10-21
---

## Context
cert_url_throws only checked that type plus the URL list length were present. tshark 4.6.9 ssl_dissect_hnd_cert_url then walks that length as a count of URLAndHash entries on the parent tvb. An empty or short CertificateURL whose leftover is a ClientHello supplies those 3 bytes with a list length past the tvb, THROW aborts dissect_ssl, and a following hello in this payload is not printed. parse_records already consults handshake_throws after the heartbeat abort.

## Options
- Special-case empty CertificateURL then a ClientHello in the same payload
- Throw only when the 2-byte list length overruns remaining bytes
- Walk ssl_dissect_hnd_cert_url: type, list length as a URLAndHash count, throw when a field overruns the parent tvb

## Choice
A CertificateURL whose tshark 4.6.9 ssl_dissect_hnd_cert_url throws aborts leftover, matching dissect_ssl.

## Why
tvb_get_ntohs and proto_tree_add_item throw on the parent tvb. tshark treats the 2-byte vector length as a count, so body 00 00 01 still throws on the first URLAndHash even though one leftover byte fits. Leftover 00 01 00 is the same abort, so the next frame is a new record. Leftover 1-2 zeros already threw. Leftover 3 zeros is list length 0, IUR. list_len 0 in the message and empty ServerHello / NST / HRR / Certificate Verify / Compressed Certificate / Encrypted Extensions still continue.
