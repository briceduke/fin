---
id: 2026-10-27-distinguishedname-and-oid-filters-oid-ber-values-overrun-the
kind: decision
date: 2026-10-27
---

## Context
`distinguished_name_throws` and the oid_filters OID arm stopped after the BER identifier and length octets. tshark 4.6.9 `dissect_x509if_DistinguishedName` (`dissect_ber_sequence_of`) and `dissect_ber_object_identifier_str` then read the BER value of that length from the ClientHello tvb (`proto_tree_add_item` / `tvb_get_ptr`). Last-ext type 47 `00 04 00 02 30 05`, type 3 `00 05 02 00 02 30 05`, long-form `30 81 05`, and type 48 `00 03 02 06 05` walked later hellos and leftover. Live tshark 4.6.9 (`v4.6.9-0-g2d548b197c75`, empty `WIRESHARK_CONFIG_DIR`).

## Options
- Keep treating DistinguishedName and oid_filters OID as identifier-and-length-only hello-tvb reads
- Throw when that BER value overruns the ClientHello tvb, including long-form length, matching tshark 4.6.9

## Choice
A DistinguishedName or oid_filters OID whose BER identifier and length fit still throws when that BER value overruns the ClientHello tvb.

## Why
Those value reads are from the ClientHello tvb after ssl_add_vector (min is expert-info only). Matching them aborts later hellos and leftover the way dissect_ssl does, without treating name length 0/1, SEQUENCE length 0, oid_filters list 0, OID-only `00 01 00` / `00 02 01 00`, or values-vector ntoh as a change.
