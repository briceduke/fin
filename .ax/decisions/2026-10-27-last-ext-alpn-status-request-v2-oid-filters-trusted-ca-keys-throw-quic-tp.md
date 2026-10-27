---
id: 2026-10-27-last-ext-alpn-status-request-v2-oid-filters-trusted-ca-keys-throw-quic-tp
kind: decision
date: 2026-10-27
---

## Context
`_ => false` still walked later ClientHellos after last-ext ALPN (16), status_request_v2 (17), oid_filters (48), and trusted_ca_keys (3) whose tshark 4.6.9 hello-tvb reads throw (ja4 first/last ALPN byte, status type plus 2-byte request length, BER OID identifier/length, SHA1 identifier 1/3). `0485092` also dropped `parameter_length = (uint32_t)parameter_length64`, so an 8-byte length varint of 2^32 threw when tshark wraps to a 0-byte ENC_NA read and keeps walking.

## Options
- Leave `_ => false` and the 64-bit QUIC length
- Port those four tshark 4.6.9 handlers' hello-tvb overruns as throws and wrap the QUIC length varint to u32

## Choice
Last-ext ALPN, status_request_v2, oid_filters, and trusted_ca_keys throw on a hello-tvb overrun, and a QUIC TP length varint wraps to u32.

## Why
Those reads are from the ClientHello tvb after ssl_add_vector (min is expert-info only). Matching them aborts later hellos and leftover the way dissect_ssl does, without treating list length 0, ALPN `00 02 01 00`, or trusted_ca_keys pre_agreed as a throw, and without dropping a later hello after a length that wraps to 0.
