---
id: 2026-10-21-incomplete-handshake-desegments-like-tshark
kind: decision
date: 2026-10-21
---

## Context

tshark 4.6.9 `dissect_tls_handshake` desegments when a TLS record is complete but the handshake is shorter than 4 bytes, or the u24 length overruns the record. fin's `tls_need` only buffered an incomplete record, so the next in-order payload was parsed as a new ClientHello. A 1-byte ServerHello then a GREASE ClientHello printed `www.example.com`; tshark prints two blanks.

## Options

- Keep buffering only incomplete records, and count the truncated handshake
- Buffer an incomplete handshake inside a complete record the same way `tls_need` already buffers an incomplete record

## Choice

A complete TLS record with an incomplete handshake still desegments; the next in-order payload on that flow is continuation, matching tshark 4.6.9 dissect_tls_handshake.

## Why

ClientHello SNI on the following segment is continuation data, not a new hello. A complete empty ServerHello (4-byte header, length 0) does not desegment, and the peer direction is a new record, so those GREASE cases still print the name.
