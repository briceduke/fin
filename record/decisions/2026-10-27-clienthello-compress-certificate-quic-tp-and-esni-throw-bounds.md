---
id: 2026-10-27-clienthello-compress-certificate-quic-tp-and-esni-throw-bounds
kind: decision
date: 2026-10-27
---

## Context
hello_ext_handler_throws missed tshark 4.6.9 hello-tvb reads in three ClientHello last-extension handlers, so fin printed extra SNI or dropped a later hello. Live tshark 4.6.9 (`v4.6.9-0-g2d548b197c75`, empty WIRESHARK_CONFIG_DIR). compress_certificate (type 27) ssl_add_vectors a 1-byte length (no throw) then proto_tree_add_items 2-byte algorithm IDs; an odd last list overruns and aborts. QUIC transport_parameters (57 / 65445) proto_tree_add_subtree of 2 then ENC_VARINT_QUIC type/length from the hello tvb; length 2 `00 40` / `40 00` / `80 00` / `00 01` and length 3 `00 00 00` still throw. ESNI (65486) reads a 2-byte suite then a 2-byte KeyShare group; ssl_add_vector for key_exchange does not throw, so length 4–5 must keep walking.

## Options
- Keep rem < 2 for QUIC, skip type 27, and treat ESNI as rem < 6
- Port the three tshark 4.6.9 handlers: odd compress_certificate algorithm-ID reads, QUIC type/length varint overruns, and ESNI rem < 4 only

## Choice
compress_certificate throws on an odd 2-byte algorithm-ID hello-tvb read, QUIC transport_parameters on a type/length varint overrun, and ESNI only when rem < 4.

## Why
ssl_add_vector never throws. Matching the hello-tvb proto_tree_add_item / ENC_VARINT_QUIC reads keeps SNI from hellos before the throw and leaves leftover unprocessed, without dropping a later hello after a length-4 ESNI.
