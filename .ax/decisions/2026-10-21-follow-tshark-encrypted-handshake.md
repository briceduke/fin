---
id: 2026-10-21-follow-tshark-encrypted-handshake
kind: decision
date: 2026-10-21
supersedes:
  - 2026-10-21-treat-unnamed-first-handshake-types-as-encrypted
---

## Context
dabf72e implemented only the unnamed-type arm of tshark 4.6.9 is_encrypted_handshake_message. Live check against v4.6.9-0-g2d548b197c75: two Hello Requests then CH (`00 00 00 00 00 00 00 00` then the hello) printed www.example.com in fin and was Encrypted Handshake Message in tshark. CCS then Hello Request then CH in the next frame was the same extra. Types 7 / 9 / 10 / 17-19 / 26-29 / 99 / 254 / 255 and type 7 then a second record with other.example already matched. A single empty Hello Request then CH still prints on both.

## Options
- Keep the unnamed-type arm only
- Also treat a 5-byte zero prefix as encrypted
- Follow is_encrypted_handshake_message exactly: zero prefix, unnamed type, 64K length, and CCS in a prior frame of this direction except a short valid ClientHello or ServerHello which resets CCS

## Choice
A new TLS handshake record of 16 or more bytes is encrypted when tshark 4.6.9 is_encrypted_handshake_message is true.

## Why
dissect_tls_handshake calls that check only on the first message of a new record. ntoh40==0 is two Hello Requests. try_val_to_str(ssl_31_handshake_type)==NULL is the unnamed arm. msg_length>=0x010000 is the 64K arm. After CCS, any other first type is encrypted; a ClientHello or ServerHello with a named ssl_versions value and length under 1024 resets ccs_frame. Same-frame CCS does not arm because pinfo->num is not greater than ccs_frame. TLS 1.3 CCS is dummy and does not arm.
