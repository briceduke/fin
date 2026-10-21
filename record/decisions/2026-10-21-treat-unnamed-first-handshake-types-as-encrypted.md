---
id: 2026-10-21-treat-unnamed-first-handshake-types-as-encrypted
kind: decision
date: 2026-10-21
---

## Context
parse_handshake_messages only stopped later messages on message_throws. tshark 4.6.9 dissect_tls_handshake calls is_encrypted_handshake_message on the first message of a new record: if the remaining record is at least 16 bytes and try_val_to_str(msg_type, ssl_31_handshake_type) is NULL, the rest of the record is Encrypted Handshake Message. Type 7 `07 00 00 00` then a ClientHello in that record printed SNI in fin and was blank in tshark. Same extra for unnamed types 9, 10, 17-19, 26-32, 64, 66, 68, 99, 254, 255. Named types include Hello Verify Request (3) even though ssl_is_valid_handshake_type treats it as DTLS-only. Message Hash (254) is not named.

## Options
- Keep walking later ClientHellos after an unrecognized first handshake type
- Treat an unnamed first type in a record of 16 or more bytes as encrypted and print no server names from that record
- Also implement the ntoh40-zero and 64K-length arms of is_encrypted_handshake_message

## Choice
An unnamed first handshake type in a TLS record of 16 or more bytes is an encrypted handshake; later ClientHellos in that record are not printed.

## Why
That is the try_val_to_str(ssl_31_handshake_type) arm of is_encrypted_handshake_message. Empty type 7 as its own 4-byte record then a ClientHello still prints because the encrypted check requires 16 bytes. CH then type 7 then another CH still prints both names because the check is only on the first message. Empty named types including type 3 and 20-25 then CH in the same record still print.
