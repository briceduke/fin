---
id: 2026-10-21-empty-ccs-leftover-sets-ccs-frame
kind: decision
date: 2026-10-21
---

## Context
fin required a nonempty CCS body before setting after_ccs. tshark 4.6.9 dissect_ssl3_record calls tvb_get_uint8 for next_byte before the CCS switch. That throw happens only when a length-0 record ends the tvb. A following byte is readable, so ssl_dissect_change_cipher_spec still sets client_ccs_frame / server_ccs_frame unless the session is already TLS 1.3. A later-frame Hello Request or empty Certificate plus ClientHello then becomes Encrypted Handshake Message. A trailing empty CCS still throws and does not arm.

## Options
- Keep requiring a nonempty CCS body
- Treat every length-0 CCS as CCS, including a trailing empty record
- Arm CCS only when next_byte is readable, matching dissect_ssl3_record

## Choice
A length-0 CCS still sets ccs_frame when tshark 4.6.9 tvb_get_uint8 for next_byte succeeds.

## Why
That is tshark 4.6.9 dissect_ssl3_record then ssl_dissect_change_cipher_spec. Same-frame leftover ClientHello still prints because pinfo->num is not greater than ccs_frame. A trailing empty CCS stays a throw, so a following GREASE hello is still continuation.
