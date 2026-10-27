---
id: 2026-10-27-quic-tp-parameter-type-hello-tvb-reads-throw
kind: decision
date: 2026-10-27
---

## Context
quic_params_varint_throws stopped after type/length ENC_VARINT_QUIC and a parameter_length fit check. tshark 4.6.9 ssl_dissect_hnd_hello_ext_quic_transport_parameters then switches on the parameter type and proto_tree_add_item / proto_tree_add_item_ret_varints a fixed width from the ClientHello tvb, including when parameter_length is 0. Last-extension MAX_IDLE_TIMEOUT `01 00`, STATELESS_RESET_TOKEN `02 08` plus 8 zeros, PREFERRED_ADDRESS `0d 00`, and varint parameters 0x03–0x0b length 0 left later hellos as uncounted extras. DISABLE_ACTIVE_MIGRATION 0x0c and ORIGINAL_DESTINATION_CONNECTION_ID 0x00 length 0 do not throw.

## Options
- Keep the type/length varint overrun check only
- Port each known parameter type's hello-tvb proto_tree_add_item / ENC_VARINT_QUIC read from tshark 4.6.9, treating an overrun as a throw for types 57 and 65445

## Choice
QUIC transport_parameters throw when a known parameter's proto_tree_add_item or ENC_VARINT_QUIC read overruns the hello tvb, even if parameter_length is 0.

## Why
Those reads happen after the length varint, from the hello tvb, not clipped to parameter_length. ssl_add_vector still does not throw. Matching them aborts later hellos and leftover the way dissect_ssl does, without treating 0x0c or 0x00 length 0 as a throw.
