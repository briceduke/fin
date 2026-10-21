---
id: 2026-10-21-tls-port-is-ssl-associations
kind: decision
date: 2026-10-21
---

## Context
is_tls_port treated a source port as a TLS server when first_named(tcp.port) was tls. tshark 4.6.9 ssl_packet_from_server looks up ssl_associations, which is the tls.port table. Ports 3389/4420/4460/6514/8009/10050/10051/10809/27017 are on tls.port and not first-named tls on tcp.port, so a CCS from those ports armed the client slot and the reverse Hello Request plus ClientHello printed SNI.

## Options
- Keep looking up first-named tls on tcp.port
- Snapshot tls.port and treat any registered port as ssl_associations
- Hard-code only the tls.port-only ports named in the review

## Choice
ssl_packet_from_server looks up the snapshotted tls.port table, not first-named tls on tcp.port.

## Why
That is tshark 4.6.9 packet-tls.c: ssl_associations = register_dissector_table("tls.port"), and ssl_packet_from_server is dissector_get_uint_handle(table, srcport) != 0 until ssl_set_server. Destination 443/465/636/853 still wins pick, so the TLS walker runs.
