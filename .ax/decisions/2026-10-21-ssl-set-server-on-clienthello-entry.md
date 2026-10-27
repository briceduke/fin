---
id: 2026-10-21-ssl-set-server-on-clienthello-entry
kind: decision
date: 2026-10-21
---

## Context
ssl_set_server ran only when parse_client_hello accepted a ClientHello. tshark 4.6.9 packet-tls.c calls ssl_set_server at the start of the SSL_HND_CLIENT_HELLO arm, before ssl_dissect_hnd_cli_hello. An empty or 1-byte ClientHello after CCS still flips the server role, so a later same-direction Hello Request plus ClientHello prints SNI and the reverse extra is Encrypted Handshake Message.

## Options
- Keep flipping only after a parsed ClientHello
- Treat empty or short ClientHello as ClientHello with no names
- Set the server when the handshake type is ClientHello and the record is not encrypted

## Choice
ssl_set_server(dst) runs when dissect_ssl enters the ClientHello arm, including an empty or short hello.

## Why
That is tshark 4.6.9 SSL_HND_CLIENT_HELLO: ssl_set_server then ssl_dissect_hnd_cli_hello. Handshake body shorter than 16 bytes stays Clear after CCS, so the arm still runs. A complete no-SNI ClientHello leftover already matched.
