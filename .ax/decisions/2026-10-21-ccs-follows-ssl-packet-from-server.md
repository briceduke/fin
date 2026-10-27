---
id: 2026-10-21-ccs-follows-ssl-packet-from-server
kind: decision
date: 2026-10-21
---

## Context
tls_ccs was a directed 5-tuple. tshark 4.6.9 ssl_dissect_change_cipher_spec writes client_ccs_frame or server_ccs_frame using ssl_packet_from_server from the start of dissect_ssl. That flag is srcport in tls.port until a ClientHello calls ssl_set_server(dst); later frames compare src to srv_addr. Frame 1 TCP 443→50000 empty CCS plus no-SNI ClientHello then frame 2 same 5-tuple Hello Request plus ClientHello SNI: tshark prints www.example.com, fin printed two blanks (drop). Inverse extra: frame 2 50000→443, tshark Encrypted Handshake Message, fin printed the name. Both total 0. Same pair for nonempty CCS leftover ClientHello, IPv6, and TLS ports 465/636/853/993/995. 50000→443, unnamed 40001→40002, non-ClientHello leftovers from 443, and trailing empty CCS with no leftover from 443 already matched.

## Options
- Keep CCS keyed by the directed TCP 5-tuple
- Key CCS by conversation but never flip the server role
- Store client_ccs_frame and server_ccs_frame on the conversation, with ssl_packet_from_server from the TLS port table until ClientHello calls ssl_set_server(dst)

## Choice
CCS uses client_ccs_frame and server_ccs_frame on the TCP conversation; ssl_packet_from_server starts from the TLS port table and flips when ClientHello calls ssl_set_server(dst).

## Why
That is tshark 4.6.9 packet-tls.c dissect_ssl plus ssl_packet_from_server and ssl_set_server in packet-tls-utils.c. CCS is stored with the start-of-packet flag; a leftover ClientHello in that same frame still prints because pinfo->num is not greater than ccs_frame, then later frames use the updated role. A directed key encrypts the same 5-tuple after a 443-sourced CCS and misses the reverse extra.
