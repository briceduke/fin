---
id: 2026-11-02-count-host-after-sstp-and-101-upgrade-as-an
kind: decision
date: 2026-11-02
---

## Context
tshark 4.6.9 packet-http.c switches the TCP conversation off HTTP after a complete response: SSTP_DUPLEX_POST plus 200 sets next_handle to SSTP, and 101 with Upgrade sets it to http_upgrade_dissector. Later segments are not HTTP. fin printed Host from a later GET on those conversations. CONNECT plus 200 and a 101 with no Upgrade stay HTTP on both.

## Options
- Port the SSTP and HTTP-upgrade dissectors so later Hosts match tshark
- Count the conversation as an unwalked tunnel after SSTP_DUPLEX_POST plus 200 or a 101 with Upgrade, and print no later Host
- Keep printing later Hosts

## Choice
After SSTP_DUPLEX_POST plus 200 or a 101 with Upgrade, later Hosts on that conversation are counted as an unwalked tunnel.

## Why
v1 does not walk SSTP or websocket/h2c. A counted miss is allowed; printing a Host tshark would not is not. CONNECT plus 200 and a 101 with no Upgrade stay HTTP.
