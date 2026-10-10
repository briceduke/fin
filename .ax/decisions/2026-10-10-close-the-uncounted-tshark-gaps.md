---
id: 2026-10-10-close-the-uncounted-tshark-gaps
kind: decision
date: 2026-10-10
supersedes:
  - 2026-10-10-lock-the-v1-reader-against-tshark-4-6-9
---

## Context

The v1 reader is already locked: one plan, tshark 4.6.9 as the oracle, and a count for any frame the plan cannot prove. A few paths still print a value in tshark and a blank in fin with no count. Checked on tshark 4.6.9 with an empty config directory.

STARTTLS on TCP port 25 prints `tls.handshake.extensions_server_name`. A ClientHello split across two TLS records prints the name. A fragmented ICMP error and a fragmented GRE packet print the inner `ip.src` on the last fragment only. A captured length of 262144 is read. 262145 stops the file: "bigger than maximum of 262144", exit 14. A file cut mid-packet prints the complete rows, then "appears to have been cut short in the middle of a packet", exit 14. The four pcap magics for microsecond and nanosecond timestamps, in both byte orders, open. Any other magic is "isn't a capture file", exit 3.

## Options

- Leave those blanks uncounted
- Close each one, and fail a classic pcap whose link type is outside v1 before reading packets

## Choice

The v1 reader compiles one plan, matches tshark 4.6.9 on claimed paths, and counts any frame it cannot prove.

## Why

The earlier lock still holds, with these corrections.

The walker steps by the packet's captured length, even past the snaplen or the original length. A captured length above 262144 is a corrupt file. Fin stops with tshark's message and exit code. It does not walk that packet.

A classic pcap whose link type is not Ethernet, classic SLL, or SLL2 fails before any row. One link type covers the whole file, so a counted blank per packet would be noise. pcapng can mix interfaces, so an unsupported interface there is still a per-frame count.

Recognize four pcap magics: `0xa1b2c3d4`, `0xd4c3b2a1`, `0xa1b23c4d`, and `0x4d3cb2a1`. Anything else is an error, with tshark's message and exit code.

A truncated file prints every complete row, then tshark's "cut short in the middle of a packet" message, and exits 14. The corpus includes a truncated file.

ICMP errors still contribute a second `ip.src` when the embedded header is complete. If that header is cut off, do not invent an address, and count the frame.

IP fragments still prove the outer `ip.src`. Fin does not reassemble. If the protocol on the fragment is GRE or IP-in-IP, count the fragment, because tshark can print the inner address on the last fragment. For UDP, remember the first fragment's ports for that fragment group. A known tunnel port counts the group. A missing first fragment counts the group. Any other UDP fragment is not counted. A stream field on any fragment is unclaimed.

SMTP on 25 and 587, IMAP on 143, FTP, XMPP, LDAP, and PostgreSQL can switch to TLS mid-connection. A frame on those connections whose bytes look like a ClientHello is counted. Fin does not parse STARTTLS.

A server name still uses one TLS record. If the ClientHello length continues past that record, count the frame. Fin does not stitch records in v1. tshark does, and it prints the name.

The rest of the reader lock is unchanged: the plan, the chunk seam proof, the port order, the QUIC Initial and DTLS handshake counts, proved values only, and the subset check.
