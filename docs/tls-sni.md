# tls.handshake.extensions_server_name vs tshark 4.6.9

Walk of `reader/src/tls_sni.rs` through the same link, VLAN, IPv4, IPv6, and TCP path as `ip.src`. Live checks use an empty `WIRESHARK_CONFIG_DIR`.

A counted miss is allowed. Fin never prints a server name tshark did not print.

## What v1 proves

The ClientHello `server_name` extension, `host_name` type. An in-order TCP split of one TLS record prints the name on the completing segment. IPv4 and IPv6, plus VLAN/QinQ, SLL, SLL2, and the tunnels `ip.src` already walks (VXLAN, IPIP, TEB, EtherIP).

- A complete ClientHello with SNI prints the name.
- An in-order split of one ClientHello record prints the name on the completing segment.
- A complete ClientHello without SNI prints an empty line.
- A port-443 payload that is not TLS prints an empty line.
- A retransmission of a TCP sequence already consumed prints an empty line, matching tshark's reassembly skip.

The TLS port table is the same tshark 4.6.9 snapshot as `ip.src`. An unregistered port pair still runs the TLS record heuristic. A named non-TLS port whose payload looks like a handshake is counted; STARTTLS is not parsed.

## Out of scope

These frames are counted when they look like a TLS/DTLS/QUIC handshake, and left blank:

| Case | Why |
| --- | --- |
| ClientHello split out of order, or across TLS records | tshark stitches; v1 counts. |
| ClientHello length past this TLS record | tshark stitches records; v1 does not. |
| DTLS | UDP. Handshake records are counted. |
| QUIC Initial | UDP. Counted, not decrypted. |
| IP fragment carrying TLS | Stream field on a fragment is unclaimed. |
| SSLv2 ClientHello | No SNI extension. |

HTTP is the next field, not this one.
