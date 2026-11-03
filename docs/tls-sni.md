# tls.handshake.extensions_server_name vs tshark 4.6.9

Walk of `reader/src/tls_sni.rs` through the same link, VLAN, IPv4, IPv6, and TCP path as `ip.src`. Live checks use an empty `WIRESHARK_CONFIG_DIR`.

A counted miss is allowed. Fin never prints a server name tshark did not print.

## What v1 proves

The ClientHello `server_name` extension. tshark prints every ServerName, not only `host_name`. An in-order TCP split of one TLS record prints the name on the completing segment. IPv4 and IPv6, plus VLAN/QinQ, SLL, SLL2, and the tunnels `ip.src` already walks (VXLAN, IPIP, TEB, EtherIP).

- A complete one-record ClientHello with SNI prints the name.
- An in-order split of one ClientHello record prints the name on the completing segment.
- A complete ClientHello without SNI prints an empty line.
- A port-443 payload that is not TLS prints an empty line.
- A retransmission of a TCP sequence already consumed prints an empty line, matching tshark's reassembly skip.
- A TCP RST payload is not TLS, matching tshark 4.6.9.

The TLS port table is the same tshark 4.6.9 snapshot as `ip.src`. An unregistered port pair still runs the TLS record heuristic. A named non-TLS port whose payload looks like a handshake is counted; STARTTLS is not parsed.

A payload proves at most one ClientHello. Leftover, CCS, GREASE after CCS, a later hello in that payload, and a last ClientHello extension whose throw fin cannot prove are counted. `parse_client_hello_sni` reads a hello body so QUIC Initials can reuse it.

## Out of scope

These frames are counted when they look like a TLS/DTLS/QUIC handshake, and left blank:

| Case | Why |
| --- | --- |
| ClientHello split out of order, or across TLS records | tshark stitches; v1 counts. |
| ClientHello length past this TLS record | tshark stitches records; v1 does not. |
| Leftover, CCS, GREASE, later hello in the same payload | Counted, not walked. |
| DTLS | UDP. Handshake records are counted. |
| QUIC Initial | UDP. Counted, not decrypted. |
| IP fragment carrying TLS | Stream field on a fragment is unclaimed. |
| SSLv2 ClientHello | No SNI extension. |
