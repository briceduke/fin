# http.host vs tshark 4.6.9

Walk of `reader/src/http_host.rs` through the same link, VLAN, IPv4, IPv6, and TCP path as `ip.src`. Live checks use an empty `WIRESHARK_CONFIG_DIR`.

A counted miss is allowed. Fin never prints a Host tshark did not print.

## What v1 proves

HTTP/1.x requests and responses over TCP on the snapshotted tshark 4.6.9 `tcp.port` names of `http` (80, 1900, 2710, 2869, 3128, 3132, 3689, 5985, 8080, 8088, 11371). A message whose headers and body fit in one TCP segment prints `http.host` the way tshark 4.6.9 does.

- A complete GET/POST/… with a Host header prints that value.
- Header names are case-insensitive. OWS after the colon is skipped. Trailing spaces in the value stay. Multiple Host headers are comma-separated, matching `-T fields`.
- Bytes 0x80–0xFF become U+FFFD. A NUL truncates the value. `-T fields` escaping is the same `ws_escape_csv` path as TLS SNI.
- A request without a Host header prints an empty line.
- A 1xx, 204, or 304 with no Content-Length, or a message whose Content-Length fits this segment, prints Host if present. A response with no Content-Length needs TCP FIN, except a 2xx to pending `SSTP_DUPLEX_POST` or CONNECT. The status token must be exactly three digits.
- Two complete requests in one segment print both Hosts. One leading CRLF is skipped at the start of a message when remaining > 3.

TCP in-order delivery, nxtseq, SYN, RST, suffix overlap, and prefix-extend live in the walker (`ip_src.rs`) with `-o tcp.reassemble_out_of_order:TRUE`. This parser sees the payload the walker hands it, plus FIN and pending SSTP/CONNECT.

The HTTP port table is the same tshark 4.6.9 snapshot as `ip.src`. Default `packet-http.c` `TCP_DEFAULT_RANGE` is `80,3128,3132,5985,8080,8088,11371,1900,2869,2710`; 3689 is also `http` in that snapshot (DAAP).

## Out of scope

These frames are counted when they look like HTTP that v1 does not prove, and left blank:

| Case | Why |
| --- | --- |
| Headers split across TCP segments | tshark desegments (`http.desegment_headers`); v1 counts. |
| Body not in this segment (Content-Length leftover, no-CL 200 without FIN, Transfer-Encoding) | tshark desegments (`http.desegment_body`). The next in-order payload on that TCP direction is continuation; v1 counts it. |
| Transfer-Encoding on a request | Counted, not dechunked. A 101 with `Upgrade`, or a 2xx to `SSTP_DUPLEX_POST`, still switches. |
| HTTP on a non-`http` TCP port | Counted `http-heuristic`; that conversation stays counted. |
| HTTP/2 (`PRI * HTTP/2.0`, h2c upgrade) | Counted. Leftover preface after a complete HTTP/1.x message sticks the conversation. A Content-Length *body* that starts with the magic is still the HTTP/1.x body. |
| HTTP over TLS | Counted `http-over-tls` on snapshotted TLS ports. |
| HTTP-like UDP (SSDP) | Counted `http-udp`. |
| Unwalked tunnels | Counted `http-tunnel`: SSTP after `SSTP_DUPLEX_POST`+200, 101 with `Upgrade`, leftover in that same segment, CONNECT plus 2xx when the URI port is not `http` or `tls`. A 101 with no Upgrade stays HTTP. Same-segment leftover GET on a CONNECT 2xx still prints. |

TLS server names stay the previous field. This one is Host on cleartext HTTP/1.x.
