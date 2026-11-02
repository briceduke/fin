# http.host vs tshark 4.6.9

Walk of `reader/src/http_host.rs` through the same link, VLAN, IPv4, IPv6, and TCP path as `ip.src`. Live checks use an empty `WIRESHARK_CONFIG_DIR`.

A counted miss is allowed. Fin never prints a Host tshark did not print.

## What v1 proves

HTTP/1.x requests and responses over TCP on the snapshotted tshark 4.6.9 `tcp.port` names of `http` (80, 1900, 2710, 2869, 3128, 3132, 3689, 5985, 8080, 8088, 11371). A message whose headers and body fit in one TCP segment prints `http.host` the way tshark 4.6.9 does.

- A complete GET/POST/… with a Host header prints that value.
- Header names are case-insensitive. OWS after the colon is skipped. Trailing spaces in the value stay. Multiple Host headers are comma-separated, matching `-T fields`.
- Bytes 0x80–0xFF become U+FFFD. A NUL truncates the value. `-T fields` escaping is the same `ws_escape_csv` path as TLS SNI.
- An in-order retransmission of a TCP sequence already consumed prints an empty line.
- A request without a Host header prints an empty line.
- A 1xx, 204, or 304 response, or a response with Content-Length that fits, prints Host if present. The status token must be exactly three digits, matching tshark 4.6.9 `parse_http_status_code`; a longer token is status 0 and a response without Content-Length waits for FIN. A Content-Length on 1xx/204/304 still consumes `min(remaining, CL)` body bytes before the next message, matching `dissect_http_message`; the RFC no-body arm (`datalen = 0`) runs only when there is no Content-Length.
- Content-Length is tshark 4.6.9 `g_ascii_strtoll` on the ENC_ASCII C string: leading `g_ascii_isspace` (including VT and FF) is skipped, and trailing NUL or `g_ascii_isspace` is accepted. A request that then still needs body bytes is counted.
- A response with no Content-Length prints Host only when this segment has TCP FIN, matching `IS_TH_FIN`.
- Two complete requests in one segment print both Hosts. One leading CRLF is skipped at the start of every message when remaining > 3, matching tshark 4.6.9 `dissect_http_message`.
- A CR ends a line the way tshark 4.6.9 `tvb_find_line_end` does, except a CR with no next byte in the segment is incomplete (`desegment=true`). A complete line that is not `name:` stops adding headers; Host is proved only when a later blank line completes them, matching `http.desegment_headers`. A folded Host prints the first line's value.

The HTTP port table is the same tshark 4.6.9 snapshot as `ip.src`. Default `packet-http.c` `TCP_DEFAULT_RANGE` is `80,3128,3132,5985,8080,8088,11371,1900,2869,2710`; 3689 is also `http` in that snapshot (DAAP).

## Out of scope

These frames are counted when they look like HTTP that v1 does not prove, and left blank:

| Case | Why |
| --- | --- |
| Headers split across TCP segments | tshark desegments (`http.desegment_headers`); v1 counts. |
| Body not in this segment (Content-Length leftover) | tshark desegments (`http.desegment_body`) and does not emit Host until the message is complete. |
| Transfer-Encoding (chunked or other) | Counted, not dechunked. |
| HTTP on a non-`http` TCP port (heuristic `http_tcp`) | tshark may still claim; v1 counts `http-heuristic` and sticks that TCP conversation so later segments stay counted. |
| HTTP/2 (`PRI * HTTP/2.0`, h2c upgrade) | Not HTTP/1.x. |
| HTTP over TLS | tshark may decrypt (pcapng secrets) or follow HTTP inside TLS; v1 counts `http-over-tls` on snapshotted TLS ports. |
| HTTP-like UDP (SSDP) | Not TCP. Counted `http-udp`. |
| Inner HTTP in a tunnel this walker does not follow (sFlow, SSTP after `SSTP_DUPLEX_POST`+200 including a 1xx before that 200, the request and 200 in the same segment, 101 with `Upgrade`, including leftover in that same segment, …) | Counted `http-tunnel`. A 101 with no Upgrade stays HTTP. |
| CONNECT plus 200 | Stays HTTP, matching tshark 4.6.9. The CONNECT request prints Host; a later GET after the 200 prints Host. |
| Out-of-order TCP | Counted. |

TLS server names stay the previous field. This one is Host on cleartext HTTP/1.x.
