# http.host vs tshark 4.6.9

Walk of `reader/src/http_host.rs` through the same link, VLAN, IPv4, IPv6, and TCP path as `ip.src`. Live checks use an empty `WIRESHARK_CONFIG_DIR`.

A counted miss is allowed. Fin never prints a Host tshark did not print.

## What v1 proves

HTTP/1.x requests and responses over TCP on the snapshotted tshark 4.6.9 `tcp.port` names of `http` (80, 1900, 2710, 2869, 3128, 3132, 3689, 5985, 8080, 8088, 11371). A message whose headers and body fit in one TCP segment prints `http.host` the way tshark 4.6.9 does.

- A complete GET/POST/… with a Host header prints that value.
- Header names are case-insensitive. OWS after the colon is skipped. Trailing spaces in the value stay. Multiple Host headers are comma-separated, matching `-T fields`.
- Bytes 0x80–0xFF become U+FFFD. A NUL truncates the value. `-T fields` escaping is the same `ws_escape_csv` path as TLS SNI.
- An in-order retransmission of a TCP sequence already consumed (same 5-tuple, seq, and payload length, or a *shorter* payload) prints an empty line. A later *longer* segment at that seq is dissected, matching tshark 4.6.9 `[TCP Out-Of-Order]`.
- TCP RST skips HTTP, matching tshark 4.6.9: a complete GET with `TH_RST` set prints no Host. PSH+ACK, ACK, FIN, SYN, and SYN+ACK with that payload still print.
- A request without a Host header prints an empty line.
- A 1xx, 204, or 304 response, or a response with Content-Length that fits, prints Host if present. The status token must be exactly three digits, matching tshark 4.6.9 `parse_http_status_code`; a longer token is status 0 and a response without Content-Length waits for FIN. A Content-Length on 1xx/204/304 still consumes `min(remaining, CL)` body bytes before the next message, matching `dissect_http_message`; the RFC no-body arm (`datalen = 0`) runs only when there is no Content-Length.
- Content-Length is tshark 4.6.9 `g_ascii_strtoll` on the ENC_ASCII C string: leading skip includes VT and FF, and trailing NUL or GLib 2.80 `g_ascii_isspace` (SP, HT, LF, FF, CR; not VT) is accepted. Trailing VT is an invalid length, so a request has body 0. A request that then still needs body bytes is counted.
- A response with no Content-Length prints Host only when this segment has TCP FIN, matching `IS_TH_FIN`, except a 2xx to a pending `SSTP_DUPLEX_POST` or CONNECT: tshark 4.6.9 sets `try_desegment_body = false`, so complete headers are a complete response even with no Content-Length, a Content-Length larger than this segment, or Transfer-Encoding. SSTP 200 switches leftover Hosts to an unwalked tunnel. CONNECT 2xx keeps leftover on that frame as HTTP and switches *later* frames when the URI port is not `http` or `tls`. A 101 with `Upgrade` does the same as SSTP, including when Transfer-Encoding is set.
- Two complete requests in one segment print both Hosts, including SEARCH and POLL leftover. NOTIFY, SUBSCRIBE, and UNSUBSCRIBE (including the `M-` prefix) without Content-Length are tshark 4.6.9 `MEDIA_CONTAINER_HTTP_NOTIFICATION`, not `HTTP_REQUEST`: leftover in this segment is the notification body, so only the first Host prints. `Content-Length: 0` leftover still pipelines. One leading CRLF is skipped at the start of every message when remaining > 3, matching tshark 4.6.9 `dissect_http_message`.
- A CR ends a line the way tshark 4.6.9 `tvb_find_line_end` does, except a CR with no next byte in the segment is incomplete (`desegment=true`). A complete line with no colon breaks the header loop with offset on that line, matching tshark 4.6.9 `dissect_http_message`; leftover starting there is Continuation, not a new HTTP message. Host is proved when a later blank line is present (`http.desegment_headers`) and, when `try_desegment_body` is true, a Content-Length or `Transfer-Encoding: chunked` collected through that blank (including after the junk line) has its body bytes; otherwise the frame is counted. `204` / TCP FIN skip body desegment and still print. A folded Host prints the first line's value. A colon still continues the header walk, so `:value` and `Foo Bar: x` leftover still pipeline.

The HTTP port table is the same tshark 4.6.9 snapshot as `ip.src`. Default `packet-http.c` `TCP_DEFAULT_RANGE` is `80,3128,3132,5985,8080,8088,11371,1900,2869,2710`; 3689 is also `http` in that snapshot (DAAP).

## Out of scope

These frames are counted when they look like HTTP that v1 does not prove, and left blank:

| Case | Why |
| --- | --- |
| Headers split across TCP segments | tshark desegments (`http.desegment_headers`); v1 counts. |
| Body not in this segment (Content-Length leftover, no-CL 200 without FIN, Transfer-Encoding) | tshark desegments (`http.desegment_body`) and does not emit Host until the message is complete. The next in-order payload on that TCP direction is continuation, not a new request; v1 counts it. |
| Transfer-Encoding (chunked or other) on a request | Counted, not dechunked. A 101 with `Upgrade`, or a 2xx to `SSTP_DUPLEX_POST`, still switches. |
| HTTP on a non-`http` TCP port (heuristic `http_tcp`) | tshark may still claim; v1 counts `http-heuristic` and sticks that TCP conversation so later segments stay counted. |
| HTTP/2 (`PRI * HTTP/2.0`, h2c upgrade) | Not HTTP/1.x. Counted, not proved. The 24-byte magic or the 16-byte first line `PRI * HTTP/2.0\r\n` (optionally after one leading CRLF) on a named `http` port, including leftover after a complete HTTP/1.x message, sticks that TCP conversation so later segments stay blank. A Content-Length *body* that starts with that magic is still the HTTP/1.x body; leftover after those body bytes is the next HTTP/1.x message, matching tshark 4.6.9 clipping `datalen` to Content-Length. Heuristic ports already stick (`http-heuristic`); TLS ports already count `http-over-tls`. |
| HTTP over TLS | tshark may decrypt (pcapng secrets) or follow HTTP inside TLS; v1 counts `http-over-tls` on snapshotted TLS ports. |
| HTTP-like UDP (SSDP) | Not TCP. Counted `http-udp`. |
| Inner HTTP in a tunnel this walker does not follow (sFlow, SSTP after `SSTP_DUPLEX_POST`+200 including a 1xx before that 200, a 200 whose headers are complete with no Content-Length / a short body / Transfer-Encoding, the request and 200 in the same segment, 101 with `Upgrade` including Transfer-Encoding, leftover in that same segment, CONNECT plus 2xx when the URI port is not `http` or `tls`, …) | Counted `http-tunnel`. A 101 with no Upgrade stays HTTP. |
| CONNECT plus 2xx | tshark 4.6.9 `dissect_http_tcp` calls `http_conversation_is_connect` after CONNECT whose `response_code` is 200–299 and hands *later* segments to `http_payload_subdissector` using the URI port. The CONNECT request prints Host. A later GET prints Host only when that port's `tcp.port` name is `http` or `tls` (`:443` / `:80` / `:8080` / `:465` / `:993` / `:995`). Other URI ports (21, 22, 23, 25, 53, 110, 143, 587, 1194, 1883, 3306, 5060, 5432, 5900, 6379, …), a URI with no port, and 201 on those arms are counted `http-tunnel`. Same-segment leftover GET on the 2xx frame still prints. |
| Headers split across increasing TCP seq | Counted. A later *longer* segment at the same seq is not this case. |

TLS server names stay the previous field. This one is Host on cleartext HTTP/1.x.
