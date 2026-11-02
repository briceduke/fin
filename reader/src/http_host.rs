//! One-segment HTTP/1.x `http.host`. Split headers, body desegment,
//! Transfer-Encoding, HTTP/2, and heuristic ports are counted.

/// A TCP payload that may carry HTTP/1.x.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpParse {
    /// Complete HTTP/1.x message(s) whose Host values follow tshark field order.
    Message(HttpProved),
    /// Hosts from complete messages before a Transfer-Encoding message
    /// this reader does not parse. Counted; values are a subset.
    Partial(Vec<String>),
    /// HTTP that this reader cannot prove.
    Unproved,
    /// Not HTTP/1.x on this payload start.
    Other,
}

/// Hosts from complete one-segment messages, plus tshark 4.6.9 tunnel switches.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HttpProved {
    pub hosts: Vec<String>,
    /// Complete `SSTP_DUPLEX_POST` request in this payload.
    pub sstp_duplex_post: bool,
    /// Complete 200 response in this payload.
    pub status_200: bool,
    /// Complete response of any status in this payload.
    pub has_response: bool,
    /// Complete response with status >= 200. tshark 4.6.9 `push_res`
    /// keeps `request_method` after a 1xx.
    pub has_final_response: bool,
    /// Complete 101 response that listed `Upgrade`.
    pub switching_upgrade: bool,
    /// Bytes remain after a complete 101 with `Upgrade`. Unwalked tunnel.
    pub leftover_after_upgrade: bool,
    /// Bytes remain after the first complete response.
    pub leftover_after_response: bool,
    /// Hosts from complete messages after the first complete response.
    pub hosts_after_response: Vec<String>,
    /// A later message in this payload is incomplete. tshark 4.6.9
    /// `http.desegment_body` keeps the next in-order payload on this
    /// TCP direction as continuation, not a new HTTP message.
    pub desegment: bool,
    /// Leftover after this payload, or leftover treated as body, is an
    /// HTTP/2 preface. Named `http` later Hosts are counted, not printed.
    pub http2: bool,
}

const TOKEN: &[u8] = b"!#$%&\\:*+-.^_`|~";

/// Parse Host from one TCP payload. `end_of_stream` is TCP FIN, matching
/// tshark 4.6.9 `IS_TH_FIN` for a response with no Content-Length.
#[cfg(test)]
pub fn parse_http(payload: &[u8], end_of_stream: bool) -> HttpParse {
    parse_http_pending(payload, end_of_stream, false)
}

/// `sstp_pending` is a prior complete `SSTP_DUPLEX_POST` on this TCP
/// conversation. tshark 4.6.9 then sets `try_desegment_body = false`
/// for a 2xx, so complete headers are a complete response.
pub fn parse_http_pending(payload: &[u8], end_of_stream: bool, sstp_pending: bool) -> HttpParse {
    if payload.is_empty() {
        return HttpParse::Other;
    }
    let mut offset = skip_leading_crlf(payload);
    if offset >= payload.len() {
        return HttpParse::Other;
    }
    if !(0x20..=0x7e).contains(&payload[offset]) {
        return HttpParse::Other;
    }
    let Some((first, _)) = take_line(&payload[offset..]) else {
        return HttpParse::Unproved;
    };
    if classify_line(first).is_none() {
        return HttpParse::Other;
    }
    let mut proved = HttpProved::default();
    while offset < payload.len() {
        let sstp = sstp_pending || proved.sstp_duplex_post;
        match take_message(&payload[offset..], end_of_stream, sstp) {
            Take::Done => break,
            Take::Complete {
                hosts: found,
                next,
                sstp_duplex_post,
                status,
                upgrade,
                http2,
            } => {
                if proved.has_response {
                    proved.hosts_after_response.extend(found.iter().cloned());
                }
                proved.hosts.extend(found);
                if sstp_duplex_post {
                    proved.sstp_duplex_post = true;
                }
                if http2 {
                    proved.http2 = true;
                }
                if let Some(status) = status {
                    proved.has_response = true;
                    if status >= 200 {
                        proved.has_final_response = true;
                    }
                    if status == 200 {
                        proved.status_200 = true;
                    }
                    if status == 101 && upgrade {
                        proved.switching_upgrade = true;
                        offset += next;
                        proved.leftover_after_upgrade = offset < payload.len();
                        break;
                    }
                }
                offset += next;
                if proved.has_response && offset < payload.len() {
                    proved.leftover_after_response = true;
                }
                if proved.http2 {
                    break;
                }
            }
            Take::Incomplete if proved.hosts.is_empty() => return HttpParse::Unproved,
            Take::Incomplete => {
                proved.desegment = true;
                return HttpParse::Message(proved);
            }
            Take::TransferEncoding if proved.hosts.is_empty() => return HttpParse::Unproved,
            Take::TransferEncoding => return HttpParse::Partial(proved.hosts),
            Take::Other => break,
        }
    }
    HttpParse::Message(proved)
}

/// tshark 4.6.9 `dissect_http2_heur_http` `kMagicHello` first line:
/// 16 bytes `PRI * HTTP/2.0\r\n`. One leading CRLF is skipped when
/// remaining > 3, matching `dissect_http_message`.
pub fn looks_like_http2_preface(payload: &[u8]) -> bool {
    const FIRST_LINE: &[u8] = b"PRI * HTTP/2.0\r\n";
    let rest = &payload[skip_leading_crlf(payload)..];
    rest.len() >= FIRST_LINE.len() && rest.starts_with(FIRST_LINE)
}

/// tshark 4.6.9 `dissect_http_heur_tcp`: a CRLF line that starts or ends
/// with `HTTP/1.`, except a line of length 8.
pub fn looks_like_http_heuristic(payload: &[u8]) -> bool {
    let Some((line, _)) = take_line(payload) else {
        return false;
    };
    if line.len() == 8 {
        return false;
    }
    starts_with_ignore_ascii_case(line, b"HTTP/1.")
        || (line.len() >= 8
            && eq_ignore_ascii_case(&line[line.len() - 8..line.len() - 1], b"HTTP/1."))
}

enum Take {
    Complete {
        hosts: Vec<String>,
        next: usize,
        sstp_duplex_post: bool,
        status: Option<u16>,
        upgrade: bool,
        http2: bool,
    },
    Incomplete,
    TransferEncoding,
    Other,
    Done,
}

enum LineKind {
    Request {
        sstp_duplex_post: bool,
    },
    /// tshark 4.6.9 `MEDIA_CONTAINER_HTTP_NOTIFICATION`.
    Notification,
    Response {
        status: u16,
    },
}

fn take_message(payload: &[u8], end_of_stream: bool, sstp_pending: bool) -> Take {
    if payload.is_empty() {
        return Take::Done;
    }
    let skip = skip_leading_crlf(payload);
    let payload = &payload[skip..];
    if payload.is_empty() {
        return Take::Done;
    }
    let Some((first, after_first)) = take_line(payload) else {
        return Take::Incomplete;
    };
    let Some(kind) = classify_line(first) else {
        return Take::Other;
    };
    let mut offset = after_first;
    let mut hosts = Vec::new();
    let mut content_length = None;
    let mut transfer_encoding = false;
    let mut upgrade = false;
    let mut ignore_headers = false;
    loop {
        let Some((line, next)) = take_line(&payload[offset..]) else {
            return Take::Incomplete;
        };
        offset += next;
        if line.is_empty() {
            break;
        }
        if classify_line(line).is_some() {
            return Take::Incomplete;
        }
        if ignore_headers {
            continue;
        }
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            // tshark 4.6.9 stops adding headers on a complete line
            // that is not a request, response, or `name:`, then still
            // needs the blank line `http.desegment_headers` waits for.
            ignore_headers = true;
            continue;
        };
        if !valid_header_name(&line[..colon]) {
            continue;
        }
        let name = &line[..colon];
        let mut value = &line[colon + 1..];
        while value.first().copied() == Some(b' ') || value.first().copied() == Some(b'\t') {
            value = &value[1..];
        }
        if eq_ignore_ascii_case(name, b"Host") {
            hosts.push(ascii_field(value));
        } else if eq_ignore_ascii_case(name, b"Transfer-Encoding") {
            transfer_encoding = true;
        } else if eq_ignore_ascii_case(name, b"Upgrade") {
            upgrade = true;
        } else if eq_ignore_ascii_case(name, b"Content-Length") {
            content_length = parse_content_length(value);
        }
    }
    let sstp_2xx = matches!(
        kind,
        LineKind::Response { status } if sstp_pending && (200..300).contains(&status)
    );
    // tshark 4.6.9 `try_desegment_body = false` for 1xx / 204 / 304
    // and for a 2xx to `SSTP_DUPLEX_POST`. Headers complete means the
    // message is complete, including Transfer-Encoding.
    let skip_body =
        sstp_2xx || matches!(kind, LineKind::Response { status } if rfc_no_body(status));
    if transfer_encoding && !skip_body {
        return Take::TransferEncoding;
    }
    let header_end = offset;
    let available = (payload.len() - header_end) as u64;
    // tshark 4.6.9 `dissect_http_message`: `have_content_length &&
    // transfer_encoding == HTTP_TE_NONE` sets datalen to
    // min(remaining, content_length) before the RFC no-body arm.
    let body_need = match kind {
        LineKind::Request { .. } => content_length.unwrap_or(0),
        // tshark 4.6.9 `is_http_request_or_reply` sets NOTIFY /
        // SUBSCRIBE / UNSUBSCRIBE to `MEDIA_CONTAINER_HTTP_NOTIFICATION`,
        // not `HTTP_REQUEST`. Without Content-Length, `dissect_http_message`
        // takes the default datalen arm (`reported_datalen = -1`): leftover
        // is the notification body. `desegment_until_fin` is only for
        // `HTTP_RESPONSE`, so this segment is complete.
        LineKind::Notification => content_length.unwrap_or(available),
        LineKind::Response { status } if rfc_no_body(status) => {
            content_length.map(|n| n.min(available)).unwrap_or(0)
        }
        LineKind::Response { .. } if sstp_2xx => match (transfer_encoding, content_length) {
            (false, Some(n)) => n.min(available),
            _ => available,
        },
        LineKind::Response { .. } => match content_length {
            Some(n) => n,
            None if end_of_stream => available,
            None => return Take::Incomplete,
        },
    };
    if available < body_need {
        return Take::Incomplete;
    }
    let after_headers = &payload[header_end..];
    let body_end = header_end + body_need as usize;
    Take::Complete {
        hosts,
        next: skip + body_end,
        sstp_duplex_post: matches!(
            kind,
            LineKind::Request {
                sstp_duplex_post: true
            }
        ),
        status: match kind {
            LineKind::Response { status } => Some(status),
            LineKind::Request { .. } | LineKind::Notification => None,
        },
        upgrade,
        http2: looks_like_http2_preface(after_headers)
            || looks_like_http2_preface(&payload[body_end..]),
    }
}

fn take_line(bytes: &[u8]) -> Option<(&[u8], usize)> {
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            return Some((&bytes[..i], i + 1));
        }
        if bytes[i] == b'\r' {
            // tshark 4.6.9 `tvb_find_line_end(..., desegment=true)`
            // returns -1 when this CR has no next byte in the tvbuff.
            if i + 1 >= bytes.len() {
                return None;
            }
            let next = if bytes[i + 1] == b'\n' { i + 2 } else { i + 1 };
            return Some((&bytes[..i], next));
        }
        i += 1;
    }
    None
}

fn classify_line(line: &[u8]) -> Option<LineKind> {
    let mut data = line;
    if data.len() >= 2 && data.starts_with(b"M-") {
        data = &data[2..];
    }
    if data.len() >= 5 && data.starts_with(b"HTTP/") {
        return Some(LineKind::Response {
            status: parse_status(data),
        });
    }
    if data.len() >= 3 && data.starts_with(b"ICY") {
        return Some(LineKind::Response {
            status: parse_status(data),
        });
    }
    let method_len = data.iter().position(|b| *b == b' ').unwrap_or(data.len());
    let method = &data[..method_len];
    if is_notification_method(method) {
        Some(LineKind::Notification)
    } else if is_request_method(method) {
        Some(LineKind::Request {
            sstp_duplex_post: method == b"SSTP_DUPLEX_POST",
        })
    } else {
        None
    }
}

fn is_notification_method(method: &[u8]) -> bool {
    matches!(method, b"NOTIFY" | b"SUBSCRIBE" | b"UNSUBSCRIBE")
}

fn is_request_method(method: &[u8]) -> bool {
    matches!(
        method,
        b"GET"
            | b"PUT"
            | b"COPY"
            | b"HEAD"
            | b"LOCK"
            | b"MOVE"
            | b"POLL"
            | b"POST"
            | b"BCOPY"
            | b"BMOVE"
            | b"MKCOL"
            | b"TRACE"
            | b"PATCH"
            | b"LABEL"
            | b"MERGE"
            | b"DELETE"
            | b"SEARCH"
            | b"UNLOCK"
            | b"REPORT"
            | b"UPDATE"
            | b"NOTIFY"
            | b"BDELETE"
            | b"CONNECT"
            | b"OPTIONS"
            | b"CHECKIN"
            | b"PROPFIND"
            | b"CHECKOUT"
            | b"CCM_POST"
            | b"SUBSCRIBE"
            | b"PROPPATCH"
            | b"BPROPFIND"
            | b"BPROPPATCH"
            | b"UNCHECKOUT"
            | b"MKACTIVITY"
            | b"MKWORKSPACE"
            | b"RPC_CONNECT"
            | b"RPC_IN_DATA"
            | b"UNSUBSCRIBE"
            | b"RPC_OUT_DATA"
            | b"VERSION-CONTROL"
            | b"BASELINE-CONTROL"
            | b"SSTP_DUPLEX_POST"
    )
}

/// RFC 7230 §3.3 / tshark 4.6.9: 1xx, 204, and 304 have no body unless
/// a Content-Length is present.
fn rfc_no_body(status: u16) -> bool {
    (100..200).contains(&status) || status == 204 || status == 304
}

/// tshark 4.6.9 `parse_http_status_code`: the status token length must
/// be exactly 3 digits, otherwise the code is 0.
fn parse_status(line: &[u8]) -> u16 {
    let mut rest = line;
    if let Some(sp) = rest.iter().position(|b| *b == b' ') {
        rest = &rest[sp + 1..];
        while rest.first().copied() == Some(b' ') {
            rest = &rest[1..];
        }
    } else {
        return 0;
    }
    let token_len = rest.iter().position(|b| *b == b' ').unwrap_or(rest.len());
    let token = &rest[..token_len];
    if token.len() != 3 {
        return 0;
    }
    let a = token[0];
    let b = token[1];
    let c = token[2];
    if !a.is_ascii_digit() || !b.is_ascii_digit() || !c.is_ascii_digit() {
        return 0;
    }
    u16::from(a - b'0') * 100 + u16::from(b - b'0') * 10 + u16::from(c - b'0')
}

/// tshark 4.6.9 `dissect_http_message` skips one leading CRLF when
/// remaining > 3 and `tvb_get_ntohs == 0x0d0a`.
fn skip_leading_crlf(payload: &[u8]) -> usize {
    if payload.len() > 3 && payload[0] == b'\r' && payload[1] == b'\n' {
        2
    } else {
        0
    }
}

fn valid_header_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || TOKEN.contains(b))
}

/// tshark 4.6.9 `HDR_CONTENT_LENGTH`: `g_ascii_strtoll` on the ENC_ASCII
/// C string. Leading `g_ascii_isspace` is skipped; after the digits, NUL
/// or `g_ascii_isspace` is accepted.
fn parse_content_length(value: &[u8]) -> Option<u64> {
    let end = value.iter().position(|b| *b == 0).unwrap_or(value.len());
    let value = &value[..end];
    let mut i = 0;
    while i < value.len() && ascii_isspace(value[i]) {
        i += 1;
    }
    if i < value.len() && value[i] == b'+' {
        i += 1;
    }
    if i >= value.len() || !value[i].is_ascii_digit() {
        return None;
    }
    let mut n: i64 = 0;
    while i < value.len() && value[i].is_ascii_digit() {
        n = n.checked_mul(10)?.checked_add(i64::from(value[i] - b'0'))?;
        i += 1;
    }
    if i < value.len() && !ascii_isspace(value[i]) {
        return None;
    }
    if n < 0 {
        None
    } else {
        Some(n as u64)
    }
}

/// GLib `g_ascii_isspace`: SP, HT, LF, VT, FF, CR.
fn ascii_isspace(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// tshark 4.6.9 `tvb_get_string_enc(..., ENC_ASCII)` then a C string:
/// NUL truncates, bytes 0x80–0xFF become U+FFFD.
fn ascii_field(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    let mut out = String::new();
    for &b in &bytes[..end] {
        if b < 0x80 {
            out.push(b as char);
        } else {
            out.push('\u{FFFD}');
        }
    }
    out
}

fn eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn starts_with_ignore_ascii_case(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len() && eq_ignore_ascii_case(&hay[..needle.len()], needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(hosts: &[&str]) -> HttpParse {
        HttpParse::Message(HttpProved {
            hosts: hosts.iter().map(|h| (*h).to_string()).collect(),
            ..HttpProved::default()
        })
    }

    fn resp(hosts: &[&str], status: u16, switching_upgrade: bool) -> HttpParse {
        HttpParse::Message(HttpProved {
            hosts: hosts.iter().map(|h| (*h).to_string()).collect(),
            status_200: status == 200,
            has_response: true,
            has_final_response: status >= 200,
            switching_upgrade,
            ..HttpProved::default()
        })
    }

    #[test]
    fn get_host() {
        assert_eq!(
            parse_http(b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n", false),
            msg(&["www.example.com"])
        );
    }

    #[test]
    fn host_case_and_ows() {
        assert_eq!(
            parse_http(b"GET / HTTP/1.1\r\nHOST: Mixed.Example\r\n\r\n", false),
            msg(&["Mixed.Example"])
        );
        assert_eq!(
            parse_http(b"GET / HTTP/1.1\r\nHost:\t  example.com\r\n\r\n", false),
            msg(&["example.com"])
        );
        assert_eq!(
            parse_http(b"GET / HTTP/1.1\r\nHost: example.com \r\n\r\n", false),
            msg(&["example.com "])
        );
    }

    #[test]
    fn multiple_hosts() {
        assert_eq!(
            parse_http(
                b"GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n",
                false
            ),
            msg(&["a.example", "b.example"])
        );
    }

    #[test]
    fn no_host_is_empty_message() {
        assert_eq!(
            parse_http(b"GET / HTTP/1.1\r\nUser-Agent: x\r\n\r\n", false),
            msg(&[])
        );
    }

    #[test]
    fn incomplete_headers_are_unproved() {
        assert_eq!(
            parse_http(b"GET / HTTP/1.1\r\nHost: cut.example", false),
            HttpParse::Unproved
        );
        assert_eq!(parse_http(b"GET / HTTP/1.1", false), HttpParse::Unproved);
    }

    #[test]
    fn post_needs_the_body() {
        assert_eq!(
            parse_http(
                b"POST / HTTP/1.1\r\nHost: post.example\r\nContent-Length: 4\r\n\r\nbody",
                false
            ),
            msg(&["post.example"])
        );
        assert_eq!(
            parse_http(
                b"POST / HTTP/1.1\r\nHost: post.example\r\nContent-Length: 100\r\n\r\nno",
                false
            ),
            HttpParse::Unproved
        );
    }

    #[test]
    fn transfer_encoding_is_unproved() {
        assert_eq!(
            parse_http(
                b"POST / HTTP/1.1\r\nHost: chunk.example\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
                false
            ),
            HttpParse::Unproved
        );
        assert_eq!(
            parse_http(
                b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\nPOST / HTTP/1.1\r\nHost: b.example\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                false
            ),
            HttpParse::Partial(vec!["a.example".to_string()])
        );
    }

    #[test]
    fn pipeline_two_gets() {
        assert_eq!(
            parse_http(
                b"GET /a HTTP/1.1\r\nHost: a.example\r\n\r\nGET /b HTTP/1.1\r\nHost: b.example\r\n\r\n",
                false
            ),
            msg(&["a.example", "b.example"])
        );
    }

    fn leftover_after(first: &[u8]) -> Vec<u8> {
        let mut payload = first.to_vec();
        payload.extend_from_slice(b"GET / HTTP/1.1\r\nHost: inner.example\r\n\r\n");
        payload
    }

    #[test]
    fn notification_without_content_length_keeps_leftover_as_body() {
        assert_eq!(
            parse_http(b"NOTIFY / HTTP/1.1\r\nHost: n.example\r\n\r\n", false),
            msg(&["n.example"])
        );
        let methods = [
            b"NOTIFY / HTTP/1.1\r\nHost: n.example\r\n\r\n".as_slice(),
            b"SUBSCRIBE / HTTP/1.1\r\nHost: n.example\r\n\r\n",
            b"UNSUBSCRIBE / HTTP/1.1\r\nHost: n.example\r\n\r\n",
            b"M-NOTIFY / HTTP/1.1\r\nHost: n.example\r\n\r\n",
        ];
        for first in methods {
            let HttpParse::Message(proved) = parse_http(&leftover_after(first), false) else {
                panic!("{}", first.escape_ascii());
            };
            assert_eq!(proved.hosts, ["n.example"], "{}", first.escape_ascii());
            assert!(!proved.desegment, "{}", first.escape_ascii());
        }
        let second = b"NOTIFY / HTTP/1.1\r\nHost: n.example\r\n\r\nNOTIFY / HTTP/1.1\r\nHost: n2.example\r\n\r\n";
        let HttpParse::Message(proved) = parse_http(second, false) else {
            panic!("expected a proved NOTIFY");
        };
        assert_eq!(proved.hosts, ["n.example"]);
        assert!(!proved.desegment);
    }

    #[test]
    fn notification_content_length_zero_still_pipelines() {
        assert_eq!(
            parse_http(
                b"NOTIFY / HTTP/1.1\r\nHost: n.example\r\nContent-Length: 0\r\n\r\nGET / HTTP/1.1\r\nHost: inner.example\r\n\r\n",
                false
            ),
            msg(&["n.example", "inner.example"])
        );
    }

    #[test]
    fn search_and_poll_leftover_still_pipelines() {
        for first in [
            b"SEARCH / HTTP/1.1\r\nHost: n.example\r\n\r\n".as_slice(),
            b"POLL / HTTP/1.1\r\nHost: n.example\r\n\r\n",
        ] {
            assert_eq!(
                parse_http(&leftover_after(first), false),
                msg(&["n.example", "inner.example"]),
                "{}",
                first.escape_ascii()
            );
        }
    }

    #[test]
    fn complete_then_incomplete_marks_desegment() {
        let HttpParse::Message(proved) = parse_http(
            b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\nPOST / HTTP/1.1\r\nHost: post.example\r\nContent-Length: 100\r\n\r\n",
            false,
        ) else {
            panic!("expected a proved GET before the incomplete POST");
        };
        assert_eq!(proved.hosts, ["a.example"]);
        assert!(proved.desegment);
    }

    #[test]
    fn junk_after_get_keeps_the_first_host() {
        let HttpParse::Message(proved) =
            parse_http(b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\njunk", false)
        else {
            panic!("expected a proved GET before leftover junk");
        };
        assert_eq!(proved.hosts, ["a.example"]);
        assert!(proved.desegment);
    }

    #[test]
    fn response_204_prints_host() {
        assert_eq!(
            parse_http(b"HTTP/1.1 204 No Content\r\nHost: x\r\n\r\n", false),
            resp(&["x"], 204, false)
        );
    }

    #[test]
    fn response_200_without_length_needs_fin() {
        assert_eq!(
            parse_http(b"HTTP/1.1 200 OK\r\nHost: x\r\n\r\nhello", false),
            HttpParse::Unproved
        );
        assert_eq!(
            parse_http(b"HTTP/1.1 200 OK\r\nHost: x\r\n\r\nhello", true),
            resp(&["x"], 200, false)
        );
    }

    #[test]
    fn lowercase_method_is_other() {
        assert_eq!(
            parse_http(b"get / HTTP/1.1\r\nHost: lower-get.example\r\n\r\n", false),
            HttpParse::Other
        );
    }

    #[test]
    fn space_before_colon_skips_host() {
        assert_eq!(
            parse_http(b"GET / HTTP/1.1\r\nHost : spaced.example\r\n\r\n", false),
            msg(&[])
        );
    }

    #[test]
    fn nul_truncates_and_high_bytes_become_fffd() {
        assert_eq!(
            parse_http(b"GET / HTTP/1.1\r\nHost: ab\x00cd.example\r\n\r\n", false),
            msg(&["ab"])
        );
        assert_eq!(
            parse_http(b"GET / HTTP/1.1\r\nHost: x\xffy\r\n\r\n", false),
            msg(&["x\u{FFFD}y"])
        );
    }

    #[test]
    fn m_get_and_leading_crlf() {
        assert_eq!(
            parse_http(b"M-GET / HTTP/1.1\r\nHost: ext.example\r\n\r\n", false),
            msg(&["ext.example"])
        );
        assert_eq!(
            parse_http(b"\r\nGET / HTTP/1.1\r\nHost: lead.example\r\n\r\n", false),
            msg(&["lead.example"])
        );
    }

    #[test]
    fn lf_only_and_http10() {
        assert_eq!(
            parse_http(b"GET / HTTP/1.1\nHost: lf.example\n\n", false),
            msg(&["lf.example"])
        );
        assert_eq!(
            parse_http(b"GET / HTTP/1.0\r\nHost: ten.example\r\n\r\n", false),
            msg(&["ten.example"])
        );
    }

    #[test]
    fn trailing_cr_blank_is_incomplete() {
        assert_eq!(
            parse_http(b"GET / HTTP/1.1\r\nHost: cr.example\r\n\r", false),
            HttpParse::Unproved
        );
        assert_eq!(
            parse_http(b"GET / HTTP/1.1\rHost: cr.example\r\r", false),
            HttpParse::Unproved
        );
        assert_eq!(
            parse_http(b"GET / HTTP/1.1\r\nHost: cr.example\r\n\r\n", false),
            msg(&["cr.example"])
        );
        assert_eq!(
            parse_http(b"GET / HTTP/1.1\r\nHost: cr.example\r", false),
            HttpParse::Unproved
        );
    }

    #[test]
    fn extra_crlf_before_a_pipelined_request() {
        assert_eq!(
            parse_http(
                b"GET /a HTTP/1.1\r\nHost: a.example\r\n\r\n\r\nGET /b HTTP/1.1\r\nHost: b.example\r\n\r\n",
                false
            ),
            msg(&["a.example", "b.example"])
        );
        assert_eq!(
            parse_http(
                b"POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 0\r\n\r\n\r\nGET /b HTTP/1.1\r\nHost: b.example\r\n\r\n",
                false
            ),
            msg(&["a.example", "b.example"])
        );
        assert_eq!(
            parse_http(
                b"GET /a HTTP/1.1\r\nHost: a.example\r\n\r\n\r\n\r\nGET /b HTTP/1.1\r\nHost: b.example\r\n\r\n",
                false
            ),
            msg(&["a.example"])
        );
    }

    #[test]
    fn status_token_must_be_exactly_three_digits() {
        let bodies = [
            b"HTTP/1.1 1010 X\r\nHost: st.example\r\n\r\nhello".as_slice(),
            b"HTTP/1.1 2040 X\r\nHost: st.example\r\n\r\nhello",
            b"HTTP/1.1 3040 X\r\nHost: st.example\r\n\r\nhello",
            b"HTTP/1.1 1000 X\r\nHost: st.example\r\n\r\nhello",
            b"HTTP/1.1 101X X\r\nHost: st.example\r\n\r\nhello",
            b"HTTP/1.1 204X X\r\nHost: st.example\r\n\r\nhello",
            b"ICY 1010 X\r\nHost: st.example\r\n\r\nhello",
            b"ICY 2040 X\r\nHost: st.example\r\n\r\nhello",
        ];
        for payload in bodies {
            assert_eq!(
                parse_http(payload, false),
                HttpParse::Unproved,
                "{payload:?}"
            );
            assert_eq!(
                parse_http(payload, true),
                resp(&["st.example"], 0, false),
                "{payload:?}"
            );
        }
        assert_eq!(
            parse_http(
                b"HTTP/1.1 101 Switching Protocols\r\nHost: st.example\r\n\r\n",
                false
            ),
            resp(&["st.example"], 101, false)
        );
        assert_eq!(
            parse_http(
                b"HTTP/1.1 204 No Content\r\nHost: st.example\r\n\r\n",
                false
            ),
            resp(&["st.example"], 204, false)
        );
        assert_eq!(
            parse_http(
                b"HTTP/1.1 304 Not Modified\r\nHost: st.example\r\n\r\n",
                false
            ),
            resp(&["st.example"], 304, false)
        );
    }

    #[test]
    fn upgrade_101_stops_before_leftover() {
        let HttpParse::Message(proved) = parse_http(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nHost: sw.example\r\n\r\nGET / HTTP/1.1\r\nHost: after.example\r\n\r\n",
            false,
        ) else {
            panic!("expected a proved 101");
        };
        assert_eq!(proved.hosts, ["sw.example"]);
        assert!(proved.switching_upgrade);
        assert!(proved.leftover_after_upgrade);
        assert_eq!(proved.hosts_after_response, [] as [&str; 0]);
    }

    #[test]
    fn cr_inside_host_ends_the_line() {
        assert_eq!(
            parse_http(b"GET / HTTP/1.1\r\nHost: fuz\r.example\r\n\r\n", false),
            msg(&["fuz"])
        );
    }

    #[test]
    fn folding_keeps_the_first_host_line() {
        assert_eq!(
            parse_http(b"GET / HTTP/1.1\r\nHost: ab\r\n cd\r\n\r\n", false),
            msg(&["ab"])
        );
    }

    #[test]
    fn junk_line_without_a_blank_is_unproved() {
        assert_eq!(
            parse_http(b"GET / HTTP/1.1\r\nHost: fuzz.example\r\n\xd8\n", false),
            HttpParse::Unproved
        );
    }

    #[test]
    fn heuristic_matches_tshark() {
        assert!(looks_like_http_heuristic(
            b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        ));
        assert!(looks_like_http_heuristic(b"HTTP/1.1 200 OK\r\n\r\n"));
        assert!(!looks_like_http_heuristic(
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        ));
        assert!(!looks_like_http_heuristic(b"GET / HTTP/1.1"));
        assert!(looks_like_http2_preface(
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        ));
        assert!(looks_like_http2_preface(b"PRI * HTTP/2.0\r\n\r\n"));
        assert!(looks_like_http2_preface(b"PRI * HTTP/2.0\r\n"));
        assert!(looks_like_http2_preface(
            b"\r\nPRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        ));
        assert!(!looks_like_http2_preface(b"PRI * HTTP/2.0"));
        assert!(!looks_like_http2_preface(b"GET / HTTP/1.1\r\n"));
    }

    fn http2_leftover(first: &[u8], leftover: &[u8]) -> HttpProved {
        let mut payload = first.to_vec();
        payload.extend_from_slice(leftover);
        message(&payload)
    }

    #[test]
    fn leftover_http2_preface_after_a_complete_message() {
        const MAGIC: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        const FIRST_LINE: &[u8] = b"PRI * HTTP/2.0\r\n";
        let firsts = [
            b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n".as_slice(),
            b"POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 204 No Content\r\nHost: a.example\r\n\r\n",
            b"NOTIFY / HTTP/1.1\r\nHost: a.example\r\n\r\n",
        ];
        for first in firsts {
            for leftover in [MAGIC, FIRST_LINE] {
                let proved = http2_leftover(first, leftover);
                assert_eq!(proved.hosts, ["a.example"], "{}", first.escape_ascii());
                assert!(proved.http2, "{}", first.escape_ascii());
            }
        }
    }

    #[test]
    fn icy_is_a_response() {
        assert_eq!(
            parse_http(b"ICY 200 OK\r\nHost: icy.example\r\n\r\n", true),
            resp(&["icy.example"], 200, false)
        );
    }

    #[test]
    fn connect_and_options() {
        assert_eq!(
            parse_http(
                b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
                false
            ),
            msg(&["example.com:443"])
        );
        assert_eq!(
            parse_http(b"OPTIONS * HTTP/1.1\r\nHost: opt.example\r\n\r\n", false),
            msg(&["opt.example"])
        );
    }

    #[test]
    fn content_length_zero_then_pipeline() {
        assert_eq!(
            parse_http(
                b"POST / HTTP/1.1\r\nHost: z\r\nContent-Length: 0\r\n\r\nGET / HTTP/1.1\r\nHost: y\r\n\r\n",
                false
            ),
            msg(&["z", "y"])
        );
    }

    #[test]
    fn content_length_vt_ff_and_trailing_nul_need_the_body() {
        let headers = [
            b"POST / HTTP/1.1\r\nHost: cllead.example\r\nContent-Length: \x0b4\r\n\r\n".as_slice(),
            b"POST / HTTP/1.1\r\nHost: cllead.example\r\nContent-Length: \x0c4\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: cllead.example\r\nContent-Length: 4\x00\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: cllead.example\r\nContent-Length: 4\x0c\r\n\r\n",
        ];
        for payload in headers {
            assert_eq!(
                parse_http(payload, false),
                HttpParse::Unproved,
                "{payload:?}"
            );
            let mut with_body = payload.to_vec();
            with_body.extend_from_slice(b"body");
            assert_eq!(
                parse_http(&with_body, false),
                msg(&["cllead.example"]),
                "{payload:?}"
            );
        }
    }

    #[test]
    fn sstp_duplex_post_sets_the_switch_flag() {
        let HttpParse::Message(proved) = parse_http(
            b"SSTP_DUPLEX_POST / HTTP/1.1\r\nHost: sstp.example\r\n\r\n",
            false,
        ) else {
            panic!("expected a proved SSTP request");
        };
        assert_eq!(proved.hosts, ["sstp.example"]);
        assert!(proved.sstp_duplex_post);
        assert!(!proved.has_response);
        assert!(!proved.has_final_response);
    }

    #[test]
    fn a_1xx_is_not_a_final_response() {
        let proved = message(b"HTTP/1.1 100 Continue\r\n\r\n");
        assert!(proved.has_response);
        assert!(!proved.has_final_response);
        assert!(!proved.status_200);
        let proved = message(
            b"SSTP_DUPLEX_POST / HTTP/1.1\r\nHost: sstp.example\r\n\r\nHTTP/1.1 100 Continue\r\n\r\n",
        );
        assert!(proved.sstp_duplex_post);
        assert!(proved.has_response);
        assert!(!proved.has_final_response);
        let proved = message(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n",
        );
        assert!(proved.has_response);
        assert!(proved.has_final_response);
        assert!(proved.status_200);
    }

    #[test]
    fn switching_101_with_upgrade_sets_the_flag() {
        assert_eq!(
            parse_http(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nHost: sw.example\r\n\r\n",
                false
            ),
            resp(&["sw.example"], 101, true)
        );
        assert_eq!(
            parse_http(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nHost: sw.example\r\n\r\n",
                false
            ),
            resp(&["sw.example"], 101, true)
        );
        assert_eq!(
            parse_http(
                b"HTTP/1.1 101 Switching Protocols\r\nHost: sw.example\r\n\r\n",
                false
            ),
            resp(&["sw.example"], 101, false)
        );
    }

    fn cl_then(status: &[u8], pad: &[u8]) -> Vec<u8> {
        let mut payload = status.to_vec();
        payload.extend_from_slice(b"\r\nHost: st.example\r\nContent-Length: 4\r\n\r\n");
        payload.extend_from_slice(pad);
        payload.extend_from_slice(b"GET / HTTP/1.1\r\nHost: after.example\r\n\r\n");
        payload
    }

    fn message(payload: &[u8]) -> HttpProved {
        match parse_http(payload, false) {
            HttpParse::Message(proved) => proved,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn rfc_no_body_content_length_skips_those_bytes() {
        let statuses = [
            b"HTTP/1.1 100 Continue".as_slice(),
            b"HTTP/1.1 101 Switching Protocols",
            b"HTTP/1.1 102 Processing",
            b"HTTP/1.1 204 No Content",
            b"HTTP/1.1 304 Not Modified",
            b"ICY 204 No Content",
        ];
        for status in statuses {
            let extra = message(&cl_then(status, b""));
            assert_eq!(extra.hosts, ["st.example"], "{status:?}");
            assert!(extra.has_response, "{status:?}");
            assert!(!extra.switching_upgrade, "{status:?}");
            assert_eq!(extra.hosts_after_response, [] as [&str; 0], "{status:?}");
            let drop = message(&cl_then(status, b"xxxx"));
            assert_eq!(drop.hosts, ["st.example", "after.example"], "{status:?}");
            assert_eq!(drop.hosts_after_response, ["after.example"], "{status:?}");
            assert!(!drop.switching_upgrade, "{status:?}");
        }
    }

    #[test]
    fn rfc_no_body_short_content_length_still_prints() {
        let proved = message(
            b"HTTP/1.1 204 No Content\r\nHost: st.example\r\nContent-Length: 100\r\n\r\nGET ",
        );
        assert_eq!(proved.hosts, ["st.example"]);
        assert!(!proved.leftover_after_response);
    }

    #[test]
    fn upgrade_101_content_length_still_stops_before_leftover() {
        for pad in [b"".as_slice(), b"xxxx"] {
            let mut payload =
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nHost: sw.example\r\nContent-Length: 4\r\n\r\n"
                    .to_vec();
            payload.extend_from_slice(pad);
            payload.extend_from_slice(b"GET / HTTP/1.1\r\nHost: after.example\r\n\r\n");
            let proved = message(&payload);
            assert_eq!(proved.hosts, ["sw.example"], "{pad:?}");
            assert!(proved.switching_upgrade, "{pad:?}");
            assert!(proved.leftover_after_upgrade, "{pad:?}");
            assert_eq!(proved.hosts_after_response, [] as [&str; 0], "{pad:?}");
        }
    }

    #[test]
    fn status_200_and_203_content_length_still_skip_those_bytes() {
        for status in [
            b"HTTP/1.1 200 OK".as_slice(),
            b"HTTP/1.1 203 Non-Authoritative Information",
        ] {
            let extra = message(&cl_then(status, b""));
            assert_eq!(extra.hosts, ["st.example"], "{status:?}");
            assert_eq!(extra.hosts_after_response, [] as [&str; 0], "{status:?}");
            assert_eq!(
                extra.status_200,
                status.starts_with(b"HTTP/1.1 200"),
                "{status:?}"
            );
            let drop = message(&cl_then(status, b"xxxx"));
            assert_eq!(drop.hosts, ["st.example", "after.example"], "{status:?}");
            assert_eq!(drop.hosts_after_response, ["after.example"], "{status:?}");
        }
    }

    fn pending(payload: &[u8]) -> HttpProved {
        match parse_http_pending(payload, false, true) {
            HttpParse::Message(proved) => proved,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn sstp_pending_2xx_headers_are_a_complete_response() {
        let bodies = [
            b"HTTP/1.1 200 Connection Established\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 Connection Established\r\nContent-Length: 100\r\n\r\n",
            b"HTTP/1.1 200 Connection Established\r\nTransfer-Encoding: identity\r\n\r\n",
            b"HTTP/1.1 200 Connection Established\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"HTTP/1.0 200 Connection Established\r\n\r\n",
            b"ICY 200 Connection Established\r\n\r\n",
        ];
        for payload in bodies {
            assert_eq!(
                parse_http(payload, false),
                HttpParse::Unproved,
                "{payload:?}"
            );
            let proved = pending(payload);
            assert!(proved.status_200, "{payload:?}");
            assert!(proved.has_final_response, "{payload:?}");
            assert!(proved.hosts.is_empty(), "{payload:?}");
        }
        let cl0 = pending(b"HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n");
        assert!(cl0.status_200);
        assert_eq!(
            parse_http(
                b"HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n",
                false
            ),
            resp(&[], 200, false)
        );
    }

    #[test]
    fn sstp_pending_200_without_length_consumes_same_segment_leftover() {
        let proved = pending(
            b"HTTP/1.1 200 Connection Established\r\n\r\nGET / HTTP/1.1\r\nHost: after.example\r\n\r\n",
        );
        assert!(proved.status_200);
        assert!(proved.hosts.is_empty());
        assert!(!proved.leftover_after_response);
        assert_eq!(proved.hosts_after_response, [] as [&str; 0]);
    }

    #[test]
    fn upgrade_101_with_transfer_encoding_still_switches() {
        let proved = message(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nTransfer-Encoding: identity\r\n\r\n",
        );
        assert!(proved.switching_upgrade);
        assert!(proved.has_response);
        assert!(!proved.has_final_response);
        let leftover = message(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nTransfer-Encoding: identity\r\n\r\nGET / HTTP/1.1\r\nHost: after.example\r\n\r\n",
        );
        assert!(leftover.switching_upgrade);
        assert!(leftover.leftover_after_upgrade);
        assert_eq!(leftover.hosts_after_response, [] as [&str; 0]);
    }

    #[test]
    fn same_segment_sstp_request_and_200_without_length_switches() {
        let proved = message(
            b"SSTP_DUPLEX_POST / HTTP/1.1\r\nHost: sstp.example\r\n\r\nHTTP/1.1 200 Connection Established\r\n\r\nGET / HTTP/1.1\r\nHost: after.example\r\n\r\n",
        );
        assert_eq!(proved.hosts, ["sstp.example"]);
        assert!(proved.sstp_duplex_post);
        assert!(proved.status_200);
        assert_eq!(proved.hosts_after_response, [] as [&str; 0]);
    }
}
