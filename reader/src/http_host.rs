//! One-segment HTTP/1.x `http.host`. Split headers, body desegment,
//! Transfer-Encoding, HTTP/2, and heuristic ports are counted.

/// A TCP payload that may carry HTTP/1.x.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpParse {
    /// Complete HTTP/1.x message(s) whose Host values follow tshark field order.
    Message(Vec<String>),
    /// Hosts from complete messages before a Transfer-Encoding message
    /// this reader does not parse. Counted; values are a subset.
    Partial(Vec<String>),
    /// HTTP that this reader cannot prove.
    Unproved,
    /// Not HTTP/1.x on this payload start.
    Other,
}

const TOKEN: &[u8] = b"!#$%&\\:*+-.^_`|~";

/// Parse Host from one TCP payload. `end_of_stream` is TCP FIN, matching
/// tshark 4.6.9 `IS_TH_FIN` for a response with no Content-Length.
pub fn parse_http(payload: &[u8], end_of_stream: bool) -> HttpParse {
    if payload.is_empty() {
        return HttpParse::Other;
    }
    let mut offset = 0;
    if payload.len() > 3 && payload[0] == b'\r' && payload[1] == b'\n' {
        offset = 2;
    }
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
    let mut hosts = Vec::new();
    while offset < payload.len() {
        match take_message(&payload[offset..], end_of_stream) {
            Take::Done => break,
            Take::Complete { hosts: found, next } => {
                hosts.extend(found);
                offset += next;
            }
            Take::Incomplete if hosts.is_empty() => return HttpParse::Unproved,
            Take::Incomplete => return HttpParse::Message(hosts),
            Take::TransferEncoding if hosts.is_empty() => return HttpParse::Unproved,
            Take::TransferEncoding => return HttpParse::Partial(hosts),
            Take::Other => break,
        }
    }
    HttpParse::Message(hosts)
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
    Complete { hosts: Vec<String>, next: usize },
    Incomplete,
    TransferEncoding,
    Other,
    Done,
}

enum LineKind {
    Request,
    Response { status: u16 },
}

fn take_message(payload: &[u8], end_of_stream: bool) -> Take {
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
        } else if eq_ignore_ascii_case(name, b"Content-Length") {
            content_length = parse_content_length(value);
        }
    }
    if transfer_encoding {
        return Take::TransferEncoding;
    }
    let header_end = offset;
    let body_need = match kind {
        LineKind::Request => content_length.unwrap_or(0),
        LineKind::Response { status }
            if (100..200).contains(&status) || status == 204 || status == 304 =>
        {
            0
        }
        LineKind::Response { .. } => match content_length {
            Some(n) => n,
            None if end_of_stream => (payload.len() - header_end) as u64,
            None => return Take::Incomplete,
        },
    };
    let available = (payload.len() - header_end) as u64;
    if available < body_need {
        return Take::Incomplete;
    }
    Take::Complete {
        hosts,
        next: header_end + body_need as usize,
    }
}

fn take_line(bytes: &[u8]) -> Option<(&[u8], usize)> {
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            return Some((&bytes[..i], i + 1));
        }
        if bytes[i] == b'\r' {
            let next = if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                i + 2
            } else {
                i + 1
            };
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
    if is_request_method(&data[..method_len]) {
        Some(LineKind::Request)
    } else {
        None
    }
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
    if rest.len() < 3 {
        return 0;
    }
    let a = rest[0];
    let b = rest[1];
    let c = rest[2];
    if !a.is_ascii_digit() || !b.is_ascii_digit() || !c.is_ascii_digit() {
        return 0;
    }
    u16::from(a - b'0') * 100 + u16::from(b - b'0') * 10 + u16::from(c - b'0')
}

fn valid_header_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || TOKEN.contains(b))
}

fn parse_content_length(value: &[u8]) -> Option<u64> {
    let mut i = 0;
    while i < value.len() && (value[i] == b' ' || value[i] == b'\t') {
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
    while i < value.len() {
        if value[i] != b' ' && value[i] != b'\t' {
            return None;
        }
        i += 1;
    }
    if n < 0 {
        None
    } else {
        Some(n as u64)
    }
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
        HttpParse::Message(hosts.iter().map(|h| (*h).to_string()).collect())
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

    #[test]
    fn junk_after_get_keeps_the_first_host() {
        assert_eq!(
            parse_http(b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\njunk", false),
            msg(&["a.example"])
        );
    }

    #[test]
    fn response_204_prints_host() {
        assert_eq!(
            parse_http(b"HTTP/1.1 204 No Content\r\nHost: x\r\n\r\n", false),
            msg(&["x"])
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
            msg(&["x"])
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
        assert_eq!(
            parse_http(b"GET / HTTP/1.1\rHost: cr.example\r\r", false),
            msg(&["cr.example"])
        );
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
    }

    #[test]
    fn icy_is_a_response() {
        assert_eq!(
            parse_http(b"ICY 200 OK\r\nHost: icy.example\r\n\r\n", true),
            msg(&["icy.example"])
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
}
