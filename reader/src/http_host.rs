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
    /// Complete CONNECT request in this payload.
    pub connect: bool,
    /// CONNECT URI port after the first `:`, matching tshark 4.6.9
    /// `wmem_strsplit(..., ":", 2)` then `strtol`. `None` when the URI
    /// has no colon.
    pub connect_port: Option<u32>,
    /// Complete 200 response in this payload.
    pub status_200: bool,
    /// Complete 2xx response in this payload. tshark 4.6.9
    /// `http_conversation_is_connect` uses `200 <= code < 300`.
    pub status_2xx: bool,
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
    parse_http_pending(payload, end_of_stream, false, false)
}

/// `sstp_pending` is a prior complete `SSTP_DUPLEX_POST` on this TCP
/// conversation. `connect_pending` is a prior complete CONNECT.
/// tshark 4.6.9 then sets `try_desegment_body = false` for a 2xx, so
/// complete headers are a complete response.
pub fn parse_http_pending(
    payload: &[u8],
    end_of_stream: bool,
    sstp_pending: bool,
    connect_pending: bool,
) -> HttpParse {
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
        let connect = connect_pending || proved.connect;
        match take_message(&payload[offset..], end_of_stream, sstp, connect) {
            Take::Done => break,
            Take::Complete {
                hosts: found,
                next,
                sstp_duplex_post,
                connect,
                connect_port,
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
                if connect {
                    proved.connect = true;
                    proved.connect_port = connect_port;
                }
                if http2 {
                    proved.http2 = true;
                }
                if let Some(status) = status {
                    proved.has_response = true;
                    if status >= 200 {
                        proved.has_final_response = true;
                    }
                    if (200..300).contains(&status) {
                        proved.status_2xx = true;
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
        connect: bool,
        connect_port: Option<u32>,
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
        connect: bool,
    },
    /// tshark 4.6.9 `MEDIA_CONTAINER_HTTP_NOTIFICATION`.
    Notification,
    Response {
        status: u16,
    },
}

fn take_message(
    payload: &[u8],
    end_of_stream: bool,
    sstp_pending: bool,
    connect_pending: bool,
) -> Take {
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
    let mut after_no_colon_blank = None;
    loop {
        let Some((line, next)) = take_line(&payload[offset..]) else {
            return Take::Incomplete;
        };
        if line.is_empty() {
            offset += next;
            break;
        }
        if classify_line(line).is_some() {
            return Take::Incomplete;
        }
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            // tshark 4.6.9 `dissect_http_message` breaks when `memchr`
            // finds no colon; offset stays on this line. Leftover
            // starting here is Continuation. `req_resp_hdrs_do_reassembly`
            // still walks until the later blank and honors a
            // Content-Length or `Transfer-Encoding: chunked` after this
            // junk line. Until those body bytes exist, Host is not
            // emitted.
            let Some(reasm) = header_reassembly_after(&payload[offset + next..], content_length)
            else {
                return Take::Incomplete;
            };
            after_no_colon_blank = Some(reasm);
            break;
        };
        offset += next;
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
    let connect_2xx = matches!(
        kind,
        LineKind::Response { status } if connect_pending && (200..300).contains(&status)
    );
    // tshark 4.6.9 `try_desegment_body = false` for 1xx / 204 / 304
    // and for a 2xx to CONNECT or `SSTP_DUPLEX_POST`. Headers complete
    // means the message is complete, including Transfer-Encoding.
    let skip_body = sstp_2xx
        || connect_2xx
        || matches!(kind, LineKind::Response { status } if rfc_no_body(status));
    if transfer_encoding && !skip_body {
        return Take::TransferEncoding;
    }
    if let Some(reasm) = after_no_colon_blank {
        let try_desegment_body = !end_of_stream && !skip_body;
        if try_desegment_body {
            if reasm.chunked {
                if !chunked_body_complete(reasm.after_blank) {
                    return Take::Incomplete;
                }
            } else if let Some(n) = reasm.content_length {
                if (reasm.after_blank.len() as u64) < n {
                    return Take::Incomplete;
                }
            }
        }
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
        LineKind::Response { .. } if sstp_2xx || connect_2xx => {
            match (transfer_encoding, content_length) {
                (false, Some(n)) => n.min(available),
                _ => available,
            }
        }
        LineKind::Response { .. } => match content_length {
            Some(n) => n,
            None if end_of_stream => available,
            None => return Take::Incomplete,
        },
    };
    if available < body_need {
        return Take::Incomplete;
    }
    let body_end = header_end + body_need as usize;
    let connect = matches!(kind, LineKind::Request { connect: true, .. });
    Take::Complete {
        hosts,
        next: skip + body_end,
        sstp_duplex_post: matches!(
            kind,
            LineKind::Request {
                sstp_duplex_post: true,
                ..
            }
        ),
        connect,
        connect_port: if connect {
            connect_uri_port(first)
        } else {
            None
        },
        status: match kind {
            LineKind::Response { status } => Some(status),
            LineKind::Request { .. } | LineKind::Notification => None,
        },
        upgrade,
        // tshark 4.6.9 `dissect_http_message` clips `datalen` to
        // Content-Length, then walks leftover as the next message.
        // A Content-Length *body* with leftover after it is not an
        // HTTP/2 preface. An unbounded body (NOTIFY, or a message
        // that consumes the rest of the payload) still is.
        http2: looks_like_http2_preface(&payload[body_end..])
            || (body_end == payload.len() && looks_like_http2_preface(&payload[header_end..])),
    }
}

/// Headers after a no-colon line, through the later blank, matching
/// tshark 4.6.9 `req_resp_hdrs_do_reassembly`. `None` when no blank is
/// present.
struct HeaderReassembly<'a> {
    after_blank: &'a [u8],
    content_length: Option<u64>,
    chunked: bool,
}

fn header_reassembly_after(
    bytes: &[u8],
    mut content_length: Option<u64>,
) -> Option<HeaderReassembly<'_>> {
    let mut offset = 0;
    let mut chunked = false;
    while let Some((line, next)) = take_line(&bytes[offset..]) {
        if line.is_empty() {
            return Some(HeaderReassembly {
                after_blank: &bytes[offset + next..],
                content_length,
                chunked,
            });
        }
        note_reassembly_header(line, &mut content_length, &mut chunked);
        offset += next;
    }
    None
}

/// tshark 4.6.9 first-byte C/T lines: `Content-Length:` and
/// `Transfer-Encoding: chunked`.
fn note_reassembly_header(line: &[u8], content_length: &mut Option<u64>, chunked: &mut bool) {
    if let Some(value) = line_prefix(line, b"Content-Length:") {
        if let Some(n) = parse_content_length(value) {
            *content_length = Some(n);
        }
    } else if let Some(value) = line_prefix(line, b"Transfer-Encoding:") {
        let mut rest = value;
        while matches!(rest.first().copied(), Some(b' ' | b'\t')) {
            rest = &rest[1..];
        }
        if starts_with_ignore_ascii_case(rest, b"chunked") {
            *chunked = true;
        }
    }
}

fn line_prefix<'a>(line: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if starts_with_ignore_ascii_case(line, prefix) {
        Some(&line[prefix.len()..])
    } else {
        None
    }
}

/// tshark 4.6.9 `req_resp_hdrs_do_reassembly` chunked loop. `false`
/// waits for more bytes. `true` is a last chunk, or a size parse that
/// gave up.
fn chunked_body_complete(bytes: &[u8]) -> bool {
    let mut offset = 0;
    loop {
        let Some((line, next)) = take_line(&bytes[offset..]) else {
            return false;
        };
        let Some(size) = parse_chunk_size(line) else {
            return true;
        };
        if size > 1u32 << 31 {
            return true;
        }
        let data = offset + next;
        if size == 0 {
            return take_line(&bytes[data..]).is_some();
        }
        let remaining = bytes.len().saturating_sub(data);
        if remaining <= size as usize {
            return false;
        }
        offset = data + size as usize + 2;
        if offset > bytes.len() {
            return false;
        }
    }
}

fn parse_chunk_size(line: &[u8]) -> Option<u32> {
    let end = line
        .iter()
        .position(|b| matches!(*b, b';' | b' ' | b'\t'))
        .unwrap_or(line.len());
    let hex = &line[..end];
    if hex.is_empty() {
        return None;
    }
    let mut n: u32 = 0;
    for &b in hex {
        let digit = match b {
            b'0'..=b'9' => u32::from(b - b'0'),
            b'a'..=b'f' => u32::from(b - b'a' + 10),
            b'A'..=b'F' => u32::from(b - b'A' + 10),
            _ => return None,
        };
        n = n.checked_mul(16)?.checked_add(digit)?;
    }
    Some(n)
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
            connect: method == b"CONNECT",
        })
    } else {
        None
    }
}

/// tshark 4.6.9 `http_payload_subdissector`: `wmem_strsplit(uri, ":", 2)`
/// then `strtol` on the second token. `None` when the URI has no colon.
fn connect_uri_port(line: &[u8]) -> Option<u32> {
    let sp = line.iter().position(|b| *b == b' ')?;
    let rest = &line[sp + 1..];
    let uri_end = rest.iter().position(|b| *b == b' ').unwrap_or(rest.len());
    let uri = &rest[..uri_end];
    let colon = uri.iter().position(|b| *b == b':')?;
    Some(parse_strtol_u32(&uri[colon + 1..]))
}

/// C `strtol(..., 10)` for a CONNECT URI port: leading `isspace`,
/// optional sign, then digits.
fn parse_strtol_u32(bytes: &[u8]) -> u32 {
    let mut i = 0;
    while i < bytes.len() && strtoll_leading_space(bytes[i]) {
        i += 1;
    }
    let mut neg = false;
    if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
        neg = bytes[i] == b'-';
        i += 1;
    }
    let mut n: i64 = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        n = n
            .saturating_mul(10)
            .saturating_add(i64::from(bytes[i] - b'0'));
        i += 1;
    }
    if neg || n < 0 {
        0
    } else if n > i64::from(u32::MAX) {
        u32::MAX
    } else {
        n as u32
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
/// C string. Leading skip follows `g_ascii_strtoll` (VT included). After
/// the digits, NUL or GLib 2.80 `g_ascii_isspace` is accepted; VT `0x0b`
/// is not space on this tshark, so `4\x0b` is an invalid length.
fn parse_content_length(value: &[u8]) -> Option<u64> {
    let end = value.iter().position(|b| *b == 0).unwrap_or(value.len());
    let value = &value[..end];
    let mut i = 0;
    while i < value.len() && strtoll_leading_space(value[i]) {
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

/// GLib 2.80 `g_ascii_isspace` on tshark 4.6.9 (`v4.6.9-0-g2d548b197c75`):
/// SP, HT, LF, FF, CR. VT `0x0b` is not space.
fn ascii_isspace(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0c | b'\r')
}

/// `g_ascii_strtoll` / C `strtol` still skip leading VT.
fn strtoll_leading_space(b: u8) -> bool {
    ascii_isspace(b) || b == 0x0b
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
            status_2xx: (200..300).contains(&status),
            has_response: true,
            has_final_response: status >= 200,
            switching_upgrade,
            ..HttpProved::default()
        })
    }

    fn message(payload: &[u8]) -> HttpProved {
        match parse_http(payload, false) {
            HttpParse::Message(proved) => proved,
            other => panic!("{other:?}"),
        }
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

    #[test]
    fn connect_and_options() {
        let proved = message(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
        assert_eq!(proved.hosts, ["example.com:443"]);
        assert!(proved.connect);
        assert_eq!(proved.connect_port, Some(443));
        let proved = message(b"CONNECT example.com:22 HTTP/1.1\r\nHost: example.com:22\r\n\r\n");
        assert_eq!(proved.hosts, ["example.com:22"]);
        assert!(proved.connect);
        assert_eq!(proved.connect_port, Some(22));
        let proved = message(b"CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assert_eq!(proved.hosts, ["example.com"]);
        assert!(proved.connect);
        assert_eq!(proved.connect_port, None);
        assert_eq!(
            parse_http(b"OPTIONS * HTTP/1.1\r\nHost: opt.example\r\n\r\n", false),
            msg(&["opt.example"])
        );
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
}
