//! One-packet TLS ClientHello SNI. Split records, TCP reassembly, QUIC,
//! and DTLS are out of scope and counted when they look like a handshake.

/// A TCP payload that may carry a ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsParse {
    /// Complete ClientHello(s). Names follow tshark's field order.
    ClientHello(Vec<String>),
    /// Handshake bytes that this reader cannot prove.
    Unproved,
    /// Not a TLS handshake.
    Other,
}

const CONTENT_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const HANDSHAKE_SERVER_HELLO: u8 = 2;
const EXT_SERVER_NAME: u16 = 0;
const EXT_EARLY_DATA: u16 = 42;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_TICKET_EARLY_DATA_INFO: u16 = 46;
const RECORD_HEADER: usize = 5;
const TLS_MAX_RECORD: usize = 16384 + 2048;

/// tshark 4.6.9 `SslSession.version` as it affects later records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsSession {
    /// `SSL_VER_UNKNOWN`. Later records need `ssl_looks_like_sslv3`.
    #[default]
    Unknown,
    /// SSLv3 / TLS 1.0–1.2 / TLCP. `dissect_ssl3_record` without `ssl_looks_like_sslv3`.
    Sticky,
    /// TLS 1.3. `dissect_ssl`'s default arm still needs `ssl_looks_like_sslv3`,
    /// and record-level `ssl_try_set_version` does not run.
    Tls13,
}

impl TlsSession {
    fn skips_looks_like(self) -> bool {
        matches!(self, Self::Sticky)
    }
}

/// Result of one TCP payload, plus whether tshark would keep this conversation
/// as TLS and the session version for later records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsOutcome {
    pub kind: TlsParse,
    pub claimed: bool,
    pub session: TlsSession,
}

/// Parse SNI from one TCP payload on an unnamed port. The first record must
/// pass tshark 4.6.9 `is_sslv3_or_tls`.
pub fn parse_tcp_tls(payload: &[u8]) -> TlsParse {
    parse_tls(payload, TlsSession::Unknown, true).kind
}

/// Port 443 (and the other `tls` ports) force the TLS dissector. An unknown
/// session uses `ssl_looks_like_sslv3`; after an authoritative SSLv3/TLS 1.0–1.2
/// or TLCP record, later records follow `dissect_ssl3_record`. TLS 1.3 stays
/// on the default arm.
pub fn parse_tcp_tls_on_tls_port(payload: &[u8]) -> TlsParse {
    parse_tls(payload, TlsSession::Unknown, false).kind
}

/// `heuristic` is tshark's first-packet `is_sslv3_or_tls` gate. `session` is
/// `SslSession.version`: unknown, sticky pre-1.3, or TLS 1.3.
pub fn parse_tls(payload: &[u8], session: TlsSession, heuristic: bool) -> TlsOutcome {
    if heuristic && !is_sslv3_or_tls(payload) {
        return TlsOutcome {
            kind: TlsParse::Other,
            claimed: false,
            session,
        };
    }
    let mut session = session;
    TlsOutcome {
        kind: parse_records(payload, &mut session),
        claimed: true,
        session,
    }
}

fn parse_records(payload: &[u8], session: &mut TlsSession) -> TlsParse {
    if payload.is_empty() {
        return TlsParse::Other;
    }
    let mut offset = 0;
    let mut names = Vec::new();
    let mut saw_hello = false;
    let mut unproved = false;
    while offset < payload.len() {
        match take_record(payload, offset, *session) {
            Record::Done => break,
            Record::Other {
                next,
                version,
                content,
            } => {
                // tshark 4.6.9 ssl_try_set_version reads the first body byte.
                // A length-0 record at the end of the payload throws (Info
                // [Malformed Packet]), so the session stays unknown. A following
                // byte in this payload is readable, so an in-record GREASE hello
                // still prints.
                if next > offset + RECORD_HEADER || next < payload.len() {
                    apply_session_version(session, content, version, None);
                }
                offset = next;
            }
            Record::Unproved => {
                unproved = true;
                break;
            }
            Record::Handshake {
                body,
                next,
                version,
            } => {
                apply_session_version(session, CONTENT_HANDSHAKE, version, Some(body));
                match parse_handshake_messages(body) {
                    Hello::None => {}
                    Hello::Names(found) => {
                        saw_hello = true;
                        names.extend(found);
                    }
                    Hello::Unproved => {
                        unproved = true;
                        break;
                    }
                }
                offset = next;
            }
        }
    }
    if saw_hello {
        TlsParse::ClientHello(names)
    } else if unproved {
        TlsParse::Unproved
    } else {
        TlsParse::Other
    }
}

/// True when the first bytes look like a TLS handshake record.
pub fn looks_like_tls_handshake(payload: &[u8]) -> bool {
    tls_record_header(payload)
        .map(|(content, _, _)| content == CONTENT_HANDSHAKE)
        .unwrap_or(false)
}

/// DTLS 1.0/1.2/1.3 handshake record at the start of a UDP datagram.
pub fn looks_like_dtls_handshake(payload: &[u8]) -> bool {
    if payload.len() < 13 {
        return false;
    }
    if payload[0] != CONTENT_HANDSHAKE {
        return false;
    }
    let version = u16::from_be_bytes([payload[1], payload[2]]);
    matches!(version, 0xfeff | 0xfefd | 0xfefc)
}

/// QUIC Initial long header, including a coalesced Initial after another
/// long-header packet.
pub fn looks_like_quic_initial(payload: &[u8]) -> bool {
    if quic_initial_at(payload) {
        return true;
    }
    match skip_quic_long(payload) {
        Some(rest) if !rest.is_empty() => quic_initial_at(rest),
        _ => false,
    }
}

enum Record<'a> {
    Handshake {
        body: &'a [u8],
        next: usize,
        version: u16,
    },
    Other {
        next: usize,
        version: u16,
        content: u8,
    },
    Unproved,
    Done,
}

enum Hello {
    Names(Vec<String>),
    None,
    Unproved,
}

fn take_record(payload: &[u8], offset: usize, session: TlsSession) -> Record<'_> {
    let rest = &payload[offset..];
    if rest.is_empty() {
        return Record::Done;
    }
    let Some((content, version, length)) = tls_record_header(rest) else {
        return if rest[0] == CONTENT_HANDSHAKE {
            Record::Unproved
        } else {
            Record::Done
        };
    };
    if !session.skips_looks_like() && !is_record_version(version) {
        return Record::Done;
    }
    if length >= TLS_MAX_RECORD {
        return if content == CONTENT_HANDSHAKE {
            Record::Unproved
        } else {
            Record::Done
        };
    }
    // tshark 4.6.9 dissect_ssl3_record consumes a length-0 CCS/alert/app-data/
    // heartbeat and continues. An empty handshake is still Unproved: a following
    // complete ClientHello in this payload is a counted miss.
    if length == 0 {
        return if content == CONTENT_HANDSHAKE {
            Record::Unproved
        } else {
            Record::Other {
                next: offset + RECORD_HEADER,
                version,
                content,
            }
        };
    }
    let start = offset + RECORD_HEADER;
    let end = start.saturating_add(length);
    if end > payload.len() {
        return if content == CONTENT_HANDSHAKE {
            Record::Unproved
        } else {
            Record::Done
        };
    }
    let body = &payload[start..end];
    if content == CONTENT_HANDSHAKE {
        Record::Handshake {
            body,
            next: end,
            version,
        }
    } else {
        Record::Other {
            next: end,
            version,
            content,
        }
    }
}

fn tls_record_header(payload: &[u8]) -> Option<(u8, u16, usize)> {
    if payload.len() < RECORD_HEADER {
        return None;
    }
    let content = payload[0];
    if !is_content_type(content) {
        return None;
    }
    let version = u16::from_be_bytes([payload[1], payload[2]]);
    let length = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    Some((content, version, length))
}

fn is_content_type(content: u8) -> bool {
    matches!(content, 20..=26)
}

/// tshark 4.6.9 `ssl_looks_like_sslv3`: SSLv3, TLS 1.0–1.3, and TLCP.
/// GREASE, DTLS, TLS 1.3 drafts, and SSL 2.0 are continuation data.
fn is_record_version(version: u16) -> bool {
    matches!(version, 0x0300 | 0x0301 | 0x0302 | 0x0303 | 0x0304 | 0x0101)
}

/// Versions that `dissect_ssl` keeps in the SSLv3/TLS 1.0–1.2/TLCP switch,
/// so a later record is fed to `dissect_ssl3_record` without `ssl_looks_like_sslv3`.
fn is_sticky_version(version: u16) -> bool {
    matches!(version, 0x0300 | 0x0301 | 0x0302 | 0x0303 | 0x0101)
}

/// tshark 4.6.9 `ssl_is_authoritative_version_message`: a valid handshake
/// except ClientHello, or any other valid content type.
fn is_authoritative(content: u8, handshake_type: Option<u8>) -> bool {
    if content == CONTENT_HANDSHAKE {
        handshake_type
            .is_some_and(|hs| is_valid_tls_handshake_type(hs) && hs != HANDSHAKE_CLIENT_HELLO)
    } else {
        is_content_type(content)
    }
}

/// tshark 4.6.9 `tls_try_get_version` mapped onto [`TlsSession`].
fn session_from_version(version: u16) -> Option<TlsSession> {
    let version = normalize_tls_version(version);
    if is_sticky_version(version) {
        Some(TlsSession::Sticky)
    } else if version == 0x0304 {
        Some(TlsSession::Tls13)
    } else {
        None
    }
}

/// Record-level `ssl_try_set_version` only when `SSL_VER_UNKNOWN`, then
/// ServerHello `tls_scan_server_hello` (always), then ClientHello `early_data`.
fn apply_session_version(
    session: &mut TlsSession,
    content: u8,
    record_version: u16,
    handshake: Option<&[u8]>,
) {
    let hs_type = handshake.and_then(|body| body.first().copied());
    if *session == TlsSession::Unknown && is_authoritative(content, hs_type) {
        if let Some(next) = session_from_version(record_version) {
            *session = next;
        }
    }
    if let Some(version) = server_hello_session_version(handshake) {
        if let Some(next) = session_from_version(version) {
            *session = next;
        }
    }
    if handshake_has_early_data(handshake) {
        *session = TlsSession::Tls13;
    }
}

/// tshark 4.6.9 ClientHello `early_data` (or draft `ticket_early_data_info`)
/// forces `session->version = TLSV1DOT3_VERSION`.
fn handshake_has_early_data(handshake: Option<&[u8]>) -> bool {
    let Some(mut body) = handshake else {
        return false;
    };
    while body.len() >= 4 {
        let msg_type = body[0];
        let msg_len = u24(&body[1..4]);
        let start: usize = 4;
        let end = start.saturating_add(msg_len);
        if end > body.len() {
            return false;
        }
        if msg_type == HANDSHAKE_CLIENT_HELLO && client_hello_has_early_data(&body[start..end]) {
            return true;
        }
        body = &body[end..];
    }
    false
}

fn client_hello_has_early_data(hello: &[u8]) -> bool {
    let Some(exts) = client_hello_extensions(hello) else {
        return false;
    };
    let mut offset = 0;
    while offset + 4 <= exts.len() {
        let typ = u16::from_be_bytes([exts[offset], exts[offset + 1]]);
        let len = u16::from_be_bytes([exts[offset + 2], exts[offset + 3]]) as usize;
        offset += 4;
        let end = match offset.checked_add(len) {
            Some(end) if end <= exts.len() => end,
            _ => return false,
        };
        if typ == EXT_EARLY_DATA || typ == EXT_TICKET_EARLY_DATA_INFO {
            return true;
        }
        offset = end;
    }
    false
}

fn client_hello_extensions(hello: &[u8]) -> Option<&[u8]> {
    if hello.len() < 34 {
        return None;
    }
    let mut offset = 34;
    let sid_len = *hello.get(offset)? as usize;
    offset += 1;
    offset = offset.checked_add(sid_len)?;
    if offset + 2 > hello.len() {
        return None;
    }
    let cipher_len = u16::from_be_bytes([hello[offset], hello[offset + 1]]) as usize;
    offset += 2;
    offset = offset.checked_add(cipher_len)?;
    let comp_len = *hello.get(offset)? as usize;
    offset += 1;
    offset = offset.checked_add(comp_len)?;
    if offset == hello.len() {
        return Some(&[]);
    }
    if offset + 2 > hello.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([hello[offset], hello[offset + 1]]) as usize;
    offset += 2;
    let ext_end = offset.checked_add(ext_len)?;
    if ext_end > hello.len() {
        return None;
    }
    Some(&hello[offset..ext_end])
}

/// tshark 4.6.9 `tls_try_get_version` for TLS: drafts become 0x0304.
fn normalize_tls_version(version: u16) -> u16 {
    if (version & 0xff00) == 0x7f00 || version == 0xfb17 || version == 0xfb1a {
        0x0304
    } else {
        version
    }
}

/// Scanned ServerHello version when tshark calls `ssl_try_set_version` again.
fn server_hello_session_version(handshake: Option<&[u8]>) -> Option<u16> {
    let body = handshake?;
    if body.first() != Some(&HANDSHAKE_SERVER_HELLO) || body.len() < 4 {
        return None;
    }
    let msg_len = u24(&body[1..4]);
    if msg_len <= 2 {
        return None;
    }
    let end = 4 + msg_len;
    if end > body.len() {
        return None;
    }
    Some(scan_server_hello_version(&body[4..end]))
}

/// tshark 4.6.9 `tls_scan_server_hello`: legacy_version, then
/// `supported_versions` when legacy is TLS 1.2 or DTLS 1.2.
fn scan_server_hello_version(hello: &[u8]) -> u16 {
    let mut version = u16::from_be_bytes([hello[0], hello[1]]);
    if !matches!(version, 0x0303 | 0xfefd) || hello.len() < 46 {
        return version;
    }
    let mut offset = 34;
    let sid_len = hello[offset] as usize;
    offset += 1;
    if hello.len().saturating_sub(offset) < sid_len + 5 {
        return version;
    }
    offset += sid_len + 5;
    while hello.len().saturating_sub(offset) >= 6 {
        let ext_type = u16::from_be_bytes([hello[offset], hello[offset + 1]]);
        let ext_len = u16::from_be_bytes([hello[offset + 2], hello[offset + 3]]) as usize;
        if hello.len().saturating_sub(offset) < 4 + ext_len {
            break;
        }
        if ext_type == EXT_SUPPORTED_VERSIONS {
            if ext_len == 2 {
                version = u16::from_be_bytes([hello[offset + 4], hello[offset + 5]]);
            }
            return version;
        }
        offset += 4 + ext_len;
    }
    version
}

/// tshark 4.6.9 `ssl_is_valid_handshake_type` with `is_dtls == false`.
fn is_valid_tls_handshake_type(hs_type: u8) -> bool {
    matches!(hs_type, 0 | 1 | 2 | 4..=6 | 8 | 11..=16 | 20..=25 | 67)
}

/// tshark 4.6.9 `is_sslv3_or_tls`: Handshake or Application Data, SSLv3/TLS 1.0–1.2
/// or TLCP, nonzero length below `TLS_MAX_RECORD_LENGTH+2048`. TLS 1.3 (0x0304)
/// and CCS/alert/heartbeat are not TLS on an unnamed port.
fn is_sslv3_or_tls(payload: &[u8]) -> bool {
    let Some((content, version, length)) = tls_record_header(payload) else {
        return false;
    };
    if content != CONTENT_HANDSHAKE && content != 0x17 {
        return false;
    }
    if !is_sticky_version(version) {
        return false;
    }
    length != 0 && length < TLS_MAX_RECORD
}

/// Bytes still needed to finish a TLS record that starts in `payload`.
///
/// tshark 4.6.9 `dissect_ssl3_record` desegments any incomplete record
/// (CCS/alert/handshake/app-data/heartbeat). A complete record whose handshake
/// is shorter than 4 bytes, or whose u24 length overruns, is also buffered.
/// The next in-order payload on that flow is continuation, not a new
/// ClientHello.
pub fn truncated_handshake_need(payload: &[u8]) -> Option<usize> {
    truncated_handshake_need_known(payload, TlsSession::Unknown)
}

/// Like [`truncated_handshake_need`], but a sticky session accepts any record
/// version the way `dissect_ssl3_record` does. Complete records, including
/// length-0 CCS/alert/app-data/heartbeat, are skipped so a following truncated
/// record is buffered, matching tshark 4.6.9 `dissect_ssl`.
pub fn truncated_handshake_need_known(payload: &[u8], session: TlsSession) -> Option<usize> {
    record_tail(payload, session).map(|tail| tail.more)
}

/// Bytes of `payload` from the incomplete record onward.
///
/// tshark 4.6.9 sets `desegment_offset` at that record, so a completing segment
/// is parsed without the ClientHellos that already finished in the prefix.
pub fn truncated_handshake_prefix(payload: &[u8], session: TlsSession) -> Option<&[u8]> {
    let tail = record_tail(payload, session)?;
    Some(&payload[tail.start..])
}

struct RecordTail {
    start: usize,
    more: usize,
}

fn record_tail(payload: &[u8], mut session: TlsSession) -> Option<RecordTail> {
    let mut offset = 0;
    while offset < payload.len() {
        let rest = &payload[offset..];
        if rest.len() < RECORD_HEADER {
            return is_content_type(rest[0]).then_some(RecordTail {
                start: offset,
                more: RECORD_HEADER - rest.len(),
            });
        }
        let (content, version, length) = tls_record_header(rest)?;
        if !session.skips_looks_like() && !is_record_version(version) {
            return None;
        }
        if length >= TLS_MAX_RECORD {
            return None;
        }
        if length == 0 {
            apply_session_version(&mut session, content, version, None);
            offset += RECORD_HEADER;
            continue;
        }
        let need = RECORD_HEADER + length;
        if need > rest.len() {
            return Some(RecordTail {
                start: offset,
                more: need - rest.len(),
            });
        }
        let body = &rest[RECORD_HEADER..need];
        if content == CONTENT_HANDSHAKE {
            if let Some(more) = handshake_need(body) {
                return Some(RecordTail {
                    start: offset,
                    more,
                });
            }
        }
        apply_session_version(
            &mut session,
            content,
            version,
            (content == CONTENT_HANDSHAKE).then_some(body),
        );
        offset += need;
    }
    None
}

/// Missing handshake bytes inside a complete record. A 4-byte header whose
/// u24 length fits is done; tshark does not desegment that message.
fn handshake_need(body: &[u8]) -> Option<usize> {
    let mut offset = 0;
    while offset < body.len() {
        let left = body.len() - offset;
        if left < 4 {
            return Some(4 - left);
        }
        let msg_len = u24(&body[offset + 1..offset + 4]);
        let end = (offset + 4).saturating_add(msg_len);
        if end > body.len() {
            return Some(end - body.len());
        }
        offset = end;
    }
    None
}

fn parse_handshake_messages(body: &[u8]) -> Hello {
    if body.is_empty() {
        return Hello::Unproved;
    }
    let mut offset = 0;
    let mut names = Vec::new();
    let mut saw_hello = false;
    while offset < body.len() {
        if body.len() - offset < 4 {
            return Hello::Unproved;
        }
        let msg_type = body[offset];
        let msg_len = u24(&body[offset + 1..offset + 4]);
        let start = offset + 4;
        let end = start.saturating_add(msg_len);
        if end > body.len() {
            return Hello::Unproved;
        }
        if msg_type == HANDSHAKE_CLIENT_HELLO {
            match parse_client_hello(&body[start..end]) {
                Some(found) => {
                    saw_hello = true;
                    names.extend(found);
                }
                None => return Hello::Unproved,
            }
        }
        offset = end;
    }
    if saw_hello {
        Hello::Names(names)
    } else {
        Hello::None
    }
}

fn parse_client_hello(body: &[u8]) -> Option<Vec<String>> {
    if body.len() < 34 {
        return None;
    }
    let mut offset = 34;
    let sid_len = *body.get(offset)? as usize;
    offset += 1;
    offset = offset.checked_add(sid_len)?;
    if offset + 2 > body.len() {
        return None;
    }
    let cipher_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
    offset += 2;
    offset = offset.checked_add(cipher_len)?;
    let comp_len = *body.get(offset)? as usize;
    offset += 1;
    offset = offset.checked_add(comp_len)?;
    if offset == body.len() {
        return Some(Vec::new());
    }
    if offset + 2 > body.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
    offset += 2;
    let ext_end = offset.checked_add(ext_len)?;
    if ext_end > body.len() {
        return None;
    }
    parse_extensions(&body[offset..ext_end])
}

fn parse_extensions(exts: &[u8]) -> Option<Vec<String>> {
    let mut offset = 0;
    let mut names = Vec::new();
    while offset < exts.len() {
        if offset + 4 > exts.len() {
            return None;
        }
        let typ = u16::from_be_bytes([exts[offset], exts[offset + 1]]);
        let len = u16::from_be_bytes([exts[offset + 2], exts[offset + 3]]) as usize;
        offset += 4;
        let end = offset.checked_add(len)?;
        if end > exts.len() {
            return None;
        }
        if typ == EXT_SERVER_NAME {
            names.extend(parse_server_name(&exts[offset..end])?);
        }
        offset = end;
    }
    Some(names)
}

fn parse_server_name(data: &[u8]) -> Option<Vec<String>> {
    if data.is_empty() {
        return Some(Vec::new());
    }
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if list_len < 1 || 2 + list_len > data.len() {
        return None;
    }
    let list = &data[2..2 + list_len];
    let mut offset = 0;
    let mut names = Vec::new();
    while offset < list.len() {
        offset += 1; // name type; tshark prints every ServerName, not only host_name
        if offset + 2 > list.len() {
            return None;
        }
        let name_len = u16::from_be_bytes([list[offset], list[offset + 1]]) as usize;
        offset += 2;
        if name_len < 1 || offset + name_len > list.len() {
            return None;
        }
        let name = &list[offset..offset + name_len];
        offset += name_len;
        names.push(ascii_name(name));
    }
    Some(names)
}

/// tshark 4.6.9 `ENC_ASCII` stops at the first NUL and emits a UTF-8
/// replacement for any non-ASCII byte.
fn ascii_name(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| if b < 0x80 { char::from(b) } else { '\u{FFFD}' })
        .collect()
}

fn u24(bytes: &[u8]) -> usize {
    ((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize
}

fn quic_initial_at(bytes: &[u8]) -> bool {
    if bytes.len() < 6 {
        return false;
    }
    let first = bytes[0];
    if first & 0xc0 != 0xc0 {
        return false;
    }
    if (first >> 4) & 0x03 != 0 {
        return false;
    }
    let version = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
    if version == 0 {
        return false;
    }
    let dcid_len = bytes[5] as usize;
    if dcid_len > 20 || bytes.len() < 7 + dcid_len {
        return false;
    }
    let scid_len = bytes[6 + dcid_len] as usize;
    scid_len <= 20 && bytes.len() >= 7 + dcid_len + scid_len
}

fn skip_quic_long(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.len() < 6 {
        return None;
    }
    let first = bytes[0];
    if first & 0xc0 != 0xc0 {
        return None;
    }
    let dcid_len = bytes[5] as usize;
    if dcid_len > 20 || bytes.len() < 7 + dcid_len {
        return None;
    }
    let scid_len = bytes[6 + dcid_len] as usize;
    let mut offset = 7 + dcid_len + scid_len;
    if scid_len > 20 || offset > bytes.len() {
        return None;
    }
    let ty = (first >> 4) & 0x03;
    if ty == 0 {
        let (token_len, n) = quic_varint(&bytes[offset..])?;
        offset = offset.checked_add(n)?.checked_add(token_len)?;
    }
    let (packet_len, n) = quic_varint(bytes.get(offset..)?)?;
    offset = offset.checked_add(n)?.checked_add(packet_len)?;
    bytes.get(offset..)
}

fn quic_varint(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.first()?;
    let n = 1usize << (first >> 6);
    if bytes.len() < n {
        return None;
    }
    let mut value: u64 = (first & 0x3f) as u64;
    for b in &bytes[1..n] {
        value = (value << 8) | u64::from(*b);
    }
    Some((usize::try_from(value).ok()?, n))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(content: u8, version: u16, body: &[u8]) -> Vec<u8> {
        let mut out = vec![content];
        out.extend_from_slice(&version.to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn handshake(msg_type: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![msg_type, 0, 0, 0];
        let len = body.len() as u32;
        out[1] = (len >> 16) as u8;
        out[2] = (len >> 8) as u8;
        out[3] = len as u8;
        out.extend_from_slice(body);
        out
    }

    fn client_hello(sni: Option<&str>) -> Vec<u8> {
        client_hello_bytes(sni.map(str::as_bytes), 0x0301)
    }

    fn client_hello_bytes(sni: Option<&[u8]>, version: u16) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x00, 0x2f]);
        body.extend_from_slice(&[1, 0]);
        match sni {
            None => {
                body.extend_from_slice(&[0, 0]);
            }
            Some(host) => {
                let entry_len = 1 + 2 + host.len();
                let list_len = entry_len;
                let sni_data_len = 2 + list_len;
                let ext_len = 4 + sni_data_len;
                body.extend_from_slice(&(ext_len as u16).to_be_bytes());
                body.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
                body.extend_from_slice(&(sni_data_len as u16).to_be_bytes());
                body.extend_from_slice(&(list_len as u16).to_be_bytes());
                body.push(0);
                body.extend_from_slice(&(host.len() as u16).to_be_bytes());
                body.extend_from_slice(host);
            }
        }
        record(
            CONTENT_HANDSHAKE,
            version,
            &handshake(HANDSHAKE_CLIENT_HELLO, &body),
        )
    }

    fn ccs() -> Vec<u8> {
        record(0x14, 0x0303, &[0x01])
    }

    fn handshake_type_record(msg_type: u8) -> Vec<u8> {
        record(CONTENT_HANDSHAKE, 0x0303, &handshake(msg_type, &[]))
    }

    fn grease_hello() -> Vec<u8> {
        client_hello_bytes(Some(b"www.example.com"), 0x0a0a)
    }

    fn tls13_server_hello() -> Vec<u8> {
        let mut hello = Vec::from(0x0303u16.to_be_bytes());
        hello.extend_from_slice(&[0x22u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&[0x13, 0x01]);
        hello.push(0);
        hello.extend_from_slice(&[0x00, 0x06]);
        hello.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
        hello.extend_from_slice(&[0x00, 0x02, 0x03, 0x04]);
        record(
            CONTENT_HANDSHAKE,
            0x0303,
            &handshake(HANDSHAKE_SERVER_HELLO, &hello),
        )
    }

    fn alert() -> Vec<u8> {
        record(0x15, 0x0303, &[0x02, 0x28])
    }

    fn app_data() -> Vec<u8> {
        record(0x17, 0x0303, &[0x01])
    }

    fn empty_record(content: u8) -> Vec<u8> {
        vec![content, 0x03, 0x03, 0x00, 0x00]
    }

    fn heartbeat() -> Vec<u8> {
        record(0x18, 0x0303, &[0x01, 0x00, 0x00])
    }

    fn ccs_at(version: u16) -> Vec<u8> {
        record(0x14, version, &[0x01])
    }

    fn client_hello_early_data() -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x00, 0x2f]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&[0, 4, 0, 42, 0, 0]);
        record(
            CONTENT_HANDSHAKE,
            0x0301,
            &handshake(HANDSHAKE_CLIENT_HELLO, &body),
        )
    }

    fn tls13_middle_records() -> [(&'static str, Vec<u8>); 8] {
        [
            ("ccs", ccs()),
            ("alert", alert()),
            ("app-data", app_data()),
            ("heartbeat", heartbeat()),
            ("certificate", handshake_type_record(11)),
            ("encrypted-extensions", handshake_type_record(8)),
            ("finished", handshake_type_record(20)),
            ("hello-request", handshake_type_record(0)),
        ]
    }

    #[test]
    fn sni_name_is_proved() {
        assert_eq!(
            parse_tcp_tls(&client_hello(Some("www.example.com"))),
            TlsParse::ClientHello(vec!["www.example.com".to_string()])
        );
    }

    #[test]
    fn client_hello_without_sni_is_proved_empty() {
        assert_eq!(
            parse_tcp_tls(&client_hello(None)),
            TlsParse::ClientHello(Vec::new())
        );
    }

    #[test]
    fn http_on_443_is_other() {
        assert_eq!(parse_tcp_tls(b"GET / HTTP/1.1\r\n"), TlsParse::Other);
    }

    #[test]
    fn truncated_record_is_unproved() {
        let mut hello = client_hello(Some("a.example"));
        hello.truncate(hello.len() - 4);
        assert_eq!(parse_tcp_tls(&hello), TlsParse::Unproved);
    }

    #[test]
    fn handshake_past_record_is_unproved() {
        let mut hs = handshake(HANDSHAKE_CLIENT_HELLO, &[0u8; 64]);
        hs[1..4].copy_from_slice(&[0, 1, 0]);
        let rec = record(CONTENT_HANDSHAKE, 0x0303, &hs);
        assert_eq!(parse_tcp_tls(&rec), TlsParse::Unproved);
    }

    #[test]
    fn app_data_is_other() {
        let rec = record(0x17, 0x0303, &[1, 2, 3, 4]);
        assert_eq!(parse_tcp_tls(&rec), TlsParse::Other);
    }

    #[test]
    fn non_ascii_sni_byte_is_replacement() {
        assert_eq!(ascii_name(&[b'a', 0x80, b'b']), "a\u{FFFD}b");
    }

    #[test]
    fn unknown_name_type_still_prints() {
        let mut hello = client_hello(Some("fuzz.example"));
        let idx = hello.len() - "fuzz.example".len() - 3;
        hello[idx] = 185;
        assert_eq!(
            parse_tcp_tls_on_tls_port(&hello),
            TlsParse::ClientHello(vec!["fuzz.example".to_string()])
        );
    }

    #[test]
    fn unknown_record_version_is_other() {
        let mut hello = client_hello(Some("www.example.com"));
        hello[1] = 0x03;
        hello[2] = 0x10;
        assert_eq!(parse_tcp_tls_on_tls_port(&hello), TlsParse::Other);
    }

    #[test]
    fn ssl_looks_like_sslv3_rejects_grease_dtls_drafts_and_ssl2() {
        for version in [
            0x0a0au16, 0x0002, 0x0100, 0x7f1c, 0xfb17, 0xfeff, 0xfefd, 0xfefc,
        ] {
            let mut hello = client_hello(Some("www.example.com"));
            hello[1..3].copy_from_slice(&version.to_be_bytes());
            assert_eq!(
                parse_tcp_tls_on_tls_port(&hello),
                TlsParse::Other,
                "{version:#06x}"
            );
        }
    }

    #[test]
    fn truncated_handshake_need_is_the_missing_record_bytes() {
        let hello = client_hello(Some("www.example.com"));
        let cut = 40;
        assert!(hello.len() > cut);
        assert_eq!(
            truncated_handshake_need(&hello[..cut]),
            Some(hello.len() - cut)
        );
        assert_eq!(truncated_handshake_need(&hello), None);
        assert_eq!(truncated_handshake_need(&hello[..5]), Some(hello.len() - 5));
        for header_cut in 1..5 {
            assert_eq!(
                truncated_handshake_need(&hello[..header_cut]),
                Some(5 - header_cut),
                "cut {header_cut}"
            );
        }
    }

    #[test]
    fn truncated_handshake_need_covers_a_short_or_overrun_handshake() {
        for body in [vec![0x02], vec![0x02, 0x00], vec![0x02, 0x00, 0x00]] {
            let rec = record(CONTENT_HANDSHAKE, 0x0303, &body);
            assert_eq!(
                truncated_handshake_need(&rec),
                Some(4 - body.len()),
                "body {}",
                body.len()
            );
        }
        let overrun = record(CONTENT_HANDSHAKE, 0x0303, &[0x02, 0x00, 0x00, 0x14]);
        assert_eq!(truncated_handshake_need(&overrun), Some(20));
        let empty = handshake_type_record(2);
        assert_eq!(truncated_handshake_need(&empty), None);
        let mut payload = empty;
        payload.extend_from_slice(&grease_hello());
        assert_eq!(truncated_handshake_need(&payload), None);
    }

    #[test]
    fn unnamed_port_rejects_tls13_record_version() {
        let hello = client_hello_bytes(Some(b"www.example.com"), 0x0304);
        assert_eq!(parse_tcp_tls(&hello), TlsParse::Other);
        assert_eq!(
            parse_tcp_tls_on_tls_port(&hello),
            TlsParse::ClientHello(vec!["www.example.com".to_string()])
        );
    }

    #[test]
    fn unnamed_port_rejects_ccs_alert_heartbeat_prefix() {
        let hello = client_hello(Some("www.example.com"));
        let alert = record(0x15, 0x0303, &[0x02, 0x28]);
        let heartbeat = record(0x18, 0x0303, &[0x01, 0x00, 0x00]);
        for prefix in [ccs(), alert, heartbeat] {
            let mut payload = prefix;
            payload.extend_from_slice(&hello);
            assert_eq!(parse_tcp_tls(&payload), TlsParse::Other);
        }
        let mut app = record(0x17, 0x0303, &[1]);
        app.extend_from_slice(&hello);
        assert_eq!(
            parse_tcp_tls(&app),
            TlsParse::ClientHello(vec!["www.example.com".to_string()])
        );
    }

    #[test]
    fn sni_stops_at_first_nul() {
        assert_eq!(ascii_name(b"www\0.example"), "www");
        assert_eq!(ascii_name(b"www.example\0"), "www.example");
        assert_eq!(ascii_name(b"a\0b\0c"), "a");
        assert_eq!(
            parse_tcp_tls_on_tls_port(&client_hello_bytes(Some(b"www\0.example"), 0x0301)),
            TlsParse::ClientHello(vec!["www".to_string()])
        );
    }

    #[test]
    fn sticky_session_reads_grease_after_ccs() {
        let mut payload = ccs();
        payload.extend_from_slice(&grease_hello());
        assert_eq!(
            parse_tcp_tls_on_tls_port(&payload),
            TlsParse::ClientHello(vec!["www.example.com".to_string()])
        );
        assert_eq!(
            parse_tcp_tls(&payload),
            TlsParse::Other,
            "unnamed port CCS prefix is not is_sslv3_or_tls"
        );
        let lone = grease_hello();
        assert_eq!(parse_tcp_tls_on_tls_port(&lone), TlsParse::Other);
        let after = parse_tls(&lone, TlsSession::Sticky, false);
        assert_eq!(
            after.kind,
            TlsParse::ClientHello(vec!["www.example.com".to_string()])
        );
    }

    #[test]
    fn sticky_session_reads_grease_after_server_hello() {
        let mut payload = handshake_type_record(2);
        payload.extend_from_slice(&grease_hello());
        assert_eq!(
            parse_tcp_tls_on_tls_port(&payload),
            TlsParse::ClientHello(vec!["www.example.com".to_string()])
        );
        let first = parse_tls(&handshake_type_record(2), TlsSession::Unknown, false);
        assert_eq!(first.session, TlsSession::Sticky);
        let after = parse_tls(&grease_hello(), TlsSession::Sticky, false);
        assert_eq!(
            after.kind,
            TlsParse::ClientHello(vec!["www.example.com".to_string()])
        );
    }

    #[test]
    fn sticky_session_reads_grease_after_non_client_hello_handshake() {
        for msg_type in [0u8, 4, 11, 14, 20] {
            let mut payload = handshake_type_record(msg_type);
            payload.extend_from_slice(&grease_hello());
            assert_eq!(
                parse_tcp_tls_on_tls_port(&payload),
                TlsParse::ClientHello(vec!["www.example.com".to_string()]),
                "handshake type {msg_type}"
            );
        }
    }

    #[test]
    fn tls13_server_hello_does_not_stick_a_later_grease_hello() {
        let mut payload = tls13_server_hello();
        payload.extend_from_slice(&grease_hello());
        assert_eq!(parse_tcp_tls_on_tls_port(&payload), TlsParse::Other);
        let first = parse_tls(&tls13_server_hello(), TlsSession::Unknown, false);
        assert_eq!(first.session, TlsSession::Tls13);
        let after = parse_tls(&grease_hello(), first.session, false);
        assert_eq!(after.kind, TlsParse::Other);
    }

    #[test]
    fn tls13_server_hello_then_tls10_hello_prints_sni() {
        let hello = client_hello(Some("www.example.com"));
        let mut payload = tls13_server_hello();
        payload.extend_from_slice(&hello);
        assert_eq!(
            parse_tcp_tls_on_tls_port(&payload),
            TlsParse::ClientHello(vec!["www.example.com".to_string()])
        );
        let first = parse_tls(&tls13_server_hello(), TlsSession::Unknown, false);
        assert_eq!(first.session, TlsSession::Tls13);
        let after = parse_tls(&hello, first.session, false);
        assert_eq!(
            after.kind,
            TlsParse::ClientHello(vec!["www.example.com".to_string()])
        );
    }

    #[test]
    fn tls13_server_hello_unsticks_a_prior_session() {
        let after = parse_tls(&tls13_server_hello(), TlsSession::Sticky, false);
        assert_eq!(after.session, TlsSession::Tls13);
        let grease = parse_tls(&grease_hello(), after.session, false);
        assert_eq!(grease.kind, TlsParse::Other);
    }

    #[test]
    fn truncated_handshake_need_after_complete_prefix() {
        let hello = client_hello(Some("www.example.com"));
        let grease = grease_hello();
        let prefixes = [ccs(), alert(), app_data(), handshake_type_record(0)];
        for prefix in &prefixes {
            for cut in [1usize, 5, 7] {
                let mut payload = prefix.clone();
                payload.extend_from_slice(&hello[..cut]);
                assert!(
                    truncated_handshake_need_known(&payload, TlsSession::Unknown).is_some(),
                    "prefix {} cut {cut}",
                    prefix[0]
                );
            }
            let mut grease_payload = prefix.clone();
            grease_payload.extend_from_slice(&grease[..1]);
            assert!(
                truncated_handshake_need_known(&grease_payload, TlsSession::Unknown).is_some(),
                "grease after {}",
                prefix[0]
            );
        }
        assert_eq!(truncated_handshake_need(&hello[..1]), Some(4));
        assert_eq!(
            truncated_handshake_need(&hello[..40]),
            Some(hello.len() - 40)
        );
    }

    #[test]
    fn truncated_handshake_need_skips_empty_records() {
        let hello = client_hello(Some("www.example.com"));
        for content in [CONTENT_HANDSHAKE, 0x14, 0x15, 0x17, 0x18] {
            let empty = empty_record(content);
            assert_eq!(
                truncated_handshake_need_known(&empty, TlsSession::Unknown),
                None,
                "empty {content}"
            );
            for cut in [1usize, 5, 7] {
                let mut payload = empty.clone();
                payload.extend_from_slice(&hello[..cut]);
                assert!(
                    truncated_handshake_need_known(&payload, TlsSession::Unknown).is_some(),
                    "empty {content} cut {cut}"
                );
                let prefix = truncated_handshake_prefix(&payload, TlsSession::Unknown).unwrap();
                assert_eq!(prefix, &hello[..cut], "empty {content} cut {cut}");
            }
        }
    }

    #[test]
    fn empty_record_does_not_stick_a_later_grease_hello() {
        let hello = client_hello(Some("www.example.com"));
        let grease = grease_hello();
        for content in [0x14u8, 0x15, 0x17, 0x18] {
            let first = parse_tls(&empty_record(content), TlsSession::Unknown, false);
            assert_eq!(first.kind, TlsParse::Other, "empty {content}");
            assert_eq!(first.session, TlsSession::Unknown, "empty {content}");
            let after = parse_tls(&grease, first.session, false);
            assert_eq!(after.kind, TlsParse::Other, "empty {content} grease");
            let named = parse_tls(&hello, first.session, false);
            assert_eq!(
                named.kind,
                TlsParse::ClientHello(vec!["www.example.com".to_string()]),
                "empty {content} 0x0301"
            );
            let mut same = empty_record(content);
            same.extend_from_slice(&grease);
            assert_eq!(
                parse_tcp_tls_on_tls_port(&same),
                TlsParse::ClientHello(vec!["www.example.com".to_string()]),
                "empty {content} grease same"
            );
        }
        let complete = parse_tls(&ccs(), TlsSession::Unknown, false);
        assert_eq!(complete.session, TlsSession::Sticky);
        let after = parse_tls(&grease, complete.session, false);
        assert_eq!(
            after.kind,
            TlsParse::ClientHello(vec!["www.example.com".to_string()])
        );
    }

    #[test]
    fn empty_non_handshake_then_complete_hello_prints_sni() {
        let hello = client_hello(Some("www.example.com"));
        let grease = grease_hello();
        for content in [0x14u8, 0x15, 0x17, 0x18] {
            let mut payload = empty_record(content);
            payload.extend_from_slice(&hello);
            assert_eq!(
                parse_tcp_tls_on_tls_port(&payload),
                TlsParse::ClientHello(vec!["www.example.com".to_string()]),
                "empty {content}"
            );
        }
        let mut two = empty_record(0x14);
        two.extend_from_slice(&empty_record(0x14));
        two.extend_from_slice(&hello);
        assert_eq!(
            parse_tcp_tls_on_tls_port(&two),
            TlsParse::ClientHello(vec!["www.example.com".to_string()])
        );
        let mut grease_payload = empty_record(0x14);
        grease_payload.extend_from_slice(&grease);
        assert_eq!(
            parse_tcp_tls_on_tls_port(&grease_payload),
            TlsParse::ClientHello(vec!["www.example.com".to_string()])
        );
        let mut empty_hs = empty_record(CONTENT_HANDSHAKE);
        empty_hs.extend_from_slice(&hello);
        assert_eq!(
            parse_tcp_tls_on_tls_port(&empty_hs),
            TlsParse::Unproved,
            "empty handshake then complete hello in the same payload is a counted miss"
        );
    }

    #[test]
    fn truncated_record_need_covers_ccs_alert_app_data_and_heartbeat() {
        let hello = client_hello(Some("www.example.com"));
        let grease = grease_hello();
        for rec in [ccs(), alert(), app_data(), heartbeat()] {
            for cut in [1usize, 3, 4] {
                assert!(
                    truncated_handshake_need(&rec[..cut]).is_some(),
                    "content {} cut {cut}",
                    rec[0]
                );
                let prefix = truncated_handshake_prefix(&rec[..cut], TlsSession::Unknown).unwrap();
                assert_eq!(prefix, &rec[..cut], "content {} cut {cut}", rec[0]);
                let mut stitched = rec[..cut].to_vec();
                stitched.extend_from_slice(&rec[cut..]);
                stitched.extend_from_slice(&hello);
                assert_eq!(
                    parse_tcp_tls_on_tls_port(&stitched),
                    TlsParse::ClientHello(vec!["www.example.com".to_string()]),
                    "content {} cut {cut} 0x0301",
                    rec[0]
                );
            }
            assert_eq!(truncated_handshake_need(&rec), None, "content {}", rec[0]);
        }
        assert_eq!(
            parse_tls(&ccs()[..1], TlsSession::Unknown, false).kind,
            TlsParse::Other
        );
        let mut rest = ccs()[1..].to_vec();
        rest.extend_from_slice(&grease);
        let mut buf = ccs()[..1].to_vec();
        buf.extend_from_slice(&rest);
        assert_eq!(
            parse_tcp_tls_on_tls_port(&buf),
            TlsParse::ClientHello(vec!["www.example.com".to_string()])
        );
        let complete = parse_tls(&ccs(), TlsSession::Unknown, false);
        assert_eq!(complete.session, TlsSession::Sticky);
        let after = parse_tls(&grease, complete.session, false);
        assert_eq!(
            after.kind,
            TlsParse::ClientHello(vec!["www.example.com".to_string()])
        );
        let named = parse_tls(&hello, complete.session, false);
        assert_eq!(
            named.kind,
            TlsParse::ClientHello(vec!["www.example.com".to_string()])
        );
    }

    #[test]
    fn complete_hello_then_truncated_keeps_the_proved_name() {
        let first = client_hello(Some("www.example.com"));
        let second = client_hello(Some("other.example"));
        for cut in [1usize, 5, 7, 40] {
            let mut payload = first.clone();
            payload.extend_from_slice(&second[..cut]);
            assert_eq!(
                parse_tcp_tls_on_tls_port(&payload),
                TlsParse::ClientHello(vec!["www.example.com".to_string()]),
                "cut {cut}"
            );
            let prefix = truncated_handshake_prefix(&payload, TlsSession::Unknown).unwrap();
            assert_eq!(prefix, &second[..cut], "cut {cut}");
        }
        let mut same = first.clone();
        same.extend_from_slice(&first[..1]);
        assert_eq!(
            parse_tcp_tls_on_tls_port(&same),
            TlsParse::ClientHello(vec!["www.example.com".to_string()])
        );
        let mut grease_payload = first.clone();
        grease_payload.extend_from_slice(&grease_hello()[..1]);
        assert_eq!(
            parse_tcp_tls_on_tls_port(&grease_payload),
            TlsParse::ClientHello(vec!["www.example.com".to_string()])
        );
    }

    #[test]
    fn tls13_session_blocks_later_sticky_record_from_grease() {
        let hello = client_hello(Some("www.example.com"));
        for (label, middle) in tls13_middle_records() {
            let mut same = tls13_server_hello();
            same.extend_from_slice(&middle);
            same.extend_from_slice(&grease_hello());
            assert_eq!(
                parse_tcp_tls_on_tls_port(&same),
                TlsParse::Other,
                "{label} same payload"
            );
            let first = parse_tls(&tls13_server_hello(), TlsSession::Unknown, false);
            assert_eq!(first.session, TlsSession::Tls13, "{label} sh");
            let second = parse_tls(&middle, first.session, false);
            assert_eq!(second.session, TlsSession::Tls13, "{label} middle");
            let grease = parse_tls(&grease_hello(), second.session, false);
            assert_eq!(grease.kind, TlsParse::Other, "{label} grease");
            let after = parse_tls(&hello, second.session, false);
            assert_eq!(
                after.kind,
                TlsParse::ClientHello(vec!["www.example.com".to_string()]),
                "{label} 0x0301"
            );
        }
    }

    #[test]
    fn ccs_0304_then_ccs_0303_does_not_stick_grease() {
        let first = parse_tls(&ccs_at(0x0304), TlsSession::Unknown, false);
        assert_eq!(first.session, TlsSession::Tls13);
        let second = parse_tls(&ccs(), first.session, false);
        assert_eq!(second.session, TlsSession::Tls13);
        let grease = parse_tls(&grease_hello(), second.session, false);
        assert_eq!(grease.kind, TlsParse::Other);
        let hello = client_hello(Some("www.example.com"));
        let after = parse_tls(&hello, second.session, false);
        assert_eq!(
            after.kind,
            TlsParse::ClientHello(vec!["www.example.com".to_string()])
        );
        let mut same = ccs_at(0x0304);
        same.extend_from_slice(&ccs());
        same.extend_from_slice(&grease_hello());
        assert_eq!(parse_tcp_tls_on_tls_port(&same), TlsParse::Other);
    }

    #[test]
    fn early_data_forces_tls13_so_later_ccs_does_not_stick_grease() {
        let first = parse_tls(&client_hello_early_data(), TlsSession::Unknown, false);
        assert_eq!(first.session, TlsSession::Tls13);
        let second = parse_tls(&ccs(), first.session, false);
        assert_eq!(second.session, TlsSession::Tls13);
        let grease = parse_tls(&grease_hello(), second.session, false);
        assert_eq!(grease.kind, TlsParse::Other);
        let hello = client_hello(Some("www.example.com"));
        let after = parse_tls(&hello, second.session, false);
        assert_eq!(
            after.kind,
            TlsParse::ClientHello(vec!["www.example.com".to_string()])
        );
        let mut same = client_hello_early_data();
        same.extend_from_slice(&ccs());
        same.extend_from_slice(&grease_hello());
        assert_eq!(
            parse_tcp_tls_on_tls_port(&same),
            TlsParse::ClientHello(Vec::new())
        );
    }

    #[test]
    fn client_hello_does_not_stick_a_later_grease_hello() {
        let first = parse_tls(&client_hello(None), TlsSession::Unknown, false);
        assert_eq!(first.session, TlsSession::Unknown);
        let mut payload = client_hello(None);
        payload.extend_from_slice(&grease_hello());
        assert_eq!(
            parse_tcp_tls_on_tls_port(&payload),
            TlsParse::ClientHello(Vec::new())
        );
        let mut named = client_hello(Some("first.example"));
        named.extend_from_slice(&grease_hello());
        assert_eq!(
            parse_tcp_tls_on_tls_port(&named),
            TlsParse::ClientHello(vec!["first.example".to_string()])
        );
    }

    #[test]
    fn fuzz_random_payloads_do_not_panic() {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..256 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let mut payload = vec![0u8; 64];
            for byte in &mut payload {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                *byte = x as u8;
            }
            let _ = parse_tcp_tls(&payload);
            let _ = looks_like_tls_handshake(&payload);
            let _ = looks_like_dtls_handshake(&payload);
            let _ = looks_like_quic_initial(&payload);
        }
    }
}
