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
const CONTENT_CCS: u8 = 0x14;
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
    /// The `u16` is the stored `SslSession.version` (`ssl_try_set_version`).
    Sticky(u16),
    /// TLS 1.3. `dissect_ssl`'s default arm still needs `ssl_looks_like_sslv3`,
    /// and record-level `ssl_try_set_version` does not run.
    Tls13,
}

impl TlsSession {
    fn skips_looks_like(self) -> bool {
        matches!(self, Self::Sticky(_))
    }

    /// `SslSession.version` as a wire value. Unknown is 0.
    fn tls_version(self) -> u16 {
        match self {
            Self::Unknown => 0,
            Self::Sticky(version) => version,
            Self::Tls13 => 0x0304,
        }
    }
}

/// Result of one TCP payload, plus whether tshark would keep this conversation
/// as TLS and the session version for later records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsOutcome {
    pub kind: TlsParse,
    pub claimed: bool,
    pub session: TlsSession,
    /// tshark `client_ccs_frame` / `server_ccs_frame` for this packet's
    /// `ssl_packet_from_server` role. A later frame uses it in
    /// `is_encrypted_handshake_message`.
    pub after_ccs: bool,
    /// tshark `ssl_set_server(dst)` at entry of `SSL_HND_CLIENT_HELLO`.
    pub set_server: bool,
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
    parse_tls_after_ccs(payload, session, heuristic, false)
}

/// Like [`parse_tls`], with this packet's `ssl_packet_from_server` CCS
/// frame already set from an earlier packet (`pinfo->num > ccs_frame`).
pub fn parse_tls_after_ccs(
    payload: &[u8],
    session: TlsSession,
    heuristic: bool,
    after_ccs: bool,
) -> TlsOutcome {
    if heuristic && !is_sslv3_or_tls(payload) {
        return TlsOutcome {
            kind: TlsParse::Other,
            claimed: false,
            session,
            after_ccs,
            set_server: false,
        };
    }
    let mut session = session;
    let mut after_ccs = after_ccs;
    let mut set_server = false;
    TlsOutcome {
        kind: parse_records(payload, &mut session, &mut after_ccs, &mut set_server),
        claimed: true,
        session,
        after_ccs,
        set_server,
    }
}

fn parse_records(
    payload: &[u8],
    session: &mut TlsSession,
    after_ccs: &mut bool,
    set_server: &mut bool,
) -> TlsParse {
    if payload.is_empty() {
        return TlsParse::Other;
    }
    let mut offset = 0;
    let mut names = Vec::new();
    let mut saw_hello = false;
    let mut unproved = false;
    // tshark only treats CCS as already seen when `pinfo->num > ccs_frame`.
    // A CCS in this payload arms later frames, not later records here.
    let mut armed = *after_ccs;
    let mut saw_ccs = false;
    while offset < payload.len() {
        match take_record(payload, offset, session) {
            Record::Done => break,
            Record::Other {
                next,
                version,
                content,
            } => {
                // tshark 4.6.9 dissect_ssl3_record reads next_byte with
                // tvb_get_uint8 before the CCS switch. A length-0 record at
                // the end of the payload throws, so the session stays unknown
                // and ssl_dissect_change_cipher_spec never runs. A following
                // byte is readable, so the session sticks and a CCS still sets
                // ccs_frame (unless the session is already TLS 1.3). Leftover
                // that is not a content type is then desegmented.
                let next_byte_readable = next > offset + RECORD_HEADER || next < payload.len();
                if next_byte_readable {
                    apply_session_version(session, content, version, None);
                }
                let body = &payload[offset + RECORD_HEADER..next];
                if content == CONTENT_CCS
                    && next_byte_readable
                    && *session != TlsSession::Tls13
                    && !armed
                {
                    saw_ccs = true;
                }
                if content == 0x18
                    && heartbeat_throws(body, &payload[next..], session.tls_version())
                {
                    // THROW(ReportedBoundsError) aborts dissect_ssl. Later
                    // records in this payload are not walked.
                    break;
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
                let leftover = &payload[next..];
                let (hello, threw, reset_ccs) = parse_handshake_messages(
                    body,
                    leftover,
                    session.tls_version(),
                    armed,
                    set_server,
                );
                if reset_ccs {
                    armed = false;
                }
                match hello {
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
                if threw {
                    // THROW(ReportedBoundsError) aborts dissect_ssl at that
                    // handshake message. Later messages in this record and
                    // later records in this payload are not walked.
                    break;
                }
                offset = next;
            }
        }
    }
    *after_ccs = armed || saw_ccs;
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

fn take_record<'a>(payload: &'a [u8], offset: usize, session: &mut TlsSession) -> Record<'a> {
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
    // complete ClientHello in this payload is a counted miss. ssl_try_set_version
    // still reads next_byte (0x14 = Finished is authoritative).
    if length == 0 {
        if content == CONTENT_HANDSHAKE {
            let next = offset + RECORD_HEADER;
            if next < payload.len() {
                apply_session_version(
                    session,
                    CONTENT_HANDSHAKE,
                    version,
                    Some(&payload[next..next + 1]),
                );
            }
            return Record::Unproved;
        }
        return Record::Other {
            next: offset + RECORD_HEADER,
            version,
            content,
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
        Some(TlsSession::Sticky(version))
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

/// tshark 4.6.9 `ssl_31_handshake_type`. `try_val_to_str` is NULL otherwise.
/// Hello Verify Request (3) is named here even though it is DTLS-only in
/// `ssl_is_valid_handshake_type`. Message Hash (254) is not named.
fn is_named_handshake_type(hs_type: u8) -> bool {
    matches!(hs_type, 0..=6 | 8 | 11..=16 | 20..=25 | 67)
}

/// tshark 4.6.9 `is_encrypted_handshake_message` on the first message of a
/// new record.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EncryptedCheck {
    Clear,
    Encrypted,
    /// Cleartext ClientHello or ServerHello after CCS; tshark resets `ccs_frame`.
    ResetCcs,
}

impl EncryptedCheck {
    fn hides(self) -> bool {
        matches!(self, Self::Encrypted)
    }
}

fn is_encrypted_handshake_message(body: &[u8], after_ccs: bool) -> EncryptedCheck {
    if body.len() < 16 {
        return EncryptedCheck::Clear;
    }
    // tvb_get_ntoh40 == 0: two Hello Requests (type=0 length=0, type=0).
    if u40(body) == 0 {
        return EncryptedCheck::Encrypted;
    }
    let msg_type = body[0];
    if !is_named_handshake_type(msg_type) {
        return EncryptedCheck::Encrypted;
    }
    let msg_length = u24(&body[1..4]);
    if msg_length >= 0x010000 {
        return EncryptedCheck::Encrypted;
    }
    if !after_ccs {
        return EncryptedCheck::Clear;
    }
    if msg_type != HANDSHAKE_CLIENT_HELLO && msg_type != HANDSHAKE_SERVER_HELLO {
        return EncryptedCheck::Encrypted;
    }
    let version = u16::from_be_bytes([body[4], body[5]]);
    if !is_named_ssl_version(version) || msg_length >= 0x400 {
        EncryptedCheck::Encrypted
    } else {
        EncryptedCheck::ResetCcs
    }
}

/// tshark 4.6.9 `ssl_is_valid_ssl_version`: `try_val_to_str(ssl_versions)`.
fn is_named_ssl_version(version: u16) -> bool {
    matches!(
        version,
        0x0002
            | 0x0100
            | 0x0101
            | 0x0300..=0x0304
            | 0x7f0e..=0x7f1c
            | 0xfb17
            | 0xfb1a
            | 0xfefc
            | 0xfefd
            | 0xfeff
    ) || is_grease_version(version)
}

fn is_grease_version(version: u16) -> bool {
    version & 0x0f0f == 0x0a0a && version & 0xff == version >> 8
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
            // tshark 4.6.9 dissect_ssl desegments remaining < 5 in both the
            // sticky arm and the SSL_VER_UNKNOWN default arm, before any
            // content-type or ssl_looks_like_sslv3 check. The next in-order
            // segment is Continuation Data.
            return Some(RecordTail {
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
            if content == 0x18
                && heartbeat_throws(&[], &rest[RECORD_HEADER..], session.tls_version())
            {
                return None;
            }
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
        let encrypted =
            content == CONTENT_HANDSHAKE && is_encrypted_handshake_message(body, false).hides();
        if content == CONTENT_HANDSHAKE && !encrypted {
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
        if content == CONTENT_HANDSHAKE
            && !encrypted
            && handshake_throws(body, &rest[need..], session.tls_version())
        {
            // tshark 4.6.9 THROW(ReportedBoundsError) aborts dissect_ssl.
            // Leftover is not desegmented; the next TCP payload is a new record.
            return None;
        }
        if content == 0x18 && heartbeat_throws(body, &rest[need..], session.tls_version()) {
            return None;
        }
        offset += need;
    }
    None
}

/// tshark 4.6.9 handshake dissectors THROW when an unconditional
/// `proto_tree_add_item` / `tvb_get_*` reads past the tvb. `ssl_add_vector`
/// checks `offset_end` and does not throw. ClientHello reads a subset of the
/// message body; the others read the parent tvb, so leftover after the record
/// is available. A throw aborts `dissect_ssl`, so leftover is not desegmented.
fn handshake_throws(body: &[u8], leftover: &[u8], version: u16) -> bool {
    let mut offset = 0;
    while offset < body.len() {
        if body.len() - offset < 4 {
            return false;
        }
        let msg_type = body[offset];
        let msg_len = u24(&body[offset + 1..offset + 4]);
        let start = offset + 4;
        let end = start.saturating_add(msg_len);
        if end > body.len() {
            return false;
        }
        let msg_body = &body[start..end];
        let parent = &body[start..];
        if message_throws(msg_type, msg_body, parent, leftover, version) {
            return true;
        }
        offset = end;
    }
    false
}

fn message_throws(msg_type: u8, body: &[u8], parent: &[u8], leftover: &[u8], version: u16) -> bool {
    match msg_type {
        0 | 5 | 8 | 11 | 12 | 13 | 14 | 16 | 23 => false,
        HANDSHAKE_CLIENT_HELLO => client_hello_throws(body),
        HANDSHAKE_SERVER_HELLO => server_hello_throws(parent, leftover, version),
        4 => new_session_ticket_throws(parent, leftover, version),
        6 => hello_retry_throws(parent, leftover),
        15 => cert_verify_throws(parent, leftover, version),
        20 => version == 0x0300 && parent_avail(parent, leftover) < 36,
        21 => cert_url_throws(parent, leftover),
        22 | 24 => parent_avail(parent, leftover) < 1,
        25 => parent_avail(parent, leftover) < 5,
        67 => npn_encrypted_exts_throws(parent, leftover),
        _ => false,
    }
}

fn parent_avail(parent: &[u8], leftover: &[u8]) -> usize {
    parent.len() + leftover.len()
}

fn parent_byte(parent: &[u8], leftover: &[u8], offset: usize) -> Option<u8> {
    if offset < parent.len() {
        Some(parent[offset])
    } else {
        leftover.get(offset - parent.len()).copied()
    }
}

fn parent_u16(parent: &[u8], leftover: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([
        parent_byte(parent, leftover, offset).unwrap_or(0),
        parent_byte(parent, leftover, offset + 1).unwrap_or(0),
    ])
}

/// `ssl_dissect_hnd_cli_hello` subsets the message body, so leftover after the
/// record cannot satisfy version/random/session_id.
fn client_hello_throws(body: &[u8]) -> bool {
    if body.len() < 35 {
        return true;
    }
    let sid_len = body[34] as usize;
    body.len() < 35 + sid_len
}

/// `ssl_dissect_hnd_srv_hello` then `ssl_dissect_hnd_hello_common`.
fn server_hello_throws(parent: &[u8], leftover: &[u8], version: u16) -> bool {
    let avail = parent_avail(parent, leftover);
    let mut offset = 0;
    if avail < 2 {
        return true;
    }
    offset += 2;
    if avail < offset + 32 {
        return true;
    }
    offset += 32;
    let draft = if (version & 0xff00) == 0x7f00 {
        version as u8
    } else {
        0
    };
    if version == 0x0304 && draft > 0 && draft < 22 {
        return avail < offset + 2;
    }
    if avail < offset + 1 {
        return true;
    }
    let sid_len = parent_byte(parent, leftover, offset).unwrap_or(0) as usize;
    offset += 1;
    if avail < offset + sid_len {
        return true;
    }
    offset += sid_len;
    if avail < offset + 2 {
        return true;
    }
    offset += 2;
    avail < offset + 1
}

/// `ssl_dissect_hnd_new_ses_ticket`: lifetime, then TLS 1.3 age_add.
fn new_session_ticket_throws(parent: &[u8], leftover: &[u8], version: u16) -> bool {
    let avail = parent_avail(parent, leftover);
    if avail < 4 {
        return true;
    }
    version == 0x0304 && avail < 8
}

/// Draft TLS 1.3 `ssl_dissect_hnd_hello_retry_request`.
fn hello_retry_throws(parent: &[u8], leftover: &[u8]) -> bool {
    let avail = parent_avail(parent, leftover);
    if avail < 2 {
        return true;
    }
    let ver = u16::from_be_bytes([
        parent_byte(parent, leftover, 0).unwrap_or(0),
        parent_byte(parent, leftover, 1).unwrap_or(0),
    ]);
    let draft = if (ver & 0xff00) == 0x7f00 {
        ver as u8
    } else {
        0
    };
    if draft == 0 || draft >= 19 {
        avail < 4
    } else {
        false
    }
}

/// `ssl_dissect_hnd_cli_cert_verify` / `ssl_dissect_digitally_signed`.
fn cert_verify_throws(parent: &[u8], leftover: &[u8], version: u16) -> bool {
    matches!(version, 0x0303 | 0x0304) && parent_avail(parent, leftover) < 2
}

/// `ssl_dissect_hnd_cert_url` reads type then the 2-byte URL list length from
/// the parent tvb, then `while (url_hash_len-- > 0)` walks that many
/// URLAndHash entries (tshark treats the vector length as a count). Each
/// entry reads url_len, url, padding, and a 20-byte SHA-1. A throw aborts
/// `dissect_ssl`: leftover is not desegmented, and later records in this
/// payload are not walked.
fn cert_url_throws(parent: &[u8], leftover: &[u8]) -> bool {
    let avail = parent_avail(parent, leftover);
    if avail < 3 {
        return true;
    }
    let list_len = parent_u16(parent, leftover, 1) as usize;
    let mut offset = 3;
    for _ in 0..list_len {
        if avail.saturating_sub(offset) < 2 {
            return true;
        }
        let url_len = parent_u16(parent, leftover, offset) as usize;
        offset += 2;
        if avail.saturating_sub(offset) < url_len {
            return true;
        }
        offset += url_len;
        if avail.saturating_sub(offset) < 1 {
            return true;
        }
        offset += 1;
        if avail.saturating_sub(offset) < 20 {
            return true;
        }
        offset += 20;
    }
    false
}

/// `dissect_ssl3_hnd_encrypted_exts` (handshake type 67, NPN).
fn npn_encrypted_exts_throws(parent: &[u8], leftover: &[u8]) -> bool {
    let avail = parent_avail(parent, leftover);
    if avail < 1 {
        return true;
    }
    let proto_len = parent_byte(parent, leftover, 0).unwrap_or(0) as usize;
    if avail < 1 + proto_len + 1 {
        return true;
    }
    let pad_len = parent_byte(parent, leftover, 1 + proto_len).unwrap_or(0) as usize;
    avail < 1 + proto_len + 1 + pad_len
}

/// tshark 4.6.9 `dissect_ssl3_heartbeat`. TLS 1.3 skips it. Otherwise it always
/// reads type + payload_length (3 bytes) from the parent tvb. A Request/Response
/// on a record shorter than 3 bytes then adds a payload of `record_length - 3`,
/// which throws. A throw aborts `dissect_ssl`: leftover is not desegmented, and
/// later records in this payload are not walked.
fn heartbeat_throws(body: &[u8], leftover: &[u8], version: u16) -> bool {
    if version == 0x0304 {
        return false;
    }
    if parent_avail(body, leftover) < 3 {
        return true;
    }
    if body.len() >= 3 {
        return false;
    }
    matches!(parent_byte(body, leftover, 0), Some(1 | 2))
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

fn parse_handshake_messages(
    body: &[u8],
    leftover: &[u8],
    version: u16,
    after_ccs: bool,
    set_server: &mut bool,
) -> (Hello, bool, bool) {
    if body.is_empty() {
        return (Hello::Unproved, false, false);
    }
    let encrypted = is_encrypted_handshake_message(body, after_ccs);
    if encrypted.hides() {
        // dissect_tls_handshake treats the rest of this record as Encrypted
        // Handshake Message. Later ClientHellos in this record are not printed.
        return (Hello::None, false, false);
    }
    let reset_ccs = encrypted == EncryptedCheck::ResetCcs;
    let mut offset = 0;
    let mut names = Vec::new();
    let mut saw_hello = false;
    while offset < body.len() {
        if body.len() - offset < 4 {
            return (Hello::Unproved, false, reset_ccs);
        }
        let msg_type = body[offset];
        let msg_len = u24(&body[offset + 1..offset + 4]);
        let start = offset + 4;
        let end = start.saturating_add(msg_len);
        if end > body.len() {
            return (Hello::Unproved, false, reset_ccs);
        }
        if msg_type == HANDSHAKE_CLIENT_HELLO {
            // tshark 4.6.9 calls ssl_set_server at the start of the
            // SSL_HND_CLIENT_HELLO arm, before ssl_dissect_hnd_cli_hello.
            *set_server = true;
            match parse_client_hello(&body[start..end]) {
                Some(found) => {
                    saw_hello = true;
                    names.extend(found);
                }
                None => return (Hello::Unproved, false, reset_ccs),
            }
        }
        let msg_body = &body[start..end];
        let parent = &body[start..];
        if message_throws(msg_type, msg_body, parent, leftover, version) {
            // THROW(ReportedBoundsError) aborts dissect_ssl at this message.
            // Later handshake messages in this record are not walked.
            return (hello_names(saw_hello, names), true, reset_ccs);
        }
        offset = end;
    }
    (hello_names(saw_hello, names), false, reset_ccs)
}

fn hello_names(saw_hello: bool, names: Vec<String>) -> Hello {
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

fn u40(bytes: &[u8]) -> u64 {
    ((bytes[0] as u64) << 32)
        | ((bytes[1] as u64) << 24)
        | ((bytes[2] as u64) << 16)
        | ((bytes[3] as u64) << 8)
        | bytes[4] as u64
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

    fn handshake_type_record_at(msg_type: u8, version: u16, body: &[u8]) -> Vec<u8> {
        record(CONTENT_HANDSHAKE, version, &handshake(msg_type, body))
    }

    fn valid_server_hello() -> Vec<u8> {
        let mut hello = Vec::from(0x0303u16.to_be_bytes());
        hello.extend_from_slice(&[0x22u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&[0x00, 0x2f]);
        hello.push(0);
        handshake_type_record_at(HANDSHAKE_SERVER_HELLO, 0x0303, &hello)
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
    fn empty_or_short_client_hello_sets_server() {
        let empty = handshake_type_record(HANDSHAKE_CLIENT_HELLO);
        let short = handshake_type_record_at(HANDSHAKE_CLIENT_HELLO, 0x0303, &[0x00]);
        for (label, rec) in [("empty", empty.as_slice()), ("1-byte", short.as_slice())] {
            let out = parse_tls(rec, TlsSession::Unknown, false);
            assert!(out.set_server, "{label}");
            assert_eq!(out.kind, TlsParse::Unproved, "{label}");
        }
        let out = parse_tls(&client_hello(None), TlsSession::Unknown, false);
        assert!(out.set_server);
        assert_eq!(out.kind, TlsParse::ClientHello(Vec::new()));
        let out = parse_tls(&handshake_type_record(0), TlsSession::Unknown, false);
        assert!(!out.set_server);
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
        let after = parse_tls(&lone, TlsSession::Sticky(0x0303), false);
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
        assert_eq!(first.session, TlsSession::Sticky(0x0303));
        let after = parse_tls(&grease_hello(), TlsSession::Sticky(0x0303), false);
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
        let after = parse_tls(&tls13_server_hello(), TlsSession::Sticky(0x0303), false);
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
                if content == 0x18 && cut < 3 {
                    // dissect_ssl3_heartbeat throws before leftover is desegmented.
                    assert_eq!(
                        truncated_handshake_need_known(&payload, TlsSession::Unknown),
                        None,
                        "empty heartbeat cut {cut}"
                    );
                    continue;
                }
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
            assert!(!first.after_ccs, "empty {content} does not arm CCS");
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
        assert_eq!(complete.session, TlsSession::Sticky(0x0303));
        let after = parse_tls(&grease, complete.session, false);
        assert_eq!(
            after.kind,
            TlsParse::ClientHello(vec!["www.example.com".to_string()])
        );
    }

    fn stitch_leftover(first: &[u8], next: &[u8]) -> TlsParse {
        let outcome = parse_tls(first, TlsSession::Unknown, false);
        match truncated_handshake_prefix(first, TlsSession::Unknown) {
            Some(prefix) => {
                let mut buf = prefix.to_vec();
                buf.extend_from_slice(next);
                parse_tls(&buf, outcome.session, false).kind
            }
            None => parse_tls(next, outcome.session, false).kind,
        }
    }

    #[test]
    fn leftover_garbage_after_empty_record_swallows_the_next_hello() {
        let hello = client_hello(Some("www.example.com"));
        let grease = grease_hello();
        for content in [0x14u8, 0x15, 0x17, 0x19, 0x1A] {
            for leftover in [0x00u8, 0x01, 0xff] {
                let mut first = empty_record(content);
                first.push(leftover);
                let outcome = parse_tls(&first, TlsSession::Unknown, false);
                assert_eq!(
                    outcome.kind,
                    TlsParse::Other,
                    "empty {content}+{leftover:#04x}"
                );
                assert_eq!(
                    outcome.session,
                    TlsSession::Sticky(0x0303),
                    "empty {content}+{leftover:#04x}"
                );
                let prefix = truncated_handshake_prefix(&first, TlsSession::Unknown).unwrap();
                assert_eq!(prefix, &[leftover], "empty {content}+{leftover:#04x}");
                assert_eq!(
                    stitch_leftover(&first, &grease),
                    TlsParse::Other,
                    "empty {content}+{leftover:#04x} grease"
                );
                assert_eq!(
                    stitch_leftover(&first, &hello),
                    TlsParse::Other,
                    "empty {content}+{leftover:#04x} 0x0301"
                );
            }
            for leftover in [0x14u8, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A] {
                let mut first = empty_record(content);
                first.push(leftover);
                assert!(
                    !matches!(stitch_leftover(&first, &grease), TlsParse::ClientHello(_)),
                    "empty {content}+ct{leftover:#04x} grease"
                );
            }
            let mut same = empty_record(content);
            same.extend_from_slice(&ccs());
            same.extend_from_slice(&grease);
            assert_eq!(
                parse_tcp_tls_on_tls_port(&same),
                TlsParse::ClientHello(vec!["www.example.com".to_string()]),
                "empty {content} complete CCS grease same"
            );
        }
        let mut ccs_leftover = ccs();
        ccs_leftover.push(0x00);
        assert_eq!(
            stitch_leftover(&ccs_leftover, &grease),
            TlsParse::Other,
            "complete CCS+00 grease"
        );
        assert_eq!(
            stitch_leftover(&ccs_leftover, &hello),
            TlsParse::Other,
            "complete CCS+00 0x0301"
        );
        let mut five = empty_record(0x14);
        five.extend_from_slice(&[0x00; 5]);
        assert_eq!(
            stitch_leftover(&five, &grease),
            TlsParse::ClientHello(vec!["www.example.com".to_string()]),
            "empty CCS+5 zeros is IUR in this frame"
        );
        let mut hb_leftover = empty_record(0x18);
        hb_leftover.push(0x00);
        assert_eq!(
            stitch_leftover(&hb_leftover, &grease),
            TlsParse::ClientHello(vec!["www.example.com".to_string()]),
            "empty heartbeat leftover throws, next GREASE prints"
        );
    }

    #[test]
    fn leftover_shorter_than_header_swallows_the_next_hello_while_unknown() {
        let hello = client_hello(Some("www.example.com"));
        let grease = grease_hello();
        let other = client_hello(Some("other.example"));
        for leftover in [0x00u8, 0x01, 0x13, 0x1b, 0xff] {
            assert_eq!(
                truncated_handshake_need(&[leftover]),
                Some(4),
                "{leftover:#04x}"
            );
            assert_eq!(
                truncated_handshake_prefix(&[leftover], TlsSession::Unknown),
                Some(&[leftover][..]),
                "{leftover:#04x}"
            );
            assert_eq!(
                stitch_leftover(&[leftover], &hello),
                TlsParse::Other,
                "{leftover:#04x} 0x0301"
            );
            assert_eq!(
                stitch_leftover(&[leftover], &grease),
                TlsParse::Other,
                "{leftover:#04x} grease"
            );
        }
        for n in 2..=4 {
            let zeros = vec![0u8; n];
            assert_eq!(truncated_handshake_need(&zeros), Some(5 - n), "{n} zeros");
            assert_eq!(
                stitch_leftover(&zeros, &hello),
                TlsParse::Other,
                "{n} zeros 0x0301"
            );
        }
        for leftover in [0x00u8, 0x01, 0x02] {
            let mut first = empty_record(CONTENT_HANDSHAKE);
            first.push(leftover);
            let outcome = parse_tls(&first, TlsSession::Unknown, false);
            assert_eq!(outcome.kind, TlsParse::Unproved, "empty HS+{leftover:#04x}");
            assert_eq!(
                truncated_handshake_prefix(&first, TlsSession::Unknown),
                Some(&[leftover][..]),
                "empty HS+{leftover:#04x}"
            );
            assert_eq!(
                stitch_leftover(&first, &grease),
                TlsParse::Other,
                "empty HS+{leftover:#04x} grease"
            );
            assert_eq!(
                stitch_leftover(&first, &hello),
                TlsParse::Other,
                "empty HS+{leftover:#04x} 0x0301"
            );
        }
        let mut hello_leftover = hello.clone();
        hello_leftover.push(0x00);
        assert_eq!(
            parse_tcp_tls_on_tls_port(&hello_leftover),
            TlsParse::ClientHello(vec!["www.example.com".to_string()])
        );
        assert_eq!(
            truncated_handshake_prefix(&hello_leftover, TlsSession::Unknown),
            Some(&[0x00][..])
        );
        assert_eq!(stitch_leftover(&hello_leftover, &other), TlsParse::Other);
        for leftover in [0x14u8, 0x16, 0x19, 0x1a] {
            assert_eq!(
                truncated_handshake_need(&[leftover]),
                Some(4),
                "ct {leftover:#04x}"
            );
            assert_eq!(
                stitch_leftover(&[leftover], &hello),
                TlsParse::Other,
                "ct {leftover:#04x}"
            );
        }
    }

    #[test]
    fn leftover_after_a_throwing_handshake_prints_the_next_hello() {
        let hello = client_hello(Some("www.example.com"));
        let grease = grease_hello();
        let named = TlsParse::ClientHello(vec!["www.example.com".to_string()]);
        let throwing = [
            handshake_type_record(2),
            handshake_type_record(4),
            handshake_type_record(6),
            handshake_type_record(15),
            handshake_type_record(21),
            handshake_type_record(25),
            handshake_type_record(67),
            handshake_type_record_at(2, 0x0303, &[0x03, 0x03]),
            handshake_type_record_at(20, 0x0300, &[]),
        ];
        for first in throwing {
            let mut payload = first.clone();
            payload.push(0x00);
            assert_eq!(
                truncated_handshake_prefix(&payload, TlsSession::Unknown),
                None,
                "type {}",
                first[5]
            );
            assert_eq!(
                stitch_leftover(&payload, &grease),
                named,
                "type {}",
                first[5]
            );
            assert_eq!(
                stitch_leftover(&payload, &hello),
                named,
                "type {} 0x0301",
                first[5]
            );
        }
        let mut empty_ch = handshake_type_record(1);
        empty_ch.push(0x00);
        assert_eq!(
            truncated_handshake_prefix(&empty_ch, TlsSession::Unknown),
            None
        );
        assert_eq!(stitch_leftover(&empty_ch, &hello), named);
        assert_eq!(stitch_leftover(&empty_ch, &grease), TlsParse::Other);
        let keep = [
            handshake_type_record(0),
            handshake_type_record(11),
            handshake_type_record(14),
            handshake_type_record(20),
            valid_server_hello(),
        ];
        for first in keep {
            let mut payload = first;
            payload.push(0x00);
            assert_eq!(
                truncated_handshake_prefix(&payload, TlsSession::Unknown),
                Some(&[0x00][..]),
                "keep {}",
                payload[5]
            );
            assert_eq!(
                stitch_leftover(&payload, &grease),
                TlsParse::Other,
                "keep {}",
                payload[5]
            );
        }
        let tls10 = parse_tls(&ccs_at(0x0301), TlsSession::Unknown, false);
        assert_eq!(tls10.session, TlsSession::Sticky(0x0301));
        let mut cv = handshake_type_record(15);
        cv.push(0x00);
        assert_eq!(
            truncated_handshake_prefix(&cv, tls10.session),
            Some(&[0x00][..]),
            "TLS 1.0 Certificate Verify leftover is ssl_add_vector"
        );
        let mut cv12 = handshake_type_record(15);
        cv12.push(0x00);
        let tls12 = parse_tls(&ccs(), TlsSession::Unknown, false);
        assert_eq!(truncated_handshake_prefix(&cv12, tls12.session), None);
        for n in 1..=4 {
            let leftover = vec![0u8; n];
            let mut payload = handshake_type_record(2);
            payload.extend_from_slice(&leftover);
            assert_eq!(
                truncated_handshake_prefix(&payload, TlsSession::Unknown),
                None,
                "empty SH leftover {n}"
            );
            assert_eq!(
                stitch_leftover(&payload, &grease),
                named,
                "empty SH leftover {n} grease"
            );
            assert_eq!(
                stitch_leftover(&payload, &hello),
                named,
                "empty SH leftover {n} 0x0301"
            );
        }
        for n in 1usize..=36 {
            let mut body = vec![0x03, 0x03];
            body.resize(n, 0);
            let mut payload = handshake_type_record_at(2, 0x0303, &body);
            payload.push(0x00);
            assert_eq!(
                truncated_handshake_prefix(&payload, TlsSession::Unknown),
                None,
                "SH body {n}"
            );
            assert_eq!(
                stitch_leftover(&payload, &grease),
                named,
                "SH body {n} grease"
            );
            assert_eq!(
                stitch_leftover(&payload, &hello),
                named,
                "SH body {n} 0x0301"
            );
        }
        let mut hs0_then_sh_body = handshake(0, &[]);
        hs0_then_sh_body.extend_from_slice(&handshake(2, &[]));
        let mut hs0_then_sh = record(CONTENT_HANDSHAKE, 0x0303, &hs0_then_sh_body);
        hs0_then_sh.push(0x00);
        assert_eq!(
            truncated_handshake_prefix(&hs0_then_sh, TlsSession::Unknown),
            None
        );
        assert_eq!(stitch_leftover(&hs0_then_sh, &grease), named);
        assert_eq!(stitch_leftover(&hs0_then_sh, &hello), named);
    }

    fn short_heartbeat(body: &[u8]) -> Vec<u8> {
        record(0x18, 0x0303, body)
    }

    #[test]
    fn leftover_after_a_throwing_heartbeat_prints_the_next_hello() {
        let hello = client_hello(Some("www.example.com"));
        let grease = grease_hello();
        let named = TlsParse::ClientHello(vec!["www.example.com".to_string()]);
        for body in [vec![0x01u8], vec![0x01, 0x00]] {
            for n in 1..=4 {
                let mut first = short_heartbeat(&body);
                first.extend_from_slice(&vec![0u8; n]);
                assert_eq!(
                    truncated_handshake_prefix(&first, TlsSession::Unknown),
                    None,
                    "hb {} leftover {n}",
                    body.len()
                );
                assert_eq!(
                    stitch_leftover(&first, &grease),
                    named,
                    "hb {} leftover {n} grease",
                    body.len()
                );
                assert_eq!(
                    stitch_leftover(&first, &hello),
                    named,
                    "hb {} leftover {n} 0x0301",
                    body.len()
                );
            }
        }
        let mut empty_type1 = empty_record(0x18);
        empty_type1.extend_from_slice(&[0x01, 0x00, 0x00]);
        assert_eq!(
            truncated_handshake_prefix(&empty_type1, TlsSession::Unknown),
            None,
            "empty heartbeat leftover 01 00 00 throws on payload"
        );
        assert_eq!(stitch_leftover(&empty_type1, &grease), named);
        assert_eq!(stitch_leftover(&empty_type1, &hello), named);
        let mut empty_zeros = empty_record(0x18);
        empty_zeros.extend_from_slice(&[0x00, 0x00, 0x00]);
        assert_eq!(
            truncated_handshake_prefix(&empty_zeros, TlsSession::Unknown),
            Some(&[0x00, 0x00, 0x00][..]),
            "empty heartbeat leftover 00 00 00 is not a heartbeat type"
        );
        let tls13 = parse_tls(&tls13_server_hello(), TlsSession::Unknown, false);
        assert_eq!(tls13.session, TlsSession::Tls13);
        let mut hb = empty_record(0x18);
        hb.push(0x00);
        assert_eq!(
            truncated_handshake_prefix(&hb, tls13.session),
            Some(&[0x00][..]),
            "TLS 1.3 skips dissect_ssl3_heartbeat, leftover desegments"
        );
        let mut buf = vec![0x00];
        buf.extend_from_slice(&hello);
        assert_eq!(
            parse_tls(&buf, tls13.session, false).kind,
            TlsParse::Other,
            "TLS 1.3 empty heartbeat leftover swallows 0x0301"
        );
        let mut short = short_heartbeat(&[0x01]);
        short.push(0x00);
        assert_eq!(
            truncated_handshake_prefix(&short, tls13.session),
            Some(&[0x00][..]),
            "TLS 1.3 length-1 heartbeat leftover desegments"
        );
    }

    #[test]
    fn throwing_heartbeat_does_not_walk_a_following_hello_in_the_same_payload() {
        let hello = client_hello(Some("www.example.com"));
        let grease = grease_hello();
        let named = TlsParse::ClientHello(vec!["www.example.com".to_string()]);
        for body in [vec![0x01u8], vec![0x01, 0x00], vec![0x01, 0x01], vec![0x02]] {
            for following in [&hello, &grease] {
                let mut payload = short_heartbeat(&body);
                payload.extend_from_slice(following);
                assert_eq!(
                    parse_tcp_tls_on_tls_port(&payload),
                    TlsParse::Other,
                    "hb {} type {} same",
                    body.len(),
                    body[0]
                );
            }
        }
        for prefix in [empty_record(0x18), heartbeat()] {
            for following in [&hello, &grease] {
                let mut payload = prefix.clone();
                payload.extend_from_slice(following);
                assert_eq!(
                    parse_tcp_tls_on_tls_port(&payload),
                    named.clone(),
                    "keep {} then {}",
                    prefix.len(),
                    following[1]
                );
            }
        }
        for following in [&hello, &grease] {
            let mut empty_sh = handshake_type_record(2);
            empty_sh.extend_from_slice(following);
            assert_eq!(
                parse_tcp_tls_on_tls_port(&empty_sh),
                named.clone(),
                "empty ServerHello leftover satisfies parent read"
            );
            let mut encrypted = short_heartbeat(&[0x00]);
            encrypted.extend_from_slice(following);
            assert_eq!(
                parse_tcp_tls_on_tls_port(&encrypted),
                named.clone(),
                "heartbeat type 0 does not throw"
            );
            let mut ccs_then = ccs();
            ccs_then.extend_from_slice(&short_heartbeat(&[0x01]));
            ccs_then.extend_from_slice(following);
            assert_eq!(
                parse_tcp_tls_on_tls_port(&ccs_then),
                TlsParse::Other,
                "CCS then throwing heartbeat aborts"
            );
        }
        let mut hello_then = hello.clone();
        hello_then.extend_from_slice(&short_heartbeat(&[0x01]));
        assert_eq!(parse_tcp_tls_on_tls_port(&hello_then), named);
        let tls13 = parse_tls(&tls13_server_hello(), TlsSession::Unknown, false);
        assert_eq!(tls13.session, TlsSession::Tls13);
        let mut tls13_payload = tls13_server_hello();
        tls13_payload.extend_from_slice(&short_heartbeat(&[0x01]));
        tls13_payload.extend_from_slice(&hello);
        assert_eq!(
            parse_tls(&tls13_payload, TlsSession::Unknown, false).kind,
            named,
            "TLS 1.3 skips dissect_ssl3_heartbeat, later 0x0301 prints"
        );
        let mut tls13_grease = tls13_server_hello();
        tls13_grease.extend_from_slice(&short_heartbeat(&[0x01]));
        tls13_grease.extend_from_slice(&grease);
        assert_eq!(
            parse_tls(&tls13_grease, TlsSession::Unknown, false).kind,
            TlsParse::Other,
            "TLS 1.3 then GREASE is continuation"
        );
        for version in [0x0300u16, 0x0301, 0x0302, 0x0303, 0x0101] {
            let mut payload = record(0x18, version, &[0x01]);
            payload.extend_from_slice(&grease);
            assert_eq!(
                parse_tcp_tls_on_tls_port(&payload),
                TlsParse::Other,
                "hb ver {version:#06x} same GREASE"
            );
        }
    }

    #[test]
    fn throwing_cert_url_does_not_walk_a_following_hello_in_the_same_payload() {
        let hello = client_hello(Some("www.example.com"));
        let grease = grease_hello();
        let named = TlsParse::ClientHello(vec!["www.example.com".to_string()]);
        let bodies: &[&[u8]] = &[
            &[],
            &[0x00],
            &[0x00, 0x01],
            &[0x00, 0x00, 0x01],
            &[0x00, 0x05, 0x00, 0x00, 0x00],
        ];
        for body in bodies {
            let rec = handshake_type_record_at(21, 0x0303, body);
            for following in [&hello, &grease] {
                let mut payload = rec.clone();
                payload.extend_from_slice(following);
                assert_eq!(
                    parse_tcp_tls_on_tls_port(&payload),
                    TlsParse::Other,
                    "cert_url body {} same {}",
                    body.len(),
                    following[1]
                );
            }
        }
        for following in [&hello, &grease] {
            for leftover in [vec![0x00u8], vec![0x00, 0x00]] {
                let mut first = handshake_type_record(21);
                first.extend_from_slice(&leftover);
                assert_eq!(
                    stitch_leftover(&first, following),
                    named.clone(),
                    "leftover {} then {}",
                    leftover.len(),
                    following[1]
                );
            }
            let mut three = handshake_type_record(21);
            three.extend_from_slice(&[0x00, 0x00, 0x00]);
            assert_eq!(
                stitch_leftover(&three, following),
                TlsParse::Other,
                "leftover 3 zeros then {}",
                following[1]
            );
            for leftover in [vec![0x00u8, 0x01, 0x00], vec![0xff, 0xff, 0xff]] {
                let mut overrun = handshake_type_record(21);
                overrun.extend_from_slice(&leftover);
                assert_eq!(
                    truncated_handshake_prefix(&overrun, TlsSession::Unknown),
                    None,
                    "leftover {leftover:?}"
                );
                assert_eq!(
                    stitch_leftover(&overrun, following),
                    named.clone(),
                    "leftover {leftover:?} then {}",
                    following[1]
                );
            }
            let mut empty_list = handshake_type_record_at(21, 0x0303, &[0x00, 0x00, 0x00]);
            empty_list.extend_from_slice(following);
            assert_eq!(
                parse_tcp_tls_on_tls_port(&empty_list),
                named.clone(),
                "list_len 0 then {}",
                following[1]
            );
            for msg_type in [2u8, 4, 6, 8, 15, 25, 67] {
                let mut payload = handshake_type_record(msg_type);
                payload.extend_from_slice(following);
                assert_eq!(
                    parse_tcp_tls_on_tls_port(&payload),
                    named.clone(),
                    "empty type {msg_type} then {}",
                    following[1]
                );
            }
        }
    }

    fn client_hello_hs(sni: &str) -> Vec<u8> {
        client_hello(Some(sni))[RECORD_HEADER..].to_vec()
    }

    fn handshake_record_messages(parts: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        for part in parts {
            body.extend_from_slice(part);
        }
        record(CONTENT_HANDSHAKE, 0x0303, &body)
    }

    #[test]
    fn throwing_handshake_does_not_walk_a_later_hello_in_the_same_record() {
        let hello_hs = client_hello_hs("www.example.com");
        let other_hs = client_hello_hs("other.example");
        let named = TlsParse::ClientHello(vec!["www.example.com".to_string()]);
        let throwing = [
            (21u8, &[0x00][..]),
            (21, &[0x00, 0x01]),
            (21, &[0x00, 0x00, 0x01]),
            (21, &[0x00, 0x05, 0x00, 0x00, 0x00]),
            (67, &[0xff]),
            (67, &[0x7f]),
            (67, &[0xfe]),
        ];
        for (msg_type, body) in throwing {
            let rec = handshake_record_messages(&[handshake(msg_type, body), hello_hs.clone()]);
            assert_eq!(
                parse_tcp_tls_on_tls_port(&rec),
                TlsParse::Other,
                "type {msg_type} body {body:?} then CH"
            );
            let both = handshake_record_messages(&[
                hello_hs.clone(),
                handshake(msg_type, body),
                other_hs.clone(),
            ]);
            assert_eq!(
                parse_tcp_tls_on_tls_port(&both),
                named.clone(),
                "CH then type {msg_type} body {body:?} then CH"
            );
        }
        for msg_type in [2u8, 4, 6, 15, 25, 67] {
            let rec = handshake_record_messages(&[handshake(msg_type, &[]), hello_hs.clone()]);
            assert_eq!(
                parse_tcp_tls_on_tls_port(&rec),
                named.clone(),
                "empty type {msg_type} then CH same record"
            );
        }
        let empty_then_record = {
            let mut payload = handshake_type_record(21);
            payload.extend_from_slice(&client_hello(Some("www.example.com")));
            payload
        };
        assert_eq!(
            parse_tcp_tls_on_tls_port(&empty_then_record),
            TlsParse::Other,
            "empty CertificateURL then CH as a second record"
        );
    }

    #[test]
    fn unnamed_first_handshake_type_hides_a_later_hello_in_the_same_record() {
        let hello_hs = client_hello_hs("www.example.com");
        let other_hs = client_hello_hs("other.example");
        let named = TlsParse::ClientHello(vec!["www.example.com".to_string()]);
        let both = TlsParse::ClientHello(vec![
            "www.example.com".to_string(),
            "other.example".to_string(),
        ]);
        let rec = handshake_record_messages(&[handshake(7, &[]), hello_hs.clone()]);
        assert!(rec.len() - RECORD_HEADER >= 16, "type 7 then CH is 16+");
        assert_eq!(
            parse_tcp_tls_on_tls_port(&rec),
            TlsParse::Other,
            "type 7 then CH same record"
        );
        assert_eq!(
            parse_tcp_tls(&rec),
            TlsParse::Other,
            "unnamed 40001→40002 type 7 then CH"
        );
        for msg_type in [
            9u8, 10, 17, 18, 19, 26, 27, 28, 29, 64, 66, 68, 99, 254, 255,
        ] {
            for body in [&[][..], &[0x00][..]] {
                let rec = handshake_record_messages(&[handshake(msg_type, body), hello_hs.clone()]);
                assert_eq!(
                    parse_tcp_tls_on_tls_port(&rec),
                    TlsParse::Other,
                    "type {msg_type} body {body:?} then CH"
                );
            }
        }
        let mut ccs_same = ccs();
        ccs_same.extend_from_slice(&handshake_record_messages(&[
            handshake(7, &[]),
            hello_hs.clone(),
        ]));
        assert_eq!(
            parse_tcp_tls_on_tls_port(&ccs_same),
            TlsParse::Other,
            "CCS then type 7 then CH same payload"
        );
        let encrypted = handshake_record_messages(&[handshake(7, &[]), hello_hs.clone()]);
        let first = parse_tls(&ccs(), TlsSession::Unknown, false);
        assert_eq!(
            parse_tls(&encrypted, first.session, false).kind,
            TlsParse::Other,
            "CCS then type 7 then CH next frame"
        );
        let mut short = handshake_type_record(7);
        short.extend_from_slice(&client_hello(Some("www.example.com")));
        assert_eq!(
            handshake_type_record(7).len() - RECORD_HEADER,
            4,
            "empty type 7 record is 4 bytes"
        );
        assert_eq!(
            parse_tcp_tls_on_tls_port(&short),
            named.clone(),
            "empty type 7 as its own record then CH"
        );
        let later =
            handshake_record_messages(&[hello_hs.clone(), handshake(7, &[]), other_hs.clone()]);
        assert_eq!(
            parse_tcp_tls_on_tls_port(&later),
            both,
            "CH then type 7 then CH same record"
        );
        for msg_type in [
            0u8, 2, 4, 6, 3, 8, 11, 12, 13, 14, 15, 16, 20, 21, 22, 23, 24, 25, 67,
        ] {
            let rec = handshake_record_messages(&[handshake(msg_type, &[]), hello_hs.clone()]);
            assert_eq!(
                parse_tcp_tls_on_tls_port(&rec),
                named.clone(),
                "empty named type {msg_type} then CH same record"
            );
        }
        let two_hr =
            handshake_record_messages(&[handshake(0, &[]), handshake(0, &[]), hello_hs.clone()]);
        assert_eq!(
            &two_hr[RECORD_HEADER..RECORD_HEADER + 8],
            &[0, 0, 0, 0, 0, 0, 0, 0],
            "two Hello Requests then CH"
        );
        assert_eq!(
            parse_tcp_tls_on_tls_port(&two_hr),
            TlsParse::Other,
            "two Hello Requests then CH"
        );
        let mut second = handshake_record_messages(&[handshake(7, &[]), hello_hs.clone()]);
        second.extend_from_slice(&client_hello(Some("other.example")));
        assert_eq!(
            parse_tcp_tls_on_tls_port(&second),
            TlsParse::ClientHello(vec!["other.example".to_string()]),
            "type 7 then CH then a second record"
        );
        let mut huge = vec![0, 0x01, 0x00, 0x00];
        huge.extend_from_slice(&hello_hs);
        let huge = record(CONTENT_HANDSHAKE, 0x0303, &huge);
        assert_eq!(
            parse_tcp_tls_on_tls_port(&huge),
            TlsParse::Other,
            "named type with 64K length then CH"
        );
        let hr_ch = handshake_record_messages(&[handshake(0, &[]), hello_hs.clone()]);
        let first = parse_tls_after_ccs(&ccs(), TlsSession::Unknown, false, false);
        assert!(first.after_ccs, "CCS arms the next frame");
        assert_eq!(
            parse_tls_after_ccs(&hr_ch, first.session, false, first.after_ccs).kind,
            TlsParse::Other,
            "CCS then Hello Request then CH next frame"
        );
        assert_eq!(
            parse_tls_after_ccs(
                &client_hello(Some("www.example.com")),
                first.session,
                false,
                first.after_ccs
            )
            .kind,
            named.clone(),
            "CCS then ClientHello next frame still prints"
        );
    }

    fn hello_request_then_hello(sni: &str) -> Vec<u8> {
        handshake_record_messages(&[handshake(0, &[]), client_hello_hs(sni)])
    }

    fn empty_cert_then_hello(sni: &str) -> Vec<u8> {
        handshake_record_messages(&[handshake(11, &[]), client_hello_hs(sni)])
    }

    fn client_hello_legacy_version(sni: Option<&str>, hello_ver: u16) -> Vec<u8> {
        let mut hello = client_hello(sni);
        hello[9..11].copy_from_slice(&hello_ver.to_be_bytes());
        hello
    }

    fn stitch_frames(first: &[u8], second: &[u8], heuristic: bool) -> (TlsOutcome, TlsOutcome) {
        let first = parse_tls_after_ccs(first, TlsSession::Unknown, heuristic, false);
        let second = parse_tls_after_ccs(second, first.session, false, first.after_ccs);
        (first, second)
    }

    #[test]
    fn empty_ccs_with_leftover_arms_later_encrypted_handshake() {
        let named = TlsParse::ClientHello(vec!["www.example.com".to_string()]);
        let no_sni = client_hello(None);
        let hr_ch = hello_request_then_hello("www.example.com");
        let empty_ccs = empty_record(CONTENT_CCS);
        let leftovers = [
            ("no-sni", no_sni.clone()),
            ("sni", client_hello(Some("www.example.com"))),
            ("server-hello", valid_server_hello()),
            ("app-data", app_data()),
            ("alert", alert()),
            ("heartbeat", heartbeat()),
            ("hello-request", handshake_type_record(0)),
        ];
        for (label, leftover) in leftovers {
            let mut first = empty_ccs.clone();
            first.extend_from_slice(&leftover);
            let (first_out, second_out) = stitch_frames(&first, &hr_ch, false);
            assert!(first_out.after_ccs, "empty CCS leftover {label} arms");
            assert_ne!(first_out.session, TlsSession::Tls13, "{label}");
            if label == "sni" {
                assert_eq!(first_out.kind, named.clone(), "{label} same-frame name");
            } else if label == "no-sni" {
                assert_eq!(first_out.kind, TlsParse::ClientHello(Vec::new()), "{label}");
            } else {
                assert_eq!(first_out.kind, TlsParse::Other, "{label}");
            }
            assert_eq!(
                second_out.kind,
                TlsParse::Other,
                "empty CCS leftover {label} then HR+CH"
            );
        }
        let mut first = empty_ccs.clone();
        first.extend_from_slice(&no_sni);
        let (_, cert_out) = stitch_frames(&first, &empty_cert_then_hello("www.example.com"), false);
        assert_eq!(cert_out.kind, TlsParse::Other, "frame 2 empty Certificate");
        let ver0 = client_hello_legacy_version(Some("www.example.com"), 0);
        assert_eq!(&ver0[9..11], &[0, 0], "hello version 0x0000");
        let (_, ver0_out) = stitch_frames(&first, &ver0, false);
        assert_eq!(ver0_out.kind, TlsParse::Other, "frame 2 hello version 0");

        let claim = parse_tls(&no_sni, TlsSession::Unknown, true);
        assert!(claim.claimed, "unnamed claiming hello");
        assert!(!claim.after_ccs);
        let mut unnamed_ccs = empty_ccs.clone();
        unnamed_ccs.extend_from_slice(&no_sni);
        let unnamed_ccs_out = parse_tls_after_ccs(&unnamed_ccs, claim.session, false, false);
        assert!(unnamed_ccs_out.after_ccs, "unnamed empty CCS leftover arms");
        let unnamed_hr = parse_tls_after_ccs(
            &hr_ch,
            unnamed_ccs_out.session,
            false,
            unnamed_ccs_out.after_ccs,
        );
        assert_eq!(
            unnamed_hr.kind,
            TlsParse::Other,
            "unnamed 40001→40002 extra"
        );

        let mut same = empty_ccs.clone();
        same.extend_from_slice(&hr_ch);
        let same_out = parse_tls(&same, TlsSession::Unknown, false);
        assert_eq!(same_out.kind, named.clone(), "same-payload empty CCS HR+CH");
        assert!(
            same_out.after_ccs,
            "same-payload CCS still arms later frames"
        );

        let trail = parse_tls(&empty_ccs, TlsSession::Unknown, false);
        assert!(!trail.after_ccs, "trailing empty CCS does not arm");
        assert_eq!(trail.session, TlsSession::Unknown);
        let grease = parse_tls(&grease_hello(), trail.session, false);
        assert_eq!(
            grease.kind,
            TlsParse::Other,
            "trailing empty CCS then GREASE"
        );
        let trail_hr = parse_tls_after_ccs(&hr_ch, trail.session, false, trail.after_ccs);
        assert_eq!(
            trail_hr.kind,
            named.clone(),
            "trailing empty CCS then HR+CH still prints"
        );

        let nonempty = parse_tls(&ccs(), TlsSession::Unknown, false);
        assert!(nonempty.after_ccs);
        let nonempty_hr = parse_tls_after_ccs(&hr_ch, nonempty.session, false, nonempty.after_ccs);
        assert_eq!(
            nonempty_hr.kind,
            TlsParse::Other,
            "nonempty CCS then HR+CH next frame"
        );

        let tls13 = parse_tls(&tls13_server_hello(), TlsSession::Unknown, false);
        assert_eq!(tls13.session, TlsSession::Tls13);
        let mut tls13_ccs = empty_ccs;
        tls13_ccs.extend_from_slice(&no_sni);
        let tls13_ccs_out = parse_tls_after_ccs(&tls13_ccs, tls13.session, false, false);
        assert!(
            !tls13_ccs_out.after_ccs,
            "TLS 1.3 dummy CCS does not set ccs_frame"
        );
        let tls13_hr = parse_tls_after_ccs(
            &hr_ch,
            tls13_ccs_out.session,
            false,
            tls13_ccs_out.after_ccs,
        );
        assert_eq!(
            tls13_hr.kind, named,
            "TLS 1.3 empty CCS leftover then HR+CH prints"
        );
    }

    #[test]
    fn empty_handshake_next_byte_sticks_a_later_grease_hello() {
        let hello = client_hello(Some("www.example.com"));
        let grease = grease_hello();
        for following in [
            empty_record(0x14),
            empty_record(0x15),
            empty_record(0x17),
            empty_record(0x18),
            empty_record(0x19),
            ccs(),
            alert(),
            app_data(),
        ] {
            let mut first = empty_record(CONTENT_HANDSHAKE);
            first.extend_from_slice(&following);
            let outcome = parse_tls(&first, TlsSession::Unknown, false);
            assert_eq!(
                outcome.kind,
                TlsParse::Unproved,
                "empty HS then {}",
                following[0]
            );
            assert_eq!(
                outcome.session,
                TlsSession::Sticky(0x0303),
                "empty HS then {}",
                following[0]
            );
            assert_eq!(
                parse_tls(&grease, outcome.session, false).kind,
                TlsParse::ClientHello(vec!["www.example.com".to_string()]),
                "empty HS then {} grease",
                following[0]
            );
            assert_eq!(
                parse_tls(&hello, outcome.session, false).kind,
                TlsParse::ClientHello(vec!["www.example.com".to_string()]),
                "empty HS then {} 0x0301",
                following[0]
            );
        }
        let mut same = empty_record(CONTENT_HANDSHAKE);
        same.extend_from_slice(&hello);
        assert_eq!(
            parse_tcp_tls_on_tls_port(&same),
            TlsParse::Unproved,
            "empty HS then complete hello same payload stays a counted miss"
        );
        let lone = parse_tls(&empty_record(CONTENT_HANDSHAKE), TlsSession::Unknown, false);
        assert_eq!(lone.kind, TlsParse::Unproved);
        assert_eq!(lone.session, TlsSession::Unknown);
        assert_eq!(
            parse_tls(&grease, lone.session, false).kind,
            TlsParse::Other
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
        assert_eq!(complete.session, TlsSession::Sticky(0x0303));
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
