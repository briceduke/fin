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
const EXT_MAX_FRAGMENT_LENGTH: u16 = 1;
const EXT_TRUSTED_CA_KEYS: u16 = 3;
const EXT_STATUS_REQUEST: u16 = 5;
const EXT_CERT_TYPE: u16 = 9;
const EXT_EC_POINT_FORMATS: u16 = 11;
const EXT_HEARTBEAT_MODE: u16 = 15;
const EXT_ALPN: u16 = 16;
const EXT_STATUS_REQUEST_V2: u16 = 17;
const EXT_CLIENT_CERT_TYPE: u16 = 19;
const EXT_SERVER_CERT_TYPE: u16 = 20;
const EXT_TOKEN_BINDING: u16 = 24;
const EXT_COMPRESS_CERTIFICATE: u16 = 27;
const EXT_RECORD_SIZE_LIMIT: u16 = 28;
const EXT_PRE_SHARED_KEY: u16 = 41;
const EXT_EARLY_DATA: u16 = 42;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_TICKET_EARLY_DATA_INFO: u16 = 46;
const EXT_CERTIFICATE_AUTHORITIES: u16 = 47;
const EXT_OID_FILTERS: u16 = 48;
const EXT_CONNECTION_ID_DEPRECATED: u16 = 53;
const EXT_CONNECTION_ID: u16 = 54;
const EXT_QUIC_TP_V1: u16 = 57;
const EXT_ECH: u16 = 65037;
const EXT_QUIC_TP: u16 = 65445;
const EXT_ESNI: u16 = 65486;
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
    /// Last ClientHello extension whose throw fin cannot prove.
    pub counted: Option<&'static str>,
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
            counted: None,
        };
    }
    let mut session = session;
    let mut after_ccs = after_ccs;
    let mut set_server = false;
    let (kind, counted) = parse_records(payload, &mut session, &mut after_ccs, &mut set_server);
    TlsOutcome {
        kind,
        claimed: true,
        session,
        after_ccs,
        set_server,
        counted,
    }
}

fn parse_records(
    payload: &[u8],
    session: &mut TlsSession,
    after_ccs: &mut bool,
    set_server: &mut bool,
) -> (TlsParse, Option<&'static str>) {
    if payload.is_empty() {
        return (TlsParse::Other, None);
    }
    let mut offset = 0;
    let mut names = Vec::new();
    let mut saw_hello = false;
    let mut unproved = false;
    let mut counted = None;
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
                let (hello, threw, reset_ccs, uncertain) = parse_handshake_messages(
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
                if uncertain {
                    counted = Some("tls-hello-ext-uncertain");
                }
                if threw || uncertain {
                    // THROW aborts dissect_ssl. An uncertain last ClientHello
                    // extension is not proved as a throw, so leftover still
                    // desegments; later messages/records in this payload are
                    // not printed.
                    break;
                }
                offset = next;
            }
        }
    }
    *after_ccs = armed || saw_ccs;
    let kind = if saw_hello {
        TlsParse::ClientHello(names)
    } else if unproved {
        TlsParse::Unproved
    } else {
        TlsParse::Other
    };
    (kind, counted)
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

/// Exact hello-tvb throw, or a last extension whose throw fin cannot prove.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HelloExtAction {
    Continue,
    Throw,
    Uncertain,
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
    // dissect_ssl3_record desegments an incomplete record before
    // ssl_check_record_length. ssl_check_record_length is expert-info only
    // and does not abort the content-type switch, so a complete record of
    // any u16 length is walked. An incomplete one is Unproved/Done here;
    // record_tail buffers it.
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
        let need = RECORD_HEADER + length;
        if need > rest.len() {
            // tshark 4.6.9 dissect_ssl3_record desegments any incomplete
            // record after a valid content type, including u16 length
            // 18432–65535. ssl_check_record_length runs only after the
            // full record is assembled, and is expert-info only.
            return Some(RecordTail {
                start: offset,
                more: need - rest.len(),
            });
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
        HANDSHAKE_CLIENT_HELLO => client_hello_action(body) == HelloExtAction::Throw,
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
/// record cannot satisfy version/random/session_id. `ssl_add_vector` does not
/// throw; `proto_tree_add_item` / `tvb_get_*` on the hello tvb do.
fn client_hello_action(body: &[u8]) -> HelloExtAction {
    if body.len() < 35 {
        return HelloExtAction::Throw;
    }
    let sid_len = body[34] as usize;
    if body.len() < 35 + sid_len {
        return HelloExtAction::Throw;
    }
    client_hello_exts_action(body)
}

/// tshark 4.6.9 `ssl_dissect_hnd_extension` on a ClientHello tvb.
fn client_hello_exts_action(body: &[u8]) -> HelloExtAction {
    let Some((mut offset, ext_end)) = hello_ext_range(body) else {
        return HelloExtAction::Continue;
    };
    while ext_end.saturating_sub(offset) >= 4 {
        let typ = u16::from_be_bytes([body[offset], body[offset + 1]]);
        let len = u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;
        let next = match offset.checked_add(4).and_then(|data| data.checked_add(len)) {
            Some(next) => next,
            None => return HelloExtAction::Throw,
        };
        let is_last = ext_end.saturating_sub(next) < 4;
        match hello_ext_action(body, offset, typ, len, is_last) {
            HelloExtAction::Continue => {}
            other => return other,
        }
        offset = next;
    }
    HelloExtAction::Continue
}

fn hello_ext_range(body: &[u8]) -> Option<(usize, usize)> {
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
        return Some((offset, offset));
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
    Some((offset, ext_end))
}

/// `proto_tree_add_none_format(..., 4 + ext_len)` then the type handler.
fn hello_ext_throws(hello: &[u8], header: usize, typ: u16, len: usize) -> bool {
    hello_ext_action(hello, header, typ, len, false) == HelloExtAction::Throw
}

fn hello_ext_action(
    hello: &[u8],
    header: usize,
    typ: u16,
    len: usize,
    is_last: bool,
) -> HelloExtAction {
    let Some(data) = header.checked_add(4) else {
        return HelloExtAction::Throw;
    };
    let Some(claimed) = data.checked_add(len) else {
        return HelloExtAction::Throw;
    };
    if claimed > hello.len() {
        return HelloExtAction::Throw;
    }
    hello_ext_handler_action(typ, len, data, hello, is_last)
}

/// Fixed-width hello-tvb reads in tshark 4.6.9 `ssl_dissect_hnd_extension`.
/// Last ALPN / status_request_v2 / PSK / certificate_authorities / oid_filters
/// and trusted_ca_keys x509_name are counted: those handlers walk BER, JA4,
/// or OCSP in ways fin does not prove.
fn hello_ext_handler_action(
    typ: u16,
    ext_len: usize,
    data: usize,
    hello: &[u8],
    is_last: bool,
) -> HelloExtAction {
    if is_last
        && matches!(
            typ,
            EXT_ALPN
                | EXT_STATUS_REQUEST_V2
                | EXT_PRE_SHARED_KEY
                | EXT_CERTIFICATE_AUTHORITIES
                | EXT_OID_FILTERS
        )
    {
        return HelloExtAction::Uncertain;
    }
    let rem = hello.len().saturating_sub(data);
    match typ {
        EXT_MAX_FRAGMENT_LENGTH
        | EXT_STATUS_REQUEST
        | EXT_CERT_TYPE
        | EXT_HEARTBEAT_MODE
        | EXT_CLIENT_CERT_TYPE
        | EXT_SERVER_CERT_TYPE => {
            if rem < 1 {
                HelloExtAction::Throw
            } else {
                HelloExtAction::Continue
            }
        }
        EXT_EC_POINT_FORMATS => {
            if rem < 1 || rem < 1 + hello[data] as usize {
                HelloExtAction::Throw
            } else {
                HelloExtAction::Continue
            }
        }
        EXT_TOKEN_BINDING | EXT_RECORD_SIZE_LIMIT => {
            if rem < 2 {
                HelloExtAction::Throw
            } else {
                HelloExtAction::Continue
            }
        }
        EXT_CONNECTION_ID_DEPRECATED | EXT_CONNECTION_ID => {
            if rem < 1 {
                HelloExtAction::Throw
            } else {
                let cidl = hello[data] as usize;
                if cidl > 0 && rem < 1 + cidl {
                    HelloExtAction::Throw
                } else {
                    HelloExtAction::Continue
                }
            }
        }
        EXT_COMPRESS_CERTIFICATE => {
            if compress_certificate_throws(hello, data, ext_len) {
                HelloExtAction::Throw
            } else {
                HelloExtAction::Continue
            }
        }
        EXT_QUIC_TP_V1 | EXT_QUIC_TP => {
            if quic_transport_parameters_throws(hello, data, ext_len) {
                HelloExtAction::Throw
            } else {
                HelloExtAction::Continue
            }
        }
        EXT_ECH => {
            if ech_client_hello_throws(hello, data) {
                HelloExtAction::Throw
            } else {
                HelloExtAction::Continue
            }
        }
        // Suite (2) then KeyShare group (2). `ssl_add_vector` for key_exchange
        // does not throw, so length 4–5 stays inside the hello tvb.
        EXT_ESNI => {
            if rem < 4 {
                HelloExtAction::Throw
            } else {
                HelloExtAction::Continue
            }
        }
        EXT_TRUSTED_CA_KEYS => trusted_ca_keys_action(hello, data, ext_len, is_last),
        _ => HelloExtAction::Continue,
    }
}

/// `ssl_dissect_hnd_hello_ext_trusted_ca_keys`: list `ssl_add_vector` (no throw),
/// then `tvb_get_uint8` identifier_type and, for SHA1 types 1 and 3, a 20-byte
/// hash from the hello tvb. Type `x509_name` (2) walks DistinguishedName BER;
/// a last extension that contains it is counted instead of parsed.
fn trusted_ca_keys_action(
    hello: &[u8],
    data: usize,
    ext_len: usize,
    is_last: bool,
) -> HelloExtAction {
    if ext_len < 2 {
        return HelloExtAction::Continue;
    }
    let list_len = u16::from_be_bytes([hello[data], hello[data + 1]]) as usize;
    if ext_len - 2 < list_len {
        return HelloExtAction::Continue;
    }
    let end = data + 2 + list_len;
    let mut offset = data + 2;
    while offset < end {
        if hello.len().saturating_sub(offset) < 1 {
            return HelloExtAction::Throw;
        }
        let id = hello[offset];
        offset += 1;
        match id {
            1 | 3 => {
                if hello.len().saturating_sub(offset) < 20 {
                    return HelloExtAction::Throw;
                }
                offset += 20;
            }
            2 => {
                if is_last {
                    return HelloExtAction::Uncertain;
                }
                if end.saturating_sub(offset) < 2 {
                    return HelloExtAction::Continue;
                }
                let name_len = u16::from_be_bytes([hello[offset], hello[offset + 1]]) as usize;
                offset += 2;
                if end.saturating_sub(offset) < name_len {
                    return HelloExtAction::Continue;
                }
                offset += name_len;
            }
            _ => {}
        }
    }
    HelloExtAction::Continue
}

/// `ssl_dissect_hnd_hello_ext_compress_certificate`: 1-byte `ssl_add_vector`
/// does not throw, then 2-byte algorithm IDs from the hello tvb.
fn compress_certificate_throws(hello: &[u8], data: usize, ext_len: usize) -> bool {
    if ext_len < 1 {
        return false;
    }
    let Some(&alg_len) = hello.get(data) else {
        return false;
    };
    let alg_len = alg_len as usize;
    if ext_len - 1 < alg_len {
        return false;
    }
    let mut offset = data + 1;
    let next_offset = offset + alg_len;
    while offset < next_offset {
        if hello.len().saturating_sub(offset) < 2 {
            return true;
        }
        offset += 2;
    }
    false
}

/// `ssl_dissect_hnd_hello_ext_quic_transport_parameters`.
fn quic_transport_parameters_throws(hello: &[u8], data: usize, ext_len: usize) -> bool {
    if quic_draft26(hello, data, ext_len) {
        let list_len = u16::from_be_bytes([hello[data], hello[data + 1]]) as usize;
        if ext_len < 2 || ext_len - 2 < list_len {
            return false;
        }
        return quic_params_legacy_throws(hello, data + 2, data + 2 + list_len);
    }
    quic_params_varint_throws(hello, data, data + ext_len)
}

/// Draft -26 or older: 2-byte list length, then 2-byte type/length params.
fn quic_draft26(hello: &[u8], data: usize, ext_len: usize) -> bool {
    if ext_len < 6 {
        return false;
    }
    let list_len = u16::from_be_bytes([hello[data], hello[data + 1]]) as usize;
    let first_val = u16::from_be_bytes([hello[data + 4], hello[data + 5]]) as usize;
    2 + list_len == ext_len && 6 + first_val <= ext_len
}

fn quic_params_varint_throws(hello: &[u8], mut offset: usize, next_offset: usize) -> bool {
    while offset < next_offset {
        // `proto_tree_add_subtree(..., 2)` then type/length `ENC_VARINT_QUIC`.
        if hello.len().saturating_sub(offset) < 2 {
            return true;
        }
        let Some((parameter_type, type_len)) = hello.get(offset..).and_then(quic_varint) else {
            return true;
        };
        offset += type_len;
        let Some((plen, len_len)) = hello.get(offset..).and_then(quic_varint) else {
            return true;
        };
        offset += len_len;
        // tshark 4.6.9: parameter_length = (uint32_t)parameter_length64
        let parameter_length = plen as u32 as usize;
        if quic_param_throws(hello, offset, next_offset, parameter_type, parameter_length) {
            return true;
        }
        match offset.checked_add(parameter_length) {
            Some(end) => offset = end,
            None => return true,
        }
    }
    false
}

fn quic_params_legacy_throws(hello: &[u8], mut offset: usize, next_offset: usize) -> bool {
    while offset < next_offset {
        if hello.len().saturating_sub(offset) < 2 {
            return true;
        }
        let parameter_type = u16::from_be_bytes([hello[offset], hello[offset + 1]]) as usize;
        offset += 2;
        if next_offset.saturating_sub(offset) < 2 {
            return false;
        }
        let parameter_length = u16::from_be_bytes([hello[offset], hello[offset + 1]]) as usize;
        offset += 2;
        if next_offset.saturating_sub(offset) < parameter_length {
            return false;
        }
        if quic_param_throws(hello, offset, next_offset, parameter_type, parameter_length) {
            return true;
        }
        offset += parameter_length;
    }
    false
}

/// tshark 4.6.9 `ssl_dissect_hnd_hello_ext_quic_transport_parameters` switch:
/// `proto_tree_add_item` / `ENC_VARINT_QUIC` from the hello tvb, including
/// when `parameter_length` is 0. `ssl_add_vector` does not throw.
fn quic_param_throws(
    hello: &[u8],
    offset: usize,
    ext_end: usize,
    parameter_type: usize,
    parameter_length: usize,
) -> bool {
    if parameter_length > 0 && hello.len().saturating_sub(offset) < parameter_length {
        return true;
    }
    match parameter_type {
        0x02 => hello.len().saturating_sub(offset) < 16,
        0x0d => quic_preferred_address_throws(hello, offset, ext_end),
        0x11 | 0xff73db => quic_version_information_throws(hello, offset, parameter_length),
        0x1000 => quic_two_varints_throw(hello, offset),
        0x4751 | 0x4752 => hello.len().saturating_sub(offset) < 4,
        0x01 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x0a | 0x0b | 0x0e | 0x20
        | 0x1057 | 0x3127 | 0x7158 | 0xde1a | 0xff00 | 0xff03de1a | 0xff04de1a | 0xff04de1b
        | 0x9f81a176 | 0x0f739bbc1b666d04 | 0x0f739bbc1b666d07 | 0x0f739bbc1b666d09
        | 0x0f739bbc1b666d11 | 0x0f739bbc1b666d0c | 0x0f739bbc1b666d0d => {
            hello.get(offset..).and_then(quic_varint).is_none()
        }
        _ => false,
    }
}

fn quic_two_varints_throw(hello: &[u8], offset: usize) -> bool {
    let Some((_, n)) = hello.get(offset..).and_then(quic_varint) else {
        return true;
    };
    match offset.checked_add(n) {
        Some(next) => hello.get(next..).and_then(quic_varint).is_none(),
        None => true,
    }
}

fn quic_version_information_throws(
    hello: &[u8],
    mut offset: usize,
    parameter_length: usize,
) -> bool {
    if hello.len().saturating_sub(offset) < 4 {
        return true;
    }
    offset += 4;
    let mut consumed = 4;
    while consumed < parameter_length {
        if hello.len().saturating_sub(offset) < 4 {
            return true;
        }
        offset += 4;
        consumed += 4;
    }
    false
}

/// IPv4 (4) + port (2) + IPv6 (16) + port (2), then `ssl_add_vector` CID
/// (no throw), then a 16-byte reset token from the hello tvb.
fn quic_preferred_address_throws(hello: &[u8], mut offset: usize, ext_end: usize) -> bool {
    if hello.len().saturating_sub(offset) < 24 {
        return true;
    }
    offset += 24;
    if offset > ext_end || ext_end - offset < 1 {
        return false;
    }
    let cid_len = hello[offset] as usize;
    offset += 1;
    if ext_end.saturating_sub(offset) < cid_len {
        return false;
    }
    offset += cid_len;
    hello.len().saturating_sub(offset) < 16
}

/// `ssl_dissect_hnd_hello_ext_ech` ClientHello: type, then outer cipher suite.
fn ech_client_hello_throws(hello: &[u8], data: usize) -> bool {
    if hello.len().saturating_sub(data) < 1 {
        return true;
    }
    if hello[data] != 0 {
        return false;
    }
    let mut offset = data + 1;
    if hello.len().saturating_sub(offset) < 4 {
        return true;
    }
    offset += 4;
    if hello.len().saturating_sub(offset) < 1 {
        return true;
    }
    offset += 1;
    if hello.len().saturating_sub(offset) < 2 {
        return true;
    }
    let enc_len = u16::from_be_bytes([hello[offset], hello[offset + 1]]) as usize;
    offset += 2;
    if hello.len().saturating_sub(offset) < enc_len {
        return true;
    }
    offset += enc_len;
    if hello.len().saturating_sub(offset) < 2 {
        return true;
    }
    let payload_len = u16::from_be_bytes([hello[offset], hello[offset + 1]]) as usize;
    offset += 2;
    hello.len().saturating_sub(offset) < payload_len
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
) -> (Hello, bool, bool, bool) {
    if body.is_empty() {
        return (Hello::Unproved, false, false, false);
    }
    let encrypted = is_encrypted_handshake_message(body, after_ccs);
    if encrypted.hides() {
        // dissect_tls_handshake treats the rest of this record as Encrypted
        // Handshake Message. Later ClientHellos in this record are not printed.
        return (Hello::None, false, false, false);
    }
    let reset_ccs = encrypted == EncryptedCheck::ResetCcs;
    let mut offset = 0;
    let mut names = Vec::new();
    let mut saw_hello = false;
    while offset < body.len() {
        if body.len() - offset < 4 {
            return (Hello::Unproved, false, reset_ccs, false);
        }
        let msg_type = body[offset];
        let msg_len = u24(&body[offset + 1..offset + 4]);
        let start = offset + 4;
        let end = start.saturating_add(msg_len);
        if end > body.len() {
            return (Hello::Unproved, false, reset_ccs, false);
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
                None => return (Hello::Unproved, false, reset_ccs, false),
            }
        }
        let msg_body = &body[start..end];
        let parent = &body[start..];
        if msg_type == HANDSHAKE_CLIENT_HELLO {
            match client_hello_action(msg_body) {
                HelloExtAction::Throw => {
                    return (hello_names(saw_hello, names), true, reset_ccs, false);
                }
                HelloExtAction::Uncertain => {
                    return (hello_names(saw_hello, names), false, reset_ccs, true);
                }
                HelloExtAction::Continue => {}
            }
        } else if message_throws(msg_type, msg_body, parent, leftover, version) {
            // THROW(ReportedBoundsError) aborts dissect_ssl at this message.
            // Later handshake messages in this record are not walked.
            return (hello_names(saw_hello, names), true, reset_ccs, false);
        }
        offset = end;
    }
    (hello_names(saw_hello, names), false, reset_ccs, false)
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
    let (offset, ext_end) = hello_ext_range(body)?;
    parse_extensions(body, offset, ext_end)
}

fn parse_extensions(hello: &[u8], mut offset: usize, ext_end: usize) -> Option<Vec<String>> {
    let mut names = Vec::new();
    while offset < ext_end {
        if offset + 4 > ext_end {
            return None;
        }
        let typ = u16::from_be_bytes([hello[offset], hello[offset + 1]]);
        let len = u16::from_be_bytes([hello[offset + 2], hello[offset + 3]]) as usize;
        if hello_ext_throws(hello, offset, typ, len) {
            return Some(names);
        }
        offset += 4;
        let end = offset.checked_add(len)?;
        if end > ext_end {
            return None;
        }
        if typ == EXT_SERVER_NAME {
            names.extend(parse_server_name(&hello[offset..end])?);
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
        let ccs = record(0x14, 0x0303, &[0x01]);
        let alert = record(0x15, 0x0303, &[0x02, 0x28]);
        let heartbeat = record(0x18, 0x0303, &[0x01, 0x00, 0x00]);
        for prefix in [ccs, alert, heartbeat] {
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
    fn split_record_stitches_when_concatenated() {
        let hello = client_hello(Some("www.example.com"));
        let cut = 40;
        assert_eq!(parse_tcp_tls(&hello[..cut]), TlsParse::Unproved);
        let prefix =
            truncated_handshake_prefix(&hello[..cut], TlsSession::Unknown).unwrap_or(&hello[..cut]);
        let mut stitched = prefix.to_vec();
        stitched.extend_from_slice(&hello[cut..]);
        assert_eq!(
            parse_tcp_tls(&stitched),
            TlsParse::ClientHello(vec!["www.example.com".to_string()])
        );
    }
}
