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
const EXT_SERVER_NAME: u16 = 0;
const RECORD_HEADER: usize = 5;
const TLS_MAX_RECORD: usize = 16384 + 2048;

/// Result of one TCP payload, plus whether tshark would keep this conversation
/// as TLS and whether a later record may skip `ssl_looks_like_sslv3`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsOutcome {
    pub kind: TlsParse,
    pub claimed: bool,
    pub known: bool,
}

/// Parse SNI from one TCP payload on an unnamed port. The first record must
/// pass tshark 4.6.9 `is_sslv3_or_tls`.
pub fn parse_tcp_tls(payload: &[u8]) -> TlsParse {
    parse_tls(payload, false, true).kind
}

/// Port 443 (and the other `tls` ports) force the TLS dissector. An unknown
/// session uses `ssl_looks_like_sslv3`; after an authoritative SSLv3/TLS 1.0–1.2
/// or TLCP record, later records follow `dissect_ssl3_record`.
pub fn parse_tcp_tls_on_tls_port(payload: &[u8]) -> TlsParse {
    parse_tls(payload, false, false).kind
}

/// `heuristic` is tshark's first-packet `is_sslv3_or_tls` gate. `known` is a
/// conversation whose version already stuck as SSLv3/TLS 1.0–1.2/TLCP.
pub fn parse_tls(payload: &[u8], known: bool, heuristic: bool) -> TlsOutcome {
    if heuristic && !is_sslv3_or_tls(payload) {
        return TlsOutcome {
            kind: TlsParse::Other,
            claimed: false,
            known,
        };
    }
    let mut known = known;
    TlsOutcome {
        kind: parse_records(payload, &mut known),
        claimed: true,
        known,
    }
}

fn parse_records(payload: &[u8], known: &mut bool) -> TlsParse {
    if payload.is_empty() {
        return TlsParse::Other;
    }
    let mut offset = 0;
    let mut names = Vec::new();
    let mut saw_hello = false;
    let mut unproved = false;
    while offset < payload.len() {
        match take_record(payload, offset, *known) {
            Record::Done => break,
            Record::Other {
                next,
                version,
                content,
            } => {
                if sets_known(content, version) {
                    *known = true;
                }
                offset = next;
            }
            Record::Unproved => {
                unproved = true;
                break;
            }
            Record::Handshake { body, next } => {
                match parse_handshake_messages(body) {
                    Hello::None => {}
                    Hello::Names(found) => {
                        saw_hello = true;
                        names.extend(found);
                    }
                    Hello::Unproved => unproved = true,
                }
                offset = next;
            }
        }
    }
    if unproved {
        return TlsParse::Unproved;
    }
    if saw_hello {
        TlsParse::ClientHello(names)
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

fn take_record(payload: &[u8], offset: usize, known: bool) -> Record<'_> {
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
    if !known && !is_record_version(version) {
        return Record::Done;
    }
    if length == 0 || length >= TLS_MAX_RECORD {
        return if content == CONTENT_HANDSHAKE {
            Record::Unproved
        } else {
            Record::Done
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
        Record::Handshake { body, next: end }
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
    matches!(content, 20 | 21 | 22 | 23 | 24 | 25 | 26)
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

fn sets_known(content: u8, version: u16) -> bool {
    content != CONTENT_HANDSHAKE && is_content_type(content) && is_sticky_version(version)
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

/// Bytes still needed to finish a handshake record that starts in `payload`.
pub fn truncated_handshake_need(payload: &[u8]) -> Option<usize> {
    truncated_handshake_need_known(payload, false)
}

/// Like [`truncated_handshake_need`], but a sticky session accepts any record
/// version the way `dissect_ssl3_record` does.
pub fn truncated_handshake_need_known(payload: &[u8], known: bool) -> Option<usize> {
    if payload.is_empty() {
        return None;
    }
    if payload.len() < RECORD_HEADER {
        return (payload[0] == CONTENT_HANDSHAKE).then_some(RECORD_HEADER - payload.len());
    }
    let (content, version, length) = tls_record_header(payload)?;
    if content != CONTENT_HANDSHAKE {
        return None;
    }
    if !known && !is_record_version(version) {
        return None;
    }
    if length == 0 || length >= TLS_MAX_RECORD {
        return None;
    }
    let need = RECORD_HEADER + length;
    (need > payload.len()).then(|| need - payload.len())
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
        payload.extend_from_slice(&client_hello_bytes(Some(b"www.example.com"), 0x0a0a));
        assert_eq!(
            parse_tcp_tls_on_tls_port(&payload),
            TlsParse::ClientHello(vec!["www.example.com".to_string()])
        );
        assert_eq!(
            parse_tcp_tls(&payload),
            TlsParse::Other,
            "unnamed port CCS prefix is not is_sslv3_or_tls"
        );
        let lone = client_hello_bytes(Some(b"www.example.com"), 0x0a0a);
        assert_eq!(parse_tcp_tls_on_tls_port(&lone), TlsParse::Other);
        let after = parse_tls(&lone, true, false);
        assert_eq!(
            after.kind,
            TlsParse::ClientHello(vec!["www.example.com".to_string()])
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
