//! One-packet TLS ClientHello SNI. Split records, TCP reassembly, QUIC,
//! and DTLS are out of scope and counted when they look like a handshake.

/// A TCP payload that may carry a ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsParse {
    /// Complete ClientHello. Names follow tshark's field order.
    ClientHello(Vec<String>),
    /// Handshake bytes that this reader cannot prove.
    Unproved,
    /// Not a TLS handshake.
    Other,
}

const CONTENT_HANDSHAKE: u8 = 0x16;
const RECORD_HEADER: usize = 5;
const TLS_MAX_RECORD: usize = 16384 + 2048;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const EXT_SERVER_NAME: u16 = 0;
const EXT_ALPN: u16 = 16;
const EXT_STATUS_REQUEST_V2: u16 = 17;
const EXT_PRE_SHARED_KEY: u16 = 41;
const EXT_CERTIFICATE_AUTHORITIES: u16 = 47;
const EXT_OID_FILTERS: u16 = 48;

/// Result of one TCP payload, plus whether tshark would keep this conversation
/// as TLS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsOutcome {
    pub kind: TlsParse,
    pub claimed: bool,
    /// Leftover, a later hello, or a last ClientHello extension whose throw
    /// fin cannot prove.
    pub counted: Option<&'static str>,
}

/// `heuristic` is tshark's first-packet `is_sslv3_or_tls` gate.
pub fn parse_tls(payload: &[u8], heuristic: bool) -> TlsOutcome {
    parse_tls_seen(payload, heuristic, false)
}

/// `after_tls` is true when this TCP conversation already claimed a TLS record.
pub(crate) fn parse_tls_seen(payload: &[u8], heuristic: bool, after_tls: bool) -> TlsOutcome {
    if heuristic && !is_sslv3_or_tls(payload) {
        return TlsOutcome {
            kind: TlsParse::Other,
            claimed: false,
            counted: None,
        };
    }
    let (kind, counted) = parse_first_hello(payload, after_tls);
    TlsOutcome {
        kind,
        claimed: true,
        counted,
    }
}

fn parse_first_hello(payload: &[u8], after_tls: bool) -> (TlsParse, Option<&'static str>) {
    if payload.len() < RECORD_HEADER {
        return (TlsParse::Unproved, None);
    }
    let Some((content, version, length)) = tls_record_header(payload) else {
        return if payload[0] == CONTENT_HANDSHAKE {
            (TlsParse::Unproved, None)
        } else {
            (TlsParse::Other, None)
        };
    };
    if !is_record_version(version) {
        return if after_tls {
            (TlsParse::Unproved, None)
        } else {
            (TlsParse::Other, None)
        };
    }
    if length == 0 {
        if content == CONTENT_HANDSHAKE {
            return (TlsParse::Unproved, None);
        }
        return if payload.len() > RECORD_HEADER {
            (TlsParse::Unproved, None)
        } else {
            (TlsParse::Other, None)
        };
    }
    let start = RECORD_HEADER;
    let end = start.saturating_add(length);
    if end > payload.len() {
        return (TlsParse::Unproved, None);
    }
    if content != CONTENT_HANDSHAKE {
        return if payload.len() > end {
            (TlsParse::Unproved, None)
        } else {
            (TlsParse::Other, None)
        };
    }
    let body = &payload[start..end];
    if body.len() < 4 {
        return (TlsParse::Unproved, None);
    }
    let msg_type = body[0];
    let msg_len = u24(&body[1..4]);
    let msg_end = 4usize.saturating_add(msg_len);
    if msg_end > body.len() {
        return (TlsParse::Unproved, None);
    }
    let extra = msg_end < body.len() || end < payload.len();
    if msg_type != HANDSHAKE_CLIENT_HELLO {
        return if extra {
            (TlsParse::Unproved, None)
        } else {
            (TlsParse::Other, None)
        };
    }
    match parse_client_hello_sni(&body[4..msg_end]) {
        None => (TlsParse::Unproved, None),
        Some(names) => {
            let counted = if last_ext_uncertain(&body[4..msg_end]) {
                Some("tls-hello-ext-uncertain")
            } else if extra {
                Some("tls-handshake")
            } else {
                None
            };
            (TlsParse::ClientHello(names), counted)
        }
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
fn is_record_version(version: u16) -> bool {
    matches!(version, 0x0300 | 0x0301 | 0x0302 | 0x0303 | 0x0304 | 0x0101)
}

/// Versions that `is_sslv3_or_tls` accepts on the first record.
fn is_sticky_version(version: u16) -> bool {
    matches!(version, 0x0300 | 0x0301 | 0x0302 | 0x0303 | 0x0101)
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

/// Bytes of `payload` from the incomplete record onward.
///
/// tshark 4.6.9 sets `desegment_offset` at that record, so a completing segment
/// is parsed without the ClientHellos that already finished in the prefix.
/// Complete records, including length-0 CCS/alert/app-data/handshake, are
/// skipped so a following truncated handshake stays in `tls_need`. An incomplete
/// record whose version fails `ssl_looks_like_sslv3` is kept too: after claimed
/// TLS, tshark 4.6.9 still desegments it, and the completing segment must be
/// counted instead of parsed as a new payload.
pub fn truncated_handshake_prefix(payload: &[u8]) -> Option<&[u8]> {
    let mut offset = 0;
    while offset < payload.len() {
        let rest = &payload[offset..];
        if rest.len() < RECORD_HEADER {
            return Some(rest);
        }
        let (content, version, length) = tls_record_header(rest)?;
        let need = RECORD_HEADER + length;
        if !is_record_version(version) {
            return (need > rest.len()).then_some(rest);
        }
        if need > rest.len() {
            return Some(rest);
        }
        if length == 0 {
            offset += RECORD_HEADER;
            continue;
        }
        if content == CONTENT_HANDSHAKE {
            let body = &rest[RECORD_HEADER..need];
            if body.len() < 4 {
                return Some(rest);
            }
            let msg_end = 4usize.saturating_add(u24(&body[1..4]));
            if msg_end > body.len() {
                return Some(rest);
            }
        }
        offset += need;
    }
    None
}

/// ClientHello body only. QUIC Initials reuse this.
pub fn parse_client_hello_sni(hello: &[u8]) -> Option<Vec<String>> {
    let (mut offset, ext_end) = hello_ext_range(hello)?;
    let mut names = Vec::new();
    while offset < ext_end {
        if offset + 4 > ext_end {
            return None;
        }
        let typ = u16::from_be_bytes([hello[offset], hello[offset + 1]]);
        let len = u16::from_be_bytes([hello[offset + 2], hello[offset + 3]]) as usize;
        offset += 4;
        let end = offset.checked_add(len)?;
        if end > ext_end {
            return Some(names);
        }
        if typ == EXT_SERVER_NAME {
            names.extend(parse_server_name(&hello[offset..end])?);
        }
        offset = end;
    }
    Some(names)
}

fn last_ext_uncertain(hello: &[u8]) -> bool {
    let Some((mut offset, ext_end)) = hello_ext_range(hello) else {
        return false;
    };
    let mut last = None;
    while offset + 4 <= ext_end {
        let typ = u16::from_be_bytes([hello[offset], hello[offset + 1]]);
        let len = u16::from_be_bytes([hello[offset + 2], hello[offset + 3]]) as usize;
        let next = match offset.checked_add(4).and_then(|data| data.checked_add(len)) {
            Some(next) if next <= ext_end => next,
            _ => break,
        };
        last = Some(typ);
        offset = next;
    }
    last.is_some_and(|typ| {
        matches!(
            typ,
            EXT_ALPN
                | EXT_STATUS_REQUEST_V2
                | EXT_PRE_SHARED_KEY
                | EXT_CERTIFICATE_AUTHORITIES
                | EXT_OID_FILTERS
        )
    })
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

    #[test]
    fn sni_name_is_proved() {
        assert_eq!(
            parse_tls(&client_hello(Some("www.example.com")), true).kind,
            TlsParse::ClientHello(vec!["www.example.com".to_string()])
        );
    }

    #[test]
    fn client_hello_without_sni_is_proved_empty() {
        assert_eq!(
            parse_tls(&client_hello(None), true).kind,
            TlsParse::ClientHello(Vec::new())
        );
    }

    #[test]
    fn http_on_443_is_other() {
        assert_eq!(parse_tls(b"GET / HTTP/1.1\r\n", true).kind, TlsParse::Other);
    }

    #[test]
    fn truncated_record_is_unproved() {
        let mut hello = client_hello(Some("a.example"));
        hello.truncate(hello.len() - 4);
        assert_eq!(parse_tls(&hello, true).kind, TlsParse::Unproved);
    }

    #[test]
    fn handshake_past_record_is_unproved() {
        let mut hs = handshake(HANDSHAKE_CLIENT_HELLO, &[0u8; 64]);
        hs[1..4].copy_from_slice(&[0, 1, 0]);
        let rec = record(CONTENT_HANDSHAKE, 0x0303, &hs);
        assert_eq!(parse_tls(&rec, true).kind, TlsParse::Unproved);
    }

    #[test]
    fn app_data_is_other() {
        let rec = record(0x17, 0x0303, &[1, 2, 3, 4]);
        assert_eq!(parse_tls(&rec, true).kind, TlsParse::Other);
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
            parse_tls(&hello, false).kind,
            TlsParse::ClientHello(vec!["fuzz.example".to_string()])
        );
    }

    #[test]
    fn unknown_record_version_is_other() {
        let mut hello = client_hello(Some("www.example.com"));
        hello[1] = 0x03;
        hello[2] = 0x10;
        assert_eq!(parse_tls(&hello, false).kind, TlsParse::Other);
    }

    #[test]
    fn ssl_looks_like_sslv3_rejects_grease_dtls_drafts_and_ssl2() {
        for version in [
            0x0a0au16, 0x0002, 0x0100, 0x7f1c, 0xfb17, 0xfeff, 0xfefd, 0xfefc,
        ] {
            let mut hello = client_hello(Some("www.example.com"));
            hello[1..3].copy_from_slice(&version.to_be_bytes());
            assert_eq!(
                parse_tls(&hello, false).kind,
                TlsParse::Other,
                "{version:#06x}"
            );
        }
    }

    #[test]
    fn unnamed_port_rejects_tls13_record_version() {
        let hello = client_hello_bytes(Some(b"www.example.com"), 0x0304);
        assert_eq!(parse_tls(&hello, true).kind, TlsParse::Other);
        assert_eq!(
            parse_tls(&hello, false).kind,
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
            assert_eq!(parse_tls(&payload, true).kind, TlsParse::Other);
        }
        let mut app = record(0x17, 0x0303, &[1]);
        app.extend_from_slice(&hello);
        assert_eq!(parse_tls(&app, true).kind, TlsParse::Unproved);
        assert_eq!(parse_tls(&app, true).counted, None);
    }

    #[test]
    fn sni_stops_at_first_nul() {
        assert_eq!(ascii_name(b"www\0.example"), "www");
        assert_eq!(ascii_name(b"www.example\0"), "www.example");
        assert_eq!(ascii_name(b"a\0b\0c"), "a");
        assert_eq!(
            parse_tls(&client_hello_bytes(Some(b"www\0.example"), 0x0301), false).kind,
            TlsParse::ClientHello(vec!["www".to_string()])
        );
    }

    #[test]
    fn split_record_stitches_when_concatenated() {
        let hello = client_hello(Some("www.example.com"));
        let cut = 40;
        assert_eq!(parse_tls(&hello[..cut], true).kind, TlsParse::Unproved);
        let prefix = truncated_handshake_prefix(&hello[..cut]).unwrap_or(&hello[..cut]);
        let mut stitched = prefix.to_vec();
        stitched.extend_from_slice(&hello[cut..]);
        assert_eq!(
            parse_tls(&stitched, true).kind,
            TlsParse::ClientHello(vec!["www.example.com".to_string()])
        );
    }

    #[test]
    fn truncated_handshake_prefix_skips_complete_and_empty_records() {
        let hello = client_hello(Some("www.example.com"));
        let cut = 40;
        let prefixes = [
            record(0x14, 0x0303, &[0x01]),
            vec![0x14, 0x03, 0x03, 0x00, 0x00],
            record(0x15, 0x0303, &[0x02, 0x28]),
            record(0x17, 0x0303, &[0x01]),
            record(CONTENT_HANDSHAKE, 0x0303, &handshake(0, &[])),
        ];
        for prefix in prefixes {
            let mut payload = prefix.clone();
            payload.extend_from_slice(&hello[..cut]);
            assert_eq!(
                truncated_handshake_prefix(&payload),
                Some(&hello[..cut]),
                "prefix {:02x?}",
                &prefix[..prefix.len().min(5)]
            );
        }
        let mut two = hello.clone();
        two.extend_from_slice(&client_hello(Some("other.example"))[..10]);
        assert_eq!(
            truncated_handshake_prefix(&two),
            Some(&client_hello(Some("other.example"))[..10])
        );
        assert_eq!(truncated_handshake_prefix(&hello), None);
        assert_eq!(
            truncated_handshake_prefix(&record(0x14, 0x0303, &[0x01])),
            None
        );
    }

    #[test]
    fn truncated_handshake_prefix_keeps_incomplete_non_sslv3_records() {
        let mut grease = client_hello(Some("www.example.com"));
        grease[1..3].copy_from_slice(&0x0a0au16.to_be_bytes());
        let cut = 40;
        assert!(grease.len() > cut);
        assert_eq!(
            truncated_handshake_prefix(&grease[..cut]),
            Some(&grease[..cut])
        );
        let mut ccs_grease = record(0x14, 0x0303, &[0x01]);
        ccs_grease.extend_from_slice(&grease[..cut]);
        assert_eq!(
            truncated_handshake_prefix(&ccs_grease),
            Some(&grease[..cut])
        );
        assert_eq!(truncated_handshake_prefix(&grease), None);
        for version in [0x0002u16, 0x0100, 0x7f1c, 0xfb17, 0xfeff, 0x0305] {
            let mut hello = client_hello(Some("www.example.com"));
            hello[1..3].copy_from_slice(&version.to_be_bytes());
            assert_eq!(
                truncated_handshake_prefix(&hello[..cut]),
                Some(&hello[..cut]),
                "{version:#06x}"
            );
        }
    }

    #[test]
    fn grease_after_a_prior_tls_record_is_unproved() {
        let mut hello = client_hello(Some("www.example.com"));
        hello[1..3].copy_from_slice(&0x0a0au16.to_be_bytes());
        assert_eq!(parse_tls(&hello, false).kind, TlsParse::Other);
        assert_eq!(parse_tls_seen(&hello, false, true).kind, TlsParse::Unproved);
    }

    #[test]
    fn later_hello_in_the_same_payload_is_counted() {
        let first = client_hello(Some("www.example.com"));
        let second = client_hello(Some("other.example"));
        let mut body = first[5..].to_vec();
        body.extend_from_slice(&second[5..]);
        let payload = record(CONTENT_HANDSHAKE, 0x0301, &body);
        let outcome = parse_tls(&payload, false);
        assert_eq!(
            outcome.kind,
            TlsParse::ClientHello(vec!["www.example.com".to_string()])
        );
        assert_eq!(outcome.counted, Some("tls-handshake"));
    }

    #[test]
    fn parse_client_hello_sni_reads_the_hello_body() {
        let rec = client_hello(Some("quic.example"));
        let body = &rec[9..];
        assert_eq!(
            parse_client_hello_sni(body).as_deref(),
            Some(["quic.example".to_string()].as_slice())
        );
    }
}
