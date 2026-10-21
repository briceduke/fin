//! Classic pcap / pcapng builders for the TLS SNI corpus.

const PCAP_MAGIC: [u8; 4] = [0xd4, 0xc3, 0xb2, 0xa1];
const ETH_DST: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
const ETH_SRC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

pub const LINK_ETHERNET: u32 = 1;
pub const LINK_SLL: u32 = 113;
pub const OUTER: [u8; 4] = [10, 0, 0, 1];
pub const PEER: [u8; 4] = [10, 255, 255, 1];

pub fn pcap(link: u32, frames: &[Vec<u8>]) -> Vec<u8> {
    let mut file = Vec::new();
    file.extend_from_slice(&PCAP_MAGIC);
    file.extend_from_slice(&2u16.to_le_bytes());
    file.extend_from_slice(&4u16.to_le_bytes());
    file.extend_from_slice(&0u32.to_le_bytes());
    file.extend_from_slice(&0u32.to_le_bytes());
    file.extend_from_slice(&65535u32.to_le_bytes());
    file.extend_from_slice(&link.to_le_bytes());
    for frame in frames {
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        let len = frame.len() as u32;
        file.extend_from_slice(&len.to_le_bytes());
        file.extend_from_slice(&len.to_le_bytes());
        file.extend_from_slice(frame);
    }
    file
}

pub fn pcapng(link: u16, frames: &[Vec<u8>]) -> Vec<u8> {
    let mut file = section_header();
    file.extend_from_slice(&interface_block(link));
    for frame in frames {
        file.extend_from_slice(&enhanced_packet(frame));
    }
    file
}

pub fn eth(etype: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::from(ETH_DST);
    frame.extend_from_slice(&ETH_SRC);
    frame.extend_from_slice(&etype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

pub fn vlan(inner: u16, payload: &[u8]) -> Vec<u8> {
    let mut tag = Vec::from(0x0001u16.to_be_bytes());
    tag.extend_from_slice(&inner.to_be_bytes());
    tag.extend_from_slice(payload);
    eth(0x8100, &tag)
}

pub fn sll(proto: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0, 0, 0, 1, 0, 6];
    frame.extend_from_slice(&ETH_SRC);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&proto.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

pub fn ipv4(src: [u8; 4], proto: u8, payload: &[u8]) -> Vec<u8> {
    ipv4_to(src, PEER, proto, payload)
}

pub fn ipv4_to(src: [u8; 4], dst: [u8; 4], proto: u8, payload: &[u8]) -> Vec<u8> {
    let total = (20 + payload.len()) as u16;
    let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, proto, 0, 0];
    ip[2..4].copy_from_slice(&total.to_be_bytes());
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    ip.extend_from_slice(payload);
    ip
}

pub fn ipv6(next: u8, payload: &[u8]) -> Vec<u8> {
    let mut ip = vec![0x60, 0, 0, 0, 0, 0, next, 64];
    ip[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    ip.extend_from_slice(&[0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    ip.extend_from_slice(&[0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    ip.extend_from_slice(payload);
    ip
}

pub fn tcp(src: u16, dst: u16, payload: &[u8]) -> Vec<u8> {
    tcp_seq(src, dst, 1, payload)
}

pub fn tcp_seq(src: u16, dst: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    let mut hdr = Vec::from(src.to_be_bytes());
    hdr.extend_from_slice(&dst.to_be_bytes());
    hdr.extend_from_slice(&seq.to_be_bytes());
    hdr.extend_from_slice(&[0, 0, 0, 0, 0x50, 0x18, 0, 64, 0, 0, 0, 0]);
    hdr.extend_from_slice(payload);
    hdr
}

pub fn udp(src: u16, dst: u16, payload: &[u8]) -> Vec<u8> {
    let mut hdr = Vec::from(src.to_be_bytes());
    hdr.extend_from_slice(&dst.to_be_bytes());
    hdr.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    hdr.extend_from_slice(&[0, 0]);
    hdr.extend_from_slice(payload);
    hdr
}

pub fn eth_ipv4_tcp(src: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    eth_ipv4_tcp_seq(src, sport, dport, 1, payload)
}

pub fn eth_ipv4_tcp_seq(src: [u8; 4], sport: u16, dport: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    eth_ipv4_tcp_flow(src, PEER, sport, dport, seq, payload)
}

pub fn eth_ipv4_tcp_flow(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    seq: u32,
    payload: &[u8],
) -> Vec<u8> {
    eth(
        0x0800,
        &ipv4_to(src, dst, 6, &tcp_seq(sport, dport, seq, payload)),
    )
}

pub fn eth_ipv4_udp(src: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    eth(0x0800, &ipv4(src, 17, &udp(sport, dport, payload)))
}

pub fn client_hello(sni: Option<&str>) -> Vec<u8> {
    client_hello_host(sni.map(str::as_bytes), 0x0301)
}

pub fn client_hello_host(sni: Option<&[u8]>, version: u16) -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0x11u8; 32]);
    body.push(0);
    body.extend_from_slice(&[0, 2, 0x00, 0x2f]);
    body.extend_from_slice(&[1, 0]);
    match sni {
        None => body.extend_from_slice(&[0, 0]),
        Some(host) => {
            let entry_len = 1 + 2 + host.len();
            let sni_data_len = 2 + entry_len;
            let ext_len = 4 + sni_data_len;
            body.extend_from_slice(&(ext_len as u16).to_be_bytes());
            body.extend_from_slice(&[0, 0]);
            body.extend_from_slice(&(sni_data_len as u16).to_be_bytes());
            body.extend_from_slice(&(entry_len as u16).to_be_bytes());
            body.push(0);
            body.extend_from_slice(&(host.len() as u16).to_be_bytes());
            body.extend_from_slice(host);
        }
    }
    let mut rec = handshake_record(&handshake(1, &body));
    rec[1..3].copy_from_slice(&version.to_be_bytes());
    rec
}

pub fn ccs() -> Vec<u8> {
    ccs_version(0x0303)
}

pub fn ccs_version(version: u16) -> Vec<u8> {
    let mut rec = vec![0x14];
    rec.extend_from_slice(&version.to_be_bytes());
    rec.extend_from_slice(&[0x00, 0x01, 0x01]);
    rec
}

pub fn alert() -> Vec<u8> {
    vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]
}

pub fn app_data() -> Vec<u8> {
    vec![0x17, 0x03, 0x03, 0x00, 0x01, 0x01]
}

pub fn heartbeat() -> Vec<u8> {
    vec![0x18, 0x03, 0x03, 0x00, 0x03, 0x01, 0x00, 0x00]
}

pub fn client_hello_early_data() -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0x11u8; 32]);
    body.push(0);
    body.extend_from_slice(&[0, 2, 0x00, 0x2f]);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&[0, 4, 0, 42, 0, 0]);
    handshake_record(&handshake(1, &body))
}

pub fn empty_record(content: u8) -> Vec<u8> {
    vec![content, 0x03, 0x03, 0x00, 0x00]
}

pub fn handshake_record(body: &[u8]) -> Vec<u8> {
    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
    rec.extend_from_slice(body);
    rec
}

pub fn handshake_type_record(msg_type: u8, version: u16) -> Vec<u8> {
    handshake_body_record(msg_type, version, &[])
}

pub fn handshake_body_record(msg_type: u8, version: u16, body: &[u8]) -> Vec<u8> {
    handshake_messages_record(version, &[(msg_type, body)])
}

pub fn handshake_messages_record(version: u16, messages: &[(u8, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    for &(msg_type, msg_body) in messages {
        body.extend_from_slice(&handshake(msg_type, msg_body));
    }
    let mut rec = handshake_record(&body);
    rec[1..3].copy_from_slice(&version.to_be_bytes());
    rec
}

pub fn tls_record(content: u8, version: u16, body: &[u8]) -> Vec<u8> {
    let mut rec = vec![content];
    rec.extend_from_slice(&version.to_be_bytes());
    rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
    rec.extend_from_slice(body);
    rec
}

pub fn server_hello() -> Vec<u8> {
    let mut hello = Vec::from(0x0303u16.to_be_bytes());
    hello.extend_from_slice(&[0x22u8; 32]);
    hello.push(0);
    hello.extend_from_slice(&[0x00, 0x2f]);
    hello.push(0);
    handshake_body_record(2, 0x0303, &hello)
}

pub fn tls13_server_hello() -> Vec<u8> {
    let mut hello = Vec::from(0x0303u16.to_be_bytes());
    hello.extend_from_slice(&[0x22u8; 32]);
    hello.push(0);
    hello.extend_from_slice(&[0x13, 0x01]);
    hello.push(0);
    hello.extend_from_slice(&[0x00, 0x06, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
    let mut rec = handshake_record(&handshake(2, &hello));
    rec[1..3].copy_from_slice(&0x0303u16.to_be_bytes());
    rec
}

fn handshake(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let len = body.len() as u32;
    let mut out = vec![msg_type, (len >> 16) as u8, (len >> 8) as u8, len as u8];
    out.extend_from_slice(body);
    out
}

fn section_header() -> Vec<u8> {
    let mut block = vec![0x0a, 0x0d, 0x0d, 0x0a];
    block.extend_from_slice(&28u32.to_le_bytes());
    block.extend_from_slice(&0x1a2b3c4du32.to_le_bytes());
    block.extend_from_slice(&1u16.to_le_bytes());
    block.extend_from_slice(&0u16.to_le_bytes());
    block.extend_from_slice(&(-1i64).to_le_bytes());
    block.extend_from_slice(&28u32.to_le_bytes());
    block
}

fn interface_block(link: u16) -> Vec<u8> {
    let mut body = Vec::from(link.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&65535u32.to_le_bytes());
    block(1, &body)
}

fn enhanced_packet(frame: &[u8]) -> Vec<u8> {
    let mut body = Vec::from(0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    let len = frame.len() as u32;
    body.extend_from_slice(&len.to_le_bytes());
    body.extend_from_slice(&len.to_le_bytes());
    body.extend_from_slice(frame);
    while body.len() % 4 != 0 {
        body.push(0);
    }
    block(6, &body)
}

fn block(kind: u32, body: &[u8]) -> Vec<u8> {
    let total = (12 + body.len()) as u32;
    let mut out = Vec::from(kind.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(&total.to_le_bytes());
    out
}
