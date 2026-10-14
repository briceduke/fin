//! Classic little-endian pcap builders for the ip.src corpus.

const MAGIC: [u8; 4] = [0xd4, 0xc3, 0xb2, 0xa1];
const ETH_DST: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
const ETH_SRC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

pub const LINK_ETHERNET: u32 = 1;
pub const LINK_SLL: u32 = 113;
pub const LINK_SLL2: u32 = 276;

pub fn pcap(link: u32, frames: &[Vec<u8>]) -> Vec<u8> {
    let mut file = Vec::new();
    file.extend_from_slice(&MAGIC);
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

pub fn cut(frame: &[u8], len: usize) -> Vec<u8> {
    frame.get(..len).unwrap_or(frame).to_vec()
}

pub fn eth(etype: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::from(ETH_DST);
    frame.extend_from_slice(&ETH_SRC);
    frame.extend_from_slice(&etype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

pub fn vlan(inner: u16, payload: &[u8]) -> Vec<u8> {
    vlan_etype(0x8100, inner, payload)
}

pub fn vlan_etype(outer: u16, inner: u16, payload: &[u8]) -> Vec<u8> {
    let mut tag = Vec::from(0x0001u16.to_be_bytes());
    tag.extend_from_slice(&inner.to_be_bytes());
    tag.extend_from_slice(payload);
    eth(outer, &tag)
}

pub fn qinq(payload: &[u8]) -> Vec<u8> {
    let mut inner = Vec::from(0x0014u16.to_be_bytes());
    inner.extend_from_slice(&0x0800u16.to_be_bytes());
    inner.extend_from_slice(payload);
    let mut outer = Vec::from(0x000au16.to_be_bytes());
    outer.extend_from_slice(&0x8100u16.to_be_bytes());
    outer.extend_from_slice(&inner);
    eth(0x88a8, &outer)
}

pub fn sll(proto: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0, 0, 0, 1, 0, 6];
    frame.extend_from_slice(&ETH_SRC);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&proto.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

pub fn sll2(proto: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::from(proto.to_be_bytes());
    frame.extend_from_slice(&[0, 0, 0, 0, 0, 1, 0, 1, 0, 6]);
    frame.extend_from_slice(&ETH_SRC);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(payload);
    frame
}

pub fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, payload: &[u8]) -> Vec<u8> {
    ipv4_frag(src, dst, proto, 0, 0, false, payload)
}

pub fn ipv4_frag(
    src: [u8; 4],
    dst: [u8; 4],
    proto: u8,
    id: u16,
    offset: u16,
    more: bool,
    payload: &[u8],
) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, proto, 0, 0];
    ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    ip[4..6].copy_from_slice(&id.to_be_bytes());
    let flags = (offset & 0x1fff) | if more { 0x2000 } else { 0 };
    ip[6..8].copy_from_slice(&flags.to_be_bytes());
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    ip.extend_from_slice(payload);
    ip
}

pub fn ipv4_len(src: [u8; 4], dst: [u8; 4], proto: u8, total: u16, payload: &[u8]) -> Vec<u8> {
    let mut ip = ipv4(src, dst, proto, payload);
    ip[2..4].copy_from_slice(&total.to_be_bytes());
    ip
}

pub fn ipv4_ihl(src: [u8; 4], ihl_words: u8, payload: &[u8]) -> Vec<u8> {
    let header = ihl_words as usize * 4;
    let total = header + payload.len();
    let mut ip = vec![0u8; header];
    ip[0] = 0x40 | (ihl_words & 0x0f);
    ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    if header >= 16 {
        ip[12..16].copy_from_slice(&src);
    }
    if header >= 20 {
        ip[16..20].copy_from_slice(&[10, 255, 255, 1]);
    }
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

pub fn ipv6_len(next: u8, plen: u16, payload: &[u8]) -> Vec<u8> {
    let mut ip = ipv6(next, payload);
    ip[4..6].copy_from_slice(&plen.to_be_bytes());
    ip
}

pub fn hopopt(next: u8, payload: &[u8]) -> Vec<u8> {
    let mut ext = vec![next, 0, 0, 0, 0, 0, 0, 0];
    ext.extend_from_slice(payload);
    ext
}

pub fn ipv6_frag(next: u8, offset: u16, more: bool, id: u32, payload: &[u8]) -> Vec<u8> {
    let mut hdr = vec![next, 0, 0, 0, 0, 0, 0, 0];
    let field = (offset << 3) | if more { 1 } else { 0 };
    hdr[2..4].copy_from_slice(&field.to_be_bytes());
    hdr[4..8].copy_from_slice(&id.to_be_bytes());
    hdr.extend_from_slice(payload);
    hdr
}

pub fn ah(next: u8, payload: &[u8]) -> Vec<u8> {
    let mut ext = vec![next, 4, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1];
    ext.extend_from_slice(&[0u8; 12]);
    ext.extend_from_slice(payload);
    ext
}

pub fn udp(src: u16, dst: u16, payload: &[u8]) -> Vec<u8> {
    let mut hdr = Vec::from(src.to_be_bytes());
    hdr.extend_from_slice(&dst.to_be_bytes());
    hdr.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    hdr.extend_from_slice(&[0, 0]);
    hdr.extend_from_slice(payload);
    hdr
}

pub fn tcp(src: u16, dst: u16, payload: &[u8]) -> Vec<u8> {
    let mut hdr = Vec::from(src.to_be_bytes());
    hdr.extend_from_slice(&dst.to_be_bytes());
    hdr.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x18, 0, 64, 0, 0, 0, 0]);
    hdr.extend_from_slice(payload);
    hdr
}

pub fn icmp_error(inner: &[u8]) -> Vec<u8> {
    let mut icmp = vec![3, 0, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(inner);
    icmp
}

pub fn icmpv6_error(inner: &[u8]) -> Vec<u8> {
    let mut icmp = vec![1, 0, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(inner);
    icmp
}

pub fn vxlan(inner_eth: &[u8]) -> Vec<u8> {
    let mut hdr = vec![0x08, 0, 0, 0, 0, 0, 1, 0];
    hdr.extend_from_slice(inner_eth);
    hdr
}

pub fn etherip(inner_eth: &[u8]) -> Vec<u8> {
    let mut hdr = vec![0x30, 0x00];
    hdr.extend_from_slice(inner_eth);
    hdr
}

pub fn eth_ipv4_udp(src: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    eth(
        0x0800,
        &ipv4(src, [10, 255, 255, 1], 17, &udp(sport, dport, payload)),
    )
}

pub const OUTER: [u8; 4] = [10, 0, 0, 1];
pub const INNER: [u8; 4] = [10, 9, 9, 9];
pub const EMBED: [u8; 4] = [10, 8, 8, 8];
