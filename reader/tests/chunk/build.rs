//! Compact pcap and pcapng builders for chunk tests.

pub const LE_USEC: [u8; 4] = [0xd4, 0xc3, 0xb2, 0xa1];
pub const BE_USEC: [u8; 4] = [0xa1, 0xb2, 0xc3, 0xd4];
pub const LE_NSEC: [u8; 4] = [0x4d, 0x3c, 0xb2, 0xa1];
pub const BE_NSEC: [u8; 4] = [0xa1, 0xb2, 0x3c, 0x4d];

#[derive(Clone, Copy)]
pub enum Endian {
    Little,
    Big,
}

pub fn pack_u16(value: u16, endian: Endian) -> [u8; 2] {
    match endian {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    }
}

pub fn pack_u32(value: u32, endian: Endian) -> [u8; 4] {
    match endian {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    }
}

pub fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

fn pad4(bytes: &[u8]) -> Vec<u8> {
    let mut padded = bytes.to_vec();
    while !padded.len().is_multiple_of(4) {
        padded.push(0);
    }
    padded
}

fn u16_bytes(value: u16, big: bool) -> [u8; 2] {
    if big {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    }
}

fn u32_bytes(value: u32, big: bool) -> [u8; 4] {
    if big {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    }
}

pub fn pcap_header(magic: [u8; 4], link_type: u32) -> Vec<u8> {
    let big = magic[0] == 0xa1;
    let mut file = magic.to_vec();
    file.extend_from_slice(&u16_bytes(2, big));
    file.extend_from_slice(&u16_bytes(4, big));
    file.extend_from_slice(&[0; 8]);
    file.extend_from_slice(&u32_bytes(65535, big));
    file.extend_from_slice(&u32_bytes(link_type, big));
    file
}

fn push_pcap_packet(file: &mut Vec<u8>, body: &[u8]) {
    let big = file[0] == 0xa1;
    file.extend_from_slice(&u32_bytes(1, big));
    file.extend_from_slice(&u32_bytes(0, big));
    file.extend_from_slice(&u32_bytes(body.len() as u32, big));
    file.extend_from_slice(&u32_bytes(body.len() as u32, big));
    file.extend_from_slice(body);
}

pub fn pcap_file(magic: [u8; 4], packets: &[&[u8]]) -> Vec<u8> {
    let mut file = pcap_header(magic, 1);
    for packet in packets {
        push_pcap_packet(&mut file, packet);
    }
    file
}

pub fn eth_ipv4_udp(src: [u8; 4], n: u8) -> Vec<u8> {
    let mut eth = vec![0u8; 14];
    eth[12] = 0x08;
    eth[13] = 0x00;
    let mut ip = vec![0x45, 0, 0, 48, 0, 0, 0, 0, 64, 17, 0, 0];
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&[10, 0, 0, 2]);
    let mut udp = vec![0, 9, 0, 9, 0, 16, 0, 0];
    udp.extend_from_slice(&[n, b'f', b'i', b'n', 0, 0, 0, 0]);
    concat(&[&eth, &ip, &udp])
}

pub fn many_pcap(count: usize) -> Vec<u8> {
    many_pcap_with(LE_USEC, count)
}

pub fn many_pcap_with(magic: [u8; 4], count: usize) -> Vec<u8> {
    let packets: Vec<Vec<u8>> = (0..count)
        .map(|i| eth_ipv4_udp([10, 0, 0, 1], i as u8))
        .collect();
    let refs: Vec<&[u8]> = packets.iter().map(|p| p.as_slice()).collect();
    pcap_file(magic, &refs)
}

pub fn section_header(endian: Endian) -> Vec<u8> {
    let total = pack_u32(28, endian);
    concat(&[
        &[0x0a, 0x0d, 0x0d, 0x0a],
        &total,
        &pack_u32(0x1A2B3C4D, endian),
        &pack_u16(1, endian),
        &pack_u16(0, endian),
        &[0xff; 8],
        &total,
    ])
}

fn block(endian: Endian, block_type: u32, body: &[u8]) -> Vec<u8> {
    let padded = pad4(body);
    let total = pack_u32((12 + padded.len()) as u32, endian);
    concat(&[&pack_u32(block_type, endian), &total, &padded, &total])
}

pub fn interface_block(endian: Endian, link_type: u16) -> Vec<u8> {
    let body = concat(&[
        &pack_u16(link_type, endian),
        &pack_u16(0, endian),
        &pack_u32(65535, endian),
    ]);
    block(endian, 1, &body)
}

pub fn enhanced_packet(endian: Endian, interface_id: u32, packet: &[u8]) -> Vec<u8> {
    let body = concat(&[
        &pack_u32(interface_id, endian),
        &pack_u32(0, endian),
        &pack_u32(0, endian),
        &pack_u32(packet.len() as u32, endian),
        &pack_u32(packet.len() as u32, endian),
        &pad4(packet),
    ]);
    block(endian, 6, &body)
}

pub fn many_pcapng(endian: Endian, count: usize) -> Vec<u8> {
    let mut parts = vec![section_header(endian), interface_block(endian, 1)];
    let packets: Vec<Vec<u8>> = (0..count)
        .map(|i| eth_ipv4_udp([10, 0, 0, 1], i as u8))
        .collect();
    for packet in &packets {
        parts.push(enhanced_packet(endian, 0, packet));
    }
    let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
    concat(&refs)
}
