//! One-frame `ip.src` walk. Counts any path tshark 4.6.9 may still follow.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::ports::{snapshot, PortPick, PortTables};
use crate::Frame;

const ETHERNET: u32 = 1;
const SLL: u32 = 113;
const SLL2: u32 = 276;
const ETH_HEADER: usize = 14;
const SLL_HEADER: usize = 16;
const SLL2_HEADER: usize = 20;
const VLAN_TAG: usize = 4;
const IPV4_SRC: usize = 12;
const IPV4_MIN: usize = 20;
const IPV6_HEADER: usize = 40;
const UDP_HEADER: usize = 8;
const TCP_MIN: usize = 20;
const ICMP_HEADER: usize = 8;
const VXLAN_HEADER: usize = 8;
const AH: u8 = 51;
const ESP: u8 = 50;
const IPV6_HOP: u8 = 0;
const IPV6_ROUTE: u8 = 43;
const IPV6_FRAG: u8 = 44;
const IPV6_DEST: u8 = 60;
const IPV6_NO_NEXT: u8 = 59;
const ICMP: u8 = 1;
const TCP: u8 = 6;
const UDP: u8 = 17;
const GRE: u8 = 47;
const IPIP: u8 = 4;
const IPV6: u8 = 41;
const ICMPV6: u8 = 58;
const ETHERIP: u8 = 97;
const TEB: u16 = 0x6558;
const DEPTH: usize = 8;

/// Proved IPv4 sources from one frame, and a count if the walk stopped short.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cell {
    pub values: Vec<String>,
    pub counted: Option<&'static str>,
}

/// Fragment-group ports remembered from the first fragment.
#[derive(Debug, Default)]
struct FragTable {
    ipv4: HashMap<Ipv4Frag, Option<(u16, u16)>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Ipv4Frag {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    id: u16,
    proto: u8,
}

/// Session state for a sequential `ip.src` walk.
pub struct IpSrc {
    tables: &'static PortTables,
    frags: FragTable,
}

impl Default for IpSrc {
    fn default() -> Self {
        Self {
            tables: snapshot(),
            frags: FragTable::default(),
        }
    }
}

impl IpSrc {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn walk(&mut self, frame: &Frame<'_>) -> Cell {
        walk_ip_src(frame, self)
    }
}

/// Walk one frame. `session` holds the port snapshot and fragment groups.
pub fn walk_ip_src(frame: &Frame<'_>, session: &mut IpSrc) -> Cell {
    let mut walk = Walk {
        values: Vec::new(),
        counted: None,
        tables: session.tables,
        frags: &mut session.frags,
        depth: 0,
    };
    walk.link(frame.link_type, frame.captured);
    Cell {
        values: walk.values,
        counted: walk.counted,
    }
}

struct Walk<'a> {
    values: Vec<String>,
    counted: Option<&'static str>,
    tables: &'static PortTables,
    frags: &'a mut FragTable,
    depth: usize,
}

impl Walk<'_> {
    fn count(&mut self, reason: &'static str) {
        if self.counted.is_none() {
            self.counted = Some(reason);
        }
    }

    fn nest(&mut self) -> bool {
        if self.depth >= DEPTH {
            self.count("other");
            return false;
        }
        self.depth += 1;
        true
    }

    fn link(&mut self, link_type: u32, bytes: &[u8]) {
        match link_type {
            ETHERNET => self.ethernet(bytes),
            SLL => self.sll(bytes),
            SLL2 => self.sll2(bytes),
            _ => self.count("unsupported-link"),
        }
    }

    fn ethernet(&mut self, bytes: &[u8]) {
        if bytes.len() < ETH_HEADER {
            return;
        }
        let etype = u16::from_be_bytes([bytes[12], bytes[13]]);
        self.ethertype(etype, &bytes[ETH_HEADER..]);
    }

    fn sll(&mut self, bytes: &[u8]) {
        if bytes.len() < SLL_HEADER {
            return;
        }
        let proto = u16::from_be_bytes([bytes[14], bytes[15]]);
        self.cooked(proto, &bytes[SLL_HEADER..]);
    }

    fn sll2(&mut self, bytes: &[u8]) {
        if bytes.len() < SLL2_HEADER {
            return;
        }
        let proto = u16::from_be_bytes([bytes[0], bytes[1]]);
        self.cooked(proto, &bytes[SLL2_HEADER..]);
    }

    fn cooked(&mut self, proto: u16, payload: &[u8]) {
        if proto <= 1536 {
            if !payload.is_empty() {
                self.count("llc");
            }
            return;
        }
        self.ethertype(proto, payload);
    }

    fn ethertype(&mut self, mut etype: u16, mut payload: &[u8]) {
        loop {
            if !is_vlan(etype) {
                break;
            }
            if payload.len() < VLAN_TAG {
                return;
            }
            etype = u16::from_be_bytes([payload[2], payload[3]]);
            payload = &payload[VLAN_TAG..];
        }
        match etype {
            0x0800 => self.ipv4(payload),
            0x86dd => self.ipv6(payload),
            TEB => {
                if self.nest() {
                    self.ethernet(payload);
                }
            }
            0x8847 | 0x8848 => self.maybe("mpls", payload),
            0x8863 | 0x8864 => self.maybe("pppoe", payload),
            etype if etype <= 1536 => self.maybe("llc", payload),
            _ => self.maybe("ethertype", payload),
        }
    }

    fn maybe(&mut self, reason: &'static str, payload: &[u8]) {
        if !payload.is_empty() {
            self.count(reason);
        }
    }

    fn ipv4(&mut self, bytes: &[u8]) {
        if bytes.len() < IPV4_SRC + 4 {
            return;
        }
        if bytes[0] >> 4 == 6 {
            self.ipv6(bytes);
            return;
        }
        if bytes[0] >> 4 != 4 {
            return;
        }
        let ihl = (bytes[0] & 0x0f) as usize * 4;
        if ihl < IPV4_MIN {
            return;
        }
        let total = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        if total != 0 && total < ihl {
            return;
        }
        let src = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
        self.values.push(src.to_string());
        if bytes.len() < ihl {
            return;
        }
        let dst = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
        let id = u16::from_be_bytes([bytes[4], bytes[5]]);
        let frag = u16::from_be_bytes([bytes[6], bytes[7]]);
        let offset = frag & 0x1fff;
        let more = frag & 0x2000 != 0;
        let proto = bytes[9];
        let rest = &bytes[ihl..];
        let payload = if total == 0 {
            rest
        } else {
            take_len(rest, total - ihl)
        };
        let fragmented = more || offset != 0;
        if fragmented {
            self.ipv4_fragment(src, dst, id, proto, offset, payload);
            return;
        }
        self.ip_proto(proto, payload, false);
    }

    fn ipv4_fragment(
        &mut self,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        id: u16,
        proto: u8,
        offset: u16,
        payload: &[u8],
    ) {
        if proto != UDP {
            self.count("fragment");
            return;
        }
        let key = Ipv4Frag {
            src,
            dst,
            id,
            proto,
        };
        if offset == 0 {
            let ports = udp_ports(payload);
            self.frags.ipv4.insert(key, ports);
            if let Some((src_port, dst_port)) = ports {
                if self.udp_counts_or_vxlan(src_port, dst_port) {
                    self.count("fragment");
                }
            } else {
                self.count("fragment");
            }
            return;
        }
        match self.frags.ipv4.get(&key).copied() {
            None => {
                self.frags.ipv4.insert(key, None);
                self.count("fragment");
            }
            Some(None) => self.count("fragment"),
            Some(Some((src_port, dst_port))) => {
                if self.udp_counts_or_vxlan(src_port, dst_port) {
                    self.count("fragment");
                }
            }
        }
    }

    fn ipv6(&mut self, bytes: &[u8]) {
        if bytes.len() < IPV6_HEADER {
            return;
        }
        if bytes[0] >> 4 != 6 {
            return;
        }
        let plen = u16::from_be_bytes([bytes[4], bytes[5]]) as u32;
        let mut next = bytes[6];
        let body = &bytes[IPV6_HEADER..];
        let want = if plen == 0 && next == IPV6_HOP {
            jumbo_payload_len(body).unwrap_or(0)
        } else {
            plen
        };
        let mut rest = take_ipv6_payload(body, want);
        loop {
            match next {
                IPV6_NO_NEXT => return,
                ESP => return,
                AH => {
                    let Some((nxt, body)) = take_ah(rest) else {
                        return;
                    };
                    next = nxt;
                    rest = body;
                }
                IPV6_HOP | IPV6_DEST => {
                    let Some((nxt, body)) = take_opts(rest) else {
                        return;
                    };
                    next = nxt;
                    rest = body;
                }
                IPV6_ROUTE => {
                    let Some((nxt, body)) = take_routing(rest) else {
                        return;
                    };
                    next = nxt;
                    rest = body;
                }
                IPV6_FRAG => {
                    if rest.len() < 8 {
                        return;
                    }
                    let frag_off = u16::from_be_bytes([rest[2], rest[3]]) >> 3;
                    let more = rest[3] & 1 != 0;
                    next = rest[0];
                    rest = &rest[8..];
                    if more || frag_off != 0 {
                        self.count("fragment");
                        return;
                    }
                }
                _ => {
                    self.ip_proto(next, rest, true);
                    return;
                }
            }
        }
    }

    fn ip_proto(&mut self, proto: u8, payload: &[u8], over_ipv6: bool) {
        match proto {
            ICMP => self.icmp(payload),
            ICMPV6 => self.icmpv6(payload),
            TCP => self.tcp(payload),
            UDP => self.udp(payload, over_ipv6),
            IPIP => {
                if self.nest() {
                    self.ipv4(payload);
                }
            }
            IPV6 => {
                if self.nest() {
                    self.ipv6(payload);
                }
            }
            GRE => self.maybe("gre", payload),
            AH => {
                let Some((nxt, body)) = take_ah(payload) else {
                    return;
                };
                if self.nest() {
                    self.ip_proto(nxt, body, over_ipv6);
                }
            }
            ETHERIP => {
                if payload.len() < 2 {
                    return;
                }
                if self.nest() {
                    self.ethernet(&payload[2..]);
                }
            }
            ESP => {}
            _ => self.maybe("ip-proto", payload),
        }
    }

    fn icmp(&mut self, bytes: &[u8]) {
        if bytes.len() < ICMP_HEADER {
            return;
        }
        if matches!(bytes[0], 3 | 4 | 5 | 11 | 12) {
            let mut embed = &bytes[ICMP_HEADER..];
            if bytes[0] == 5 && !embed.is_empty() {
                let cap = ((embed[0] & 0x0f) as usize) * 4 + 8;
                embed = take_len(embed, cap);
            } else if let Some(cap) = rfc4884_embed_len(bytes) {
                embed = take_len(embed, cap);
            }
            self.embedded_ipv4(embed);
        }
    }

    fn icmpv6(&mut self, bytes: &[u8]) {
        if bytes.len() < ICMP_HEADER {
            return;
        }
        if matches!(bytes[0], 1..=4) && bytes.len() > ICMP_HEADER + IPV6_HEADER {
            self.count("icmp");
        }
    }

    fn embedded_ipv4(&mut self, bytes: &[u8]) {
        if bytes.len() < IPV4_SRC + 4 {
            return;
        }
        if bytes[0] >> 4 == 6 {
            self.ipv6(bytes);
            return;
        }
        if bytes[0] >> 4 != 4 {
            return;
        }
        let ihl = (bytes[0] & 0x0f) as usize * 4;
        if ihl < IPV4_MIN {
            return;
        }
        let total = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        if total != 0 && total < ihl {
            if bytes.len() > ihl {
                self.count("icmp");
            }
            return;
        }
        self.values
            .push(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]).to_string());
        if bytes.len() > ihl {
            self.count("icmp");
        }
    }

    fn udp(&mut self, bytes: &[u8], over_ipv6: bool) {
        let Some((src, dst)) = udp_ports(bytes) else {
            return;
        };
        let ulen = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
        let rest = if bytes.len() > UDP_HEADER {
            &bytes[UDP_HEADER..]
        } else {
            &[]
        };
        let payload = if ulen == 0 && over_ipv6 {
            rest
        } else if ulen < UDP_HEADER {
            return;
        } else {
            take_len(rest, ulen - UDP_HEADER)
        };
        if payload.is_empty() {
            return;
        }
        let pick = self.tables.udp(src, dst);
        self.after_ports(pick, payload);
    }

    fn tcp(&mut self, bytes: &[u8]) {
        if bytes.len() < TCP_MIN {
            return;
        }
        let src = u16::from_be_bytes([bytes[0], bytes[1]]);
        let dst = u16::from_be_bytes([bytes[2], bytes[3]]);
        let data_off = (bytes[12] >> 4) as usize * 4;
        if data_off < TCP_MIN {
            return;
        }
        if bytes.len() <= data_off {
            return;
        }
        let pick = self.tables.tcp(src, dst);
        self.after_ports(pick, &bytes[data_off..]);
    }

    fn after_ports(&mut self, pick: PortPick, payload: &[u8]) {
        if pick.is_vxlan() {
            self.vxlan(payload);
            return;
        }
        if pick.name.is_none() {
            self.count("heuristics");
            return;
        }
        if pick.may_reject {
            self.count("may-reject");
            return;
        }
        if pick.reaches_ip {
            self.count("reaches-ip");
        }
    }

    fn vxlan(&mut self, bytes: &[u8]) {
        if bytes.len() < VXLAN_HEADER {
            return;
        }
        if self.nest() {
            self.ethernet(&bytes[VXLAN_HEADER..]);
        }
    }

    fn udp_counts_or_vxlan(&self, src: u16, dst: u16) -> bool {
        let pick = self.tables.udp(src, dst);
        pick.must_count() || pick.is_vxlan()
    }
}

fn udp_ports(bytes: &[u8]) -> Option<(u16, u16)> {
    if bytes.len() < UDP_HEADER {
        return None;
    }
    let src = u16::from_be_bytes([bytes[0], bytes[1]]);
    let dst = u16::from_be_bytes([bytes[2], bytes[3]]);
    Some((src, dst))
}

fn is_vlan(etype: u16) -> bool {
    matches!(etype, 0x8100 | 0x88a8 | 0x9100)
}

fn take_len(bytes: &[u8], want: usize) -> &[u8] {
    if bytes.len() > want {
        &bytes[..want]
    } else {
        bytes
    }
}

/// tshark 4.6.9 `dissect_icmp` RFC 4884 clip of the original datagram tvbuff.
fn rfc4884_embed_len(icmp: &[u8]) -> Option<usize> {
    let length = icmp[5] as usize;
    if length == 0 || icmp.len() < ICMP_HEADER + 4 {
        return None;
    }
    let orig = length * 4;
    if icmp.len() <= ICMP_HEADER + orig {
        return None;
    }
    let tot_len = u16::from_be_bytes([icmp[ICMP_HEADER + 2], icmp[ICMP_HEADER + 3]]) as usize;
    if tot_len <= orig {
        return None;
    }
    let ihl_nibble = (icmp[ICMP_HEADER] & 0x0f) as usize;
    Some((ihl_nibble + length) * 4)
}

/// tshark 4.6.9 `set_actual_length(tvb, 40 + plen)` in uint32.
fn take_ipv6_payload(body: &[u8], plen: u32) -> &[u8] {
    let actual = (IPV6_HEADER as u32).wrapping_add(plen);
    if actual < IPV6_HEADER as u32 {
        &[]
    } else {
        take_len(body, actual as usize - IPV6_HEADER)
    }
}

/// tshark 4.6.9 `ipv6_get_jumbo_plen`: hop-by-hop option 0xC2, length 4, value > 65535.
fn jumbo_payload_len(hop: &[u8]) -> Option<u32> {
    if hop.len() < 2 {
        return None;
    }
    let end = (hop[1] as usize + 1) * 8;
    let mut offset = 2;
    while offset < end && hop.len().saturating_sub(offset) >= 6 {
        let opt_type = hop[offset];
        offset += 1;
        if opt_type == 0 {
            continue;
        }
        let opt_len = hop[offset] as usize;
        offset += 1;
        if opt_type == 0xc2 && opt_len == 4 {
            let jumbo = u32::from_be_bytes([
                hop[offset],
                hop[offset + 1],
                hop[offset + 2],
                hop[offset + 3],
            ]);
            return (jumbo > u16::MAX as u32).then_some(jumbo);
        }
        offset += opt_len;
    }
    None
}

fn take_ext8(bytes: &[u8]) -> Option<(u8, &[u8])> {
    if bytes.len() < 2 {
        return None;
    }
    let len = (bytes[1] as usize + 1) * 8;
    if bytes.len() < len {
        return None;
    }
    Some((bytes[0], &bytes[len..]))
}

/// tshark 4.6.9 `dissect_opts` reads option type at `offset` and length at
/// `offset + 1` from the remaining IPv6 payload tvbuff, then
/// `proto_tree_add_item` of `opt_len` bytes. Pad1 still reads the length byte
/// but only consumes 1. A claimed non-Pad1 option longer than the remaining
/// captured payload throws BoundsError, so `ipv6_dissect_next` is not called.
/// Type dissectors that ignore `opt_len` leave `offset` where they stopped;
/// leftover header bytes are not a new TLV. CALIPSO / SMF_DPD / APN6 reads
/// that overrun the captured payload still throw.
fn take_opts(bytes: &[u8]) -> Option<(u8, &[u8])> {
    let (next, rest) = take_ext8(bytes)?;
    if opts_bounds_error(bytes) {
        return None;
    }
    Some((next, rest))
}

fn opts_bounds_error(payload: &[u8]) -> bool {
    if payload.len() < 2 {
        return false;
    }
    let end = (payload[1] as usize + 1) * 8;
    let mut offset = 2;
    while offset < end {
        if offset + 1 >= payload.len() {
            return true;
        }
        let typ = payload[offset];
        let opt_len = payload[offset + 1] as usize;
        if typ == 0 {
            offset += 1;
            continue;
        }
        if offset + 2 + opt_len > payload.len() {
            return true;
        }
        let Some(read) = opt_data_read(typ, &payload[offset + 2..], opt_len) else {
            return true;
        };
        offset = (offset + 2 + read).max(offset + 2 + opt_len);
    }
    false
}

/// Bytes of option data tshark 4.6.9 actually advances, or None on BoundsError.
fn opt_data_read(typ: u8, data: &[u8], opt_len: usize) -> Option<usize> {
    match typ {
        0x07 => calipso_read(data),
        0x08 => smf_dpd_read(data, opt_len),
        0x0f => need(data, 10),
        0x13 => apn6_read(data),
        0x23 | 0x63 => need(data, 4),
        0x26 => quickstart_read(data),
        0x30 | 0x41 | 0xc2 => need(data, 4),
        0x31 => ioam_read(data),
        0xc9 => need(data, 16),
        _ => Some(opt_len),
    }
}

fn need(data: &[u8], n: usize) -> Option<usize> {
    (data.len() >= n).then_some(n)
}

/// tshark 4.6.9 `dissect_opt_calipso` always reads DOI (4), cmpt_length (1),
/// sens (1), checksum (2), then `cmpt_length * 4` bitmap bytes.
fn calipso_read(data: &[u8]) -> Option<usize> {
    if data.len() < 8 {
        return None;
    }
    need(data, 8 + data[4] as usize * 4)
}

/// tshark 4.6.9 `dissect_opt_smf_dpd` I-DPD with tid bits reads `hash_tid`
/// then `(hash_tid & 0x0f) + 1` tagger-id bytes from the parent payload.
fn smf_dpd_read(data: &[u8], opt_len: usize) -> Option<usize> {
    let hash_tid = *data.first()?;
    if hash_tid & 0x80 != 0 {
        return need(data, opt_len);
    }
    let mut n = 1;
    if hash_tid & 0x70 != 0 {
        n += (hash_tid & 0x0f) as usize + 1;
    }
    need(data, n)
}

/// tshark 4.6.9 `dissect_opt_apn6` always reads id-type (1) + flags (1) +
/// param (2), then 4/8/16 more when `apn_id_type` is 1/2/≥3.
fn apn6_read(data: &[u8]) -> Option<usize> {
    let id_type = *data.first()?;
    let n = match id_type {
        0 => 4,
        1 => 8,
        2 => 12,
        _ => 20,
    };
    need(data, n)
}

/// tshark 4.6.9 `dissect_opt_quickstart`: Rate Request/Report consume 6.
fn quickstart_read(data: &[u8]) -> Option<usize> {
    let cmd = *data.first()?;
    match cmd >> 4 {
        0 | 8 => need(data, 6),
        _ => Some(0),
    }
}

/// tshark 4.6.9 `dissect_opt_ioam` reads 2, then trace/DEX type-specific bytes.
fn ioam_read(data: &[u8]) -> Option<usize> {
    if data.len() < 2 {
        return None;
    }
    match data[1] {
        0 | 1 | 4 => need(data, 10),
        _ => Some(2),
    }
}

/// tshark 4.6.9 `dissect_routing6` still calls `ipv6_dissect_next`, but type
/// dissectors read past the type-specific tvbuff (`total_len - 4`) and throw
/// BoundsError, so the next header is not dissected.
fn take_routing(bytes: &[u8]) -> Option<(u8, &[u8])> {
    let (next, rest) = take_ext8(bytes)?;
    let total = (bytes[1] as usize + 1) * 8;
    if routing_bounds_error(bytes[2], bytes[3], bytes[1], &bytes[4..total]) {
        return None;
    }
    Some((next, rest))
}

fn routing_bounds_error(typ: u8, segs_left: u8, hdrlen: u8, body: &[u8]) -> bool {
    match typ {
        2 => body.len() < 20,
        3 => rpl_bounds_error(hdrlen, body),
        4 => match body.first() {
            None => true,
            Some(&last_entry) => body.len() < 4 + 16 * (last_entry as usize + 1),
        },
        5 => crh_bounds_error(2, hdrlen as usize * 4 + 2, segs_left, body),
        6 => crh_bounds_error(4, hdrlen as usize * 2 + 1, segs_left, body),
        _ => false,
    }
}

/// tshark 4.6.9 `dissect_routing6_rpl`: 4-byte Cmpr/Pad, then `hdrlen > 0`
/// addresses of size `16 - CmprI` (last uses `CmprE`).
fn rpl_bounds_error(hdrlen: u8, body: &[u8]) -> bool {
    if body.len() < 4 {
        return true;
    }
    if hdrlen == 0 {
        return false;
    }
    let cmpr_i = body[0] >> 4;
    let cmpr_e = body[0] & 0x0f;
    let pad = body[1] >> 4;
    let numer = i32::from(hdrlen) * 8 - i32::from(pad) - (16 - i32::from(cmpr_e));
    let denom = 16 - i32::from(cmpr_i);
    let addr_count = numer / denom + 1;
    if addr_count <= 0 {
        return false;
    }
    let mut offset = 4;
    for idx in 1..=addr_count {
        let size = if idx == addr_count {
            16 - cmpr_e as usize
        } else {
            16 - cmpr_i as usize
        };
        if offset + size > body.len() {
            return true;
        }
        offset += size;
    }
    false
}

/// tshark 4.6.9 `dissect_routing6_crh`: `current_sid` at
/// `octets_per_sid * segments_left`, then SID words until a zero SID, always
/// reading one word past the last nonzero SID.
fn crh_bounds_error(octets_per_sid: usize, sid_count: usize, segs_left: u8, body: &[u8]) -> bool {
    let current = octets_per_sid * segs_left as usize;
    if current + octets_per_sid > body.len() {
        return true;
    }
    if body.len() < octets_per_sid {
        return true;
    }
    let mut offset = 0;
    let mut sid = crh_sid(body, offset, octets_per_sid);
    for _ in 0..sid_count {
        if sid == 0 {
            break;
        }
        offset += octets_per_sid;
        if offset + octets_per_sid > body.len() {
            return true;
        }
        sid = crh_sid(body, offset, octets_per_sid);
    }
    false
}

fn crh_sid(body: &[u8], offset: usize, octets: usize) -> u32 {
    if octets == 2 {
        u16::from_be_bytes([body[offset], body[offset + 1]]).into()
    } else {
        u32::from_be_bytes([
            body[offset],
            body[offset + 1],
            body[offset + 2],
            body[offset + 3],
        ])
    }
}

fn take_ah(bytes: &[u8]) -> Option<(u8, &[u8])> {
    if bytes.len() < 2 {
        return None;
    }
    let len = (bytes[1] as usize + 2) * 4;
    if bytes.len() < len {
        return None;
    }
    Some((bytes[0], &bytes[len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn walk(captured: &[u8]) -> Cell {
        walk_ip_src(
            &Frame {
                link_type: ETHERNET,
                captured,
            },
            &mut IpSrc::new(),
        )
    }

    fn eth_ipv6(next: u8, plen: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0, 0, 1, 0x86, 0xdd, 0x60, 0, 0, 0,
        ];
        frame.extend_from_slice(&plen.to_be_bytes());
        frame.push(next);
        frame.push(64);
        frame.extend_from_slice(&[0u8; 32]);
        frame.extend_from_slice(payload);
        frame
    }

    fn hopopt_jumbo(next: u8, jumbo: u32, payload: &[u8]) -> Vec<u8> {
        let mut ext = vec![next, 0, 0xc2, 4];
        ext.extend_from_slice(&jumbo.to_be_bytes());
        ext.extend_from_slice(payload);
        ext
    }

    fn routing6(
        next: u8,
        hdrlen: u8,
        typ: u8,
        segs_left: u8,
        specific: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        let total = (hdrlen as usize + 1) * 8;
        let mut hdr = vec![0u8; total];
        hdr[0] = next;
        hdr[1] = hdrlen;
        hdr[2] = typ;
        hdr[3] = segs_left;
        let n = specific.len().min(total - 4);
        hdr[4..4 + n].copy_from_slice(&specific[..n]);
        hdr.extend_from_slice(payload);
        hdr
    }

    fn route_frame(hdrlen: u8, typ: u8, specific: &[u8]) -> Vec<u8> {
        route_frame_segs(hdrlen, typ, 0, specific)
    }

    fn route_frame_segs(hdrlen: u8, typ: u8, segs_left: u8, specific: &[u8]) -> Vec<u8> {
        let payload = routing6(4, hdrlen, typ, segs_left, specific, &ipv4_udp_discard());
        eth_ipv6(43, payload.len() as u16, &payload)
    }

    fn hopopt_hdr(next: u8, hdrlen: u8, options: &[u8], payload: &[u8]) -> Vec<u8> {
        let total = (hdrlen as usize + 1) * 8;
        let mut ext = vec![0u8; total];
        ext[0] = next;
        ext[1] = hdrlen;
        let n = options.len().min(total.saturating_sub(2));
        ext[2..2 + n].copy_from_slice(&options[..n]);
        ext.extend_from_slice(payload);
        ext
    }

    fn opts_frame(ext: u8, options: &[u8]) -> Vec<u8> {
        opts_frame_hdr(ext, 0, options)
    }

    fn opts_frame_hdr(ext: u8, hdrlen: u8, options: &[u8]) -> Vec<u8> {
        opts_frame_ip(ext, hdrlen, options, &ipv4_udp_discard())
    }

    fn opts_frame_ip(ext: u8, hdrlen: u8, options: &[u8], ip: &[u8]) -> Vec<u8> {
        let payload = hopopt_hdr(4, hdrlen, options, ip);
        eth_ipv6(ext, payload.len() as u16, &payload)
    }

    fn last_tlv(typ: u8) -> [u8; 5] {
        [0, 0, 0, 0, typ]
    }

    fn ipv4_tso(ihl: u8, captured: usize) -> Vec<u8> {
        let mut ip = vec![0u8; captured];
        if captured == 0 {
            return ip;
        }
        ip[0] = ihl;
        if captured > 8 {
            ip[8] = 64;
        }
        if captured > 9 {
            ip[9] = 17;
        }
        if captured >= 16 {
            ip[12..16].copy_from_slice(&[10, 9, 9, 9]);
        }
        ip
    }

    fn ipv4_udp_discard() -> Vec<u8> {
        let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0];
        let udp = [0, 9, 0, 9, 0, 16, 0, 0, b'f', b'i', b'n', 0, 0, 0, 0, 0];
        let total = (20 + udp.len()) as u16;
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&[10, 9, 9, 9, 10, 255, 255, 1]);
        ip.extend_from_slice(&udp);
        ip
    }

    fn proved(values: &[&str]) -> Cell {
        Cell {
            values: values.iter().map(|value| (*value).to_string()).collect(),
            counted: None,
        }
    }

    fn blank() -> Cell {
        Cell {
            values: Vec::new(),
            counted: None,
        }
    }

    fn vxlan_inner_eth() -> Vec<u8> {
        let inner = ipv4_udp_discard();
        let mut eth = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00,
        ];
        eth.extend_from_slice(&inner);
        let mut udp = vec![0xc3, 0x50, 0x12, 0xb5, 0, 0, 0, 0];
        let payload_len = (8 + 8 + eth.len()) as u16;
        udp[4..6].copy_from_slice(&payload_len.to_be_bytes());
        udp.extend_from_slice(&[0x08, 0, 0, 0, 0, 0, 1, 0]);
        udp.extend_from_slice(&eth);
        udp
    }

    #[test]
    fn hopopt_jumbo_65536_walks_ipip() {
        let frame = eth_ipv6(0, 0, &hopopt_jumbo(4, 65536, &ipv4_udp_discard()));
        assert_eq!(walk(&frame), proved(&["10.9.9.9"]));
    }

    #[test]
    fn hopopt_jumbo_65536_walks_vxlan() {
        let frame = eth_ipv6(0, 0, &hopopt_jumbo(17, 65536, &vxlan_inner_eth()));
        assert_eq!(walk(&frame), proved(&["10.9.9.9"]));
    }

    #[test]
    fn hopopt_jumbo_65535_stays_blank() {
        let frame = eth_ipv6(0, 0, &hopopt_jumbo(4, 65535, &ipv4_udp_discard()));
        assert_eq!(walk(&frame), blank());
    }

    #[test]
    fn hopopt_jumbo_ffffffd7_walks_ipip() {
        let frame = eth_ipv6(0, 0, &hopopt_jumbo(4, 0xffff_ffd7, &ipv4_udp_discard()));
        assert_eq!(walk(&frame), proved(&["10.9.9.9"]));
    }

    #[test]
    fn hopopt_jumbo_ffffffd8_stays_blank() {
        let frame = eth_ipv6(0, 0, &hopopt_jumbo(4, 0xffff_ffd8, &ipv4_udp_discard()));
        assert_eq!(walk(&frame), blank());
    }

    #[test]
    fn hopopt_jumbo_fffffffe_stays_blank() {
        let frame = eth_ipv6(0, 0, &hopopt_jumbo(4, 0xffff_fffe, &ipv4_udp_discard()));
        assert_eq!(walk(&frame), blank());
    }

    #[test]
    fn hopopt_jumbo_ffffffff_stays_blank() {
        let frame = eth_ipv6(0, 0, &hopopt_jumbo(4, 0xffff_ffff, &ipv4_udp_discard()));
        assert_eq!(walk(&frame), blank());
    }

    #[test]
    fn zero_plen_without_hopopt_stays_blank() {
        let frame = eth_ipv6(4, 0, &ipv4_udp_discard());
        assert_eq!(walk(&frame), blank());
    }

    #[test]
    fn dstopts_jumbo_is_ignored() {
        let frame = eth_ipv6(60, 0, &hopopt_jumbo(4, 65536, &ipv4_udp_discard()));
        assert_eq!(walk(&frame), blank());
    }

    fn eth_ipv4_icmp(icmp: &[u8]) -> Vec<u8> {
        let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 1, 0, 0];
        let total = (20 + icmp.len()) as u16;
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&[10, 0, 0, 1, 10, 255, 255, 1]);
        ip.extend_from_slice(icmp);
        let mut eth = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00,
        ];
        eth.extend_from_slice(&ip);
        eth
    }

    fn icmp_embed(typ: u8, orig_words: u8, inner: &[u8]) -> Vec<u8> {
        let mut icmp = vec![typ, 0, 0, 0, 0, orig_words, 0, 0];
        icmp.extend_from_slice(inner);
        icmp
    }

    fn ipv6_flow(next: u8, flow_low: u16, payload: &[u8]) -> Vec<u8> {
        let mut ip = vec![0x60, 0, 0, 0, 0, 0, next, 64];
        ip[2..4].copy_from_slice(&flow_low.to_be_bytes());
        ip[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        ip.extend_from_slice(&[0u8; 32]);
        ip.extend_from_slice(payload);
        ip
    }

    fn icmp_v6_embed(typ: u8, orig_words: u8, flow_low: u16) -> Vec<u8> {
        eth_ipv4_icmp(&icmp_embed(
            typ,
            orig_words,
            &ipv6_flow(4, flow_low, &ipv4_udp_discard()),
        ))
    }

    #[test]
    fn rfc4884_ipv6_flow_0100_len_1_clips_to_4() {
        let icmp = icmp_embed(3, 1, &ipv6_flow(4, 0x0100, &ipv4_udp_discard()));
        assert_eq!(rfc4884_embed_len(&icmp), Some(4));
    }

    #[test]
    fn rfc4884_ipv4_len_1_clips_to_ihl_plus_length() {
        let icmp = icmp_embed(3, 1, &ipv4_udp_discard());
        assert_eq!(rfc4884_embed_len(&icmp), Some(24));
    }

    #[test]
    fn rfc4884_len_0_does_not_clip() {
        let icmp = icmp_embed(3, 0, &ipv6_flow(4, 0x0100, &ipv4_udp_discard()));
        assert_eq!(rfc4884_embed_len(&icmp), None);
    }

    #[test]
    fn rfc4884_flow_1_len_1_does_not_clip() {
        let icmp = icmp_embed(3, 1, &ipv6_flow(4, 1, &ipv4_udp_discard()));
        assert_eq!(rfc4884_embed_len(&icmp), None);
    }

    #[test]
    fn rfc4884_len_14_clips_to_56() {
        let icmp = icmp_embed(3, 14, &ipv6_flow(4, 0x0100, &ipv4_udp_discard()));
        assert_eq!(rfc4884_embed_len(&icmp), Some(56));
    }

    #[test]
    fn icmp_rfc4884_ipv6_types_clip_flow_0100_len_1() {
        for typ in [3, 4, 11, 12] {
            assert_eq!(
                walk(&icmp_v6_embed(typ, 1, 0x0100)),
                proved(&["10.0.0.1"]),
                "type {typ}"
            );
        }
    }

    #[test]
    fn icmp_rfc4884_ipv6_len_0_prints_inner() {
        assert_eq!(
            walk(&icmp_v6_embed(3, 0, 0x0100)),
            proved(&["10.0.0.1", "10.9.9.9"])
        );
    }

    #[test]
    fn icmp_rfc4884_ipv6_flow_1_len_1_prints_inner() {
        assert_eq!(
            walk(&icmp_v6_embed(3, 1, 1)),
            proved(&["10.0.0.1", "10.9.9.9"])
        );
    }

    #[test]
    fn icmp_rfc4884_ipv6_len_1_to_13_clips_flow_0100() {
        for length in 1..=13 {
            assert_eq!(
                walk(&icmp_v6_embed(3, length, 0x0100)),
                proved(&["10.0.0.1"]),
                "length {length}"
            );
        }
    }

    #[test]
    fn icmp_rfc4884_ipv6_len_14_prints_inner() {
        assert_eq!(
            walk(&icmp_v6_embed(3, 14, 0x0100)),
            proved(&["10.0.0.1", "10.9.9.9"])
        );
    }

    #[test]
    fn icmp_type_5_len_14_stays_outer_only() {
        assert_eq!(walk(&icmp_v6_embed(5, 14, 0x0100)), proved(&["10.0.0.1"]));
    }

    #[test]
    fn icmp_rfc4884_ipv4_embed_len_1_prints_src() {
        let frame = eth_ipv4_icmp(&icmp_embed(3, 1, &ipv4_udp_discard()));
        let cell = walk(&frame);
        assert_eq!(cell.values, ["10.0.0.1", "10.9.9.9"]);
        assert_eq!(cell.counted, Some("icmp"));
    }

    #[test]
    fn routing_type2_type4_short_header_stays_blank() {
        for (typ, hdrlen, specific) in [
            (2, 0, &[] as &[u8]),
            (2, 1, &[]),
            (4, 0, &[]),
            (4, 1, &[]),
            (4, 2, &[255]),
        ] {
            assert_eq!(
                walk(&route_frame(hdrlen, typ, specific)),
                blank(),
                "type {typ} hdrlen {hdrlen}"
            );
        }
    }

    #[test]
    fn routing_hdrlen0_types_that_walk() {
        for typ in [0, 3, 99] {
            assert_eq!(
                walk(&route_frame(0, typ, &[])),
                proved(&["10.9.9.9"]),
                "type {typ}"
            );
        }
    }

    #[test]
    fn routing_type2_hdrlen2_walks_ipip() {
        assert_eq!(walk(&route_frame(2, 2, &[])), proved(&["10.9.9.9"]));
    }

    #[test]
    fn routing_type4_hdrlen2_last_entry0_walks_ipip() {
        assert_eq!(walk(&route_frame(2, 4, &[0])), proved(&["10.9.9.9"]));
    }

    #[test]
    fn routing_type4_hdrlen2_last_entry1_stays_blank() {
        assert_eq!(walk(&route_frame(2, 4, &[1])), blank());
    }

    #[test]
    fn routing_type3_hdrlen1_stays_blank() {
        for cmpr in [0u8, 0x11] {
            assert_eq!(
                walk(&route_frame(1, 3, &[cmpr])),
                blank(),
                "cmpr {cmpr:#04x}"
            );
        }
    }

    #[test]
    fn routing_type3_hdrlen2_walks_ipip() {
        assert_eq!(walk(&route_frame(2, 3, &[])), proved(&["10.9.9.9"]));
    }

    #[test]
    fn routing_type3_hdrlen1_cmpr_ff_walks_ipip() {
        assert_eq!(walk(&route_frame(1, 3, &[0xff])), proved(&["10.9.9.9"]));
    }

    #[test]
    fn routing_type5_type6_nonzero_sids_stays_blank() {
        assert_eq!(walk(&route_frame(0, 5, &[0, 1, 0, 1])), blank());
        assert_eq!(walk(&route_frame(0, 6, &[0, 1, 0, 1])), blank());
    }

    #[test]
    fn routing_type5_type6_zero_sids_walks_ipip() {
        for typ in [5u8, 6] {
            assert_eq!(
                walk(&route_frame(0, typ, &[0, 0, 0, 0])),
                proved(&["10.9.9.9"]),
                "type {typ}"
            );
        }
    }

    #[test]
    fn routing_type5_first_sid_nonzero_second_zero_walks_ipip() {
        assert_eq!(
            walk(&route_frame(0, 5, &[0, 1, 0, 0])),
            proved(&["10.9.9.9"])
        );
    }

    #[test]
    fn routing_type5_type6_hdrlen1_segleft255_stays_blank() {
        for typ in [5u8, 6] {
            assert_eq!(
                walk(&route_frame_segs(1, typ, 255, &[])),
                blank(),
                "type {typ}"
            );
        }
    }

    #[test]
    fn hopopt_and_dstopts_overrun_stays_blank() {
        for ext in [0u8, 60] {
            assert_eq!(
                walk(&opts_frame(ext, &[0x05, 255])),
                blank(),
                "ext {ext} rtalert 255"
            );
            assert_eq!(
                walk(&opts_frame(ext, &[0, 0, 0, 0, 0, 1])),
                blank(),
                "ext {ext} five Pad1 then type 1"
            );
        }
    }

    #[test]
    fn hopopt_and_dstopts_padn_overruns_header_walks_ipip() {
        for ext in [0u8, 60] {
            assert_eq!(
                walk(&opts_frame(ext, &[0x01, 6])),
                proved(&["10.9.9.9"]),
                "ext {ext}"
            );
        }
    }

    #[test]
    fn hopopt_six_pad1_walks_ipip() {
        assert_eq!(
            walk(&opts_frame(0, &[0, 0, 0, 0, 0, 0])),
            proved(&["10.9.9.9"])
        );
    }

    #[test]
    fn hopopt_padn_len_40_walks_and_41_stays_blank() {
        assert_eq!(walk(&opts_frame(0, &[0x01, 40])), proved(&["10.9.9.9"]));
        assert_eq!(walk(&opts_frame(0, &[0x01, 41])), blank());
    }

    #[test]
    fn hopopt_and_dstopts_calipso_short_stays_blank() {
        for ext in [0u8, 60] {
            assert_eq!(
                walk(&opts_frame(ext, &[0x07])),
                blank(),
                "ext {ext} CALIPSO on 8-byte header"
            );
        }
    }

    #[test]
    fn hopopt_calipso_cmpt0_walks_ipip() {
        let options = [0x07, 8, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(walk(&opts_frame_hdr(0, 1, &options)), proved(&["10.9.9.9"]));
    }

    #[test]
    fn hopopt_calipso_cmpt255_stays_blank() {
        let options = [0x07, 8, 0, 0, 0, 0, 255, 0, 0, 0];
        assert_eq!(walk(&opts_frame_hdr(0, 1, &options)), blank());
    }

    #[test]
    fn hopopt_and_dstopts_apn6_last_tlv_short_stays_blank() {
        let ip = ipv4_tso(0x45, 16);
        for ext in [0u8, 60] {
            assert_eq!(
                walk(&opts_frame_ip(ext, 0, &last_tlv(0x13), &ip)),
                blank(),
                "ext {ext}"
            );
        }
        assert_eq!(
            walk(&opts_frame_ip(
                0,
                1,
                &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x13],
                &ip
            )),
            blank()
        );
        assert_eq!(
            walk(&opts_frame_ip(0, 0, &last_tlv(0x13), &ipv4_tso(0x45, 19))),
            blank()
        );
    }

    #[test]
    fn hopopt_apn6_last_tlv_20_walks_ipip() {
        assert_eq!(
            walk(&opts_frame_ip(0, 0, &last_tlv(0x13), &ipv4_tso(0x45, 20))),
            proved(&["10.9.9.9"])
        );
    }

    #[test]
    fn hopopt_and_dstopts_smf_last_tlv_short_stays_blank() {
        let ip = ipv4_tso(0x4f, 16);
        for ext in [0u8, 60] {
            assert_eq!(
                walk(&opts_frame_ip(ext, 0, &last_tlv(0x08), &ip)),
                blank(),
                "ext {ext}"
            );
        }
    }

    #[test]
    fn hopopt_smf_last_tlv_17_walks_ipip() {
        assert_eq!(
            walk(&opts_frame_ip(0, 0, &last_tlv(0x08), &ipv4_tso(0x4f, 17))),
            proved(&["10.9.9.9"])
        );
    }

    #[test]
    fn hopopt_and_dstopts_jumbo_len0_trailing_0x40_walks_ipip() {
        for ext in [0u8, 60] {
            assert_eq!(
                walk(&opts_frame(ext, &[0xc2, 0, 0, 0, 0, 0x40])),
                proved(&["10.9.9.9"]),
                "ext {ext}"
            );
        }
    }

    #[test]
    fn hopopt_first_tlv_len0_trailing_0x40_walks_ipip() {
        for typ in [0x0fu8, 0x13, 0x23, 0x26, 0x30, 0x31, 0x41, 0x63, 0xc9] {
            assert_eq!(
                walk(&opts_frame(0, &[typ, 0, 0, 0, 0, 0x40])),
                proved(&["10.9.9.9"]),
                "typ {typ:#x}"
            );
        }
    }
}
