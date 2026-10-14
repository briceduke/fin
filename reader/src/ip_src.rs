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
            0x8847 | 0x8848 => self.maybe("mpls", payload),
            0x8863 | 0x8864 => self.maybe("pppoe", payload),
            etype if etype <= 1536 => self.maybe("llc", payload),
            _ => {}
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
        if bytes[0] >> 4 != 4 {
            return;
        }
        let ihl = (bytes[0] & 0x0f) as usize * 4;
        if ihl < IPV4_MIN {
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
        let total = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        let rest = &bytes[ihl..];
        let payload = if total >= ihl {
            let want = total - ihl;
            if rest.len() > want {
                &rest[..want]
            } else {
                rest
            }
        } else {
            rest
        };
        let fragmented = more || offset != 0;
        if fragmented {
            self.ipv4_fragment(src, dst, id, proto, offset, payload);
            return;
        }
        self.ip_proto(proto, payload);
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
        if proto == GRE || proto == IPIP || proto == IPV6 {
            self.count("fragment");
            return;
        }
        if proto != UDP {
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
        let mut next = bytes[6];
        let mut rest = &bytes[IPV6_HEADER..];
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
                IPV6_HOP | IPV6_ROUTE | IPV6_DEST => {
                    let Some((nxt, body)) = take_ext8(rest) else {
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
                        if next == GRE || next == IPIP || next == IPV6 || next == UDP {
                            self.count("fragment");
                        }
                        return;
                    }
                }
                _ => {
                    self.ip_proto(next, rest);
                    return;
                }
            }
        }
    }

    fn ip_proto(&mut self, proto: u8, payload: &[u8]) {
        match proto {
            ICMP => self.icmp(payload),
            ICMPV6 => self.icmpv6(payload),
            TCP => self.tcp(payload),
            UDP => self.udp(payload),
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
            ESP => {}
            _ => {}
        }
    }

    fn icmp(&mut self, bytes: &[u8]) {
        if bytes.len() < ICMP_HEADER {
            return;
        }
        if matches!(bytes[0], 3 | 4 | 5 | 11 | 12) {
            self.embedded_ipv4(&bytes[ICMP_HEADER..]);
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
        if bytes[0] >> 4 != 4 {
            return;
        }
        if (bytes[0] & 0x0f) as usize * 4 < IPV4_MIN {
            return;
        }
        self.values
            .push(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]).to_string());
    }

    fn udp(&mut self, bytes: &[u8]) {
        let Some((src, dst)) = udp_ports(bytes) else {
            return;
        };
        let payload = if bytes.len() > UDP_HEADER {
            &bytes[UDP_HEADER..]
        } else {
            &[]
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
    matches!(etype, 0x8100 | 0x88a8 | 0x9100 | 0x9200 | 0x9300)
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
