//! tshark 4.6.9 UDP/TCP port table snapshot.
//!
//! `udp-tcp-decodes.txt` is the `udp.port` / `tcp.port` rows of
//! `tshark -G decodes`. `tls-port-decodes.txt` is the `tls.port` rows
//! (`ssl_associations`). Names on the always-claim
//! and reaches-IP lists come from `reader/ports/reaches-ip.md` and
//! `reader/ports/may-reject.md`. Anything not proved to always claim may reject.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

const DECODES: &str = include_str!("../ports/udp-tcp-decodes.txt");
const TLS_DECODES: &str = include_str!("../ports/tls-port-decodes.txt");

/// Port dissectors proved in 4.6.9 to always claim the payload.
const ALWAYS_CLAIM: &[&str] = &[
    "acdr",
    "amt",
    "ayiya",
    "capwap",
    "capwap.data",
    "discard",
    "dns",
    "echo",
    "geneve",
    "gre",
    "gtpprime",
    "lisp",
    "llc",
    "lwapp",
    "mip",
    "mpls",
    "msrcp",
    "openflow",
    "teredo",
    "tzsp",
    "udpencap",
    "vxlan",
    "vxlan_gpe",
    "wassp",
];

/// Port names that can call the IPv4 dissector, including unproven names
/// treated as reaches-IP so a miss stays a count.
const REACHES_IP: &[&str] = &[
    "acdr",
    "amt",
    "atmtcp",
    "ayiya",
    "bat.gw",
    "capwap",
    "capwap.data",
    "cflow",
    "classicstun",
    "dtls",
    "geneve",
    "gre",
    "gsmtap",
    "gtp",
    "hip",
    "infiniband",
    "jmirror",
    "l2tp",
    "lisp",
    "lisp-data",
    "llc",
    "lwapp",
    "lwapp-l3",
    "mint",
    "mip",
    "mpls",
    "msdp",
    "msrcp",
    "nsh",
    "openflow",
    "openvpn",
    "pptp",
    "proxy",
    "sflow",
    "socks",
    "stun",
    "teredo",
    "tls",
    "tzsp",
    "udpencap",
    "vxlan",
    "vxlan_gpe",
    "wassp",
    "wg",
    "xot",
];

/// One UDP or TCP port pair after tshark's lower-then-higher lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortPick {
    pub name: Option<&'static str>,
    pub reaches_ip: bool,
    pub may_reject: bool,
}

impl PortPick {
    /// True when tshark may still run heuristics or an inner IP dissector
    /// this walker does not follow. VXLAN is walked, so it is not counted here.
    pub fn must_count(self) -> bool {
        match self.name {
            None => true,
            Some("vxlan") => self.may_reject,
            Some(_) => self.may_reject || self.reaches_ip,
        }
    }

    pub fn is_vxlan(self) -> bool {
        self.name == Some("vxlan") && !self.may_reject
    }

    pub fn is_tls(self) -> bool {
        self.name == Some("tls")
    }
}

/// Snapshotted `udp.port` / `tcp.port` / `tls.port` tables from tshark 4.6.9.
pub struct PortTables {
    udp: HashMap<u16, &'static str>,
    tcp: HashMap<u16, &'static str>,
    tls: HashSet<u16>,
    always_claim: HashSet<&'static str>,
    reaches_ip: HashSet<&'static str>,
}

fn tables() -> &'static PortTables {
    static TABLES: OnceLock<PortTables> = OnceLock::new();
    TABLES.get_or_init(PortTables::from_dump)
}

/// Process-wide snapshot parsed from the checked-in dump.
pub fn snapshot() -> &'static PortTables {
    tables()
}

impl PortTables {
    fn from_dump() -> Self {
        let mut udp = HashMap::new();
        let mut tcp = HashMap::new();
        let mut tls = HashSet::new();
        for line in DECODES.lines().chain(TLS_DECODES.lines()) {
            let mut cols = line.split('\t');
            let Some(table) = cols.next() else { continue };
            let Some(key) = cols.next() else { continue };
            let Some(name) = cols.next() else { continue };
            let Some(port) = parse_port(key) else {
                continue;
            };
            match table {
                "udp.port" => {
                    udp.entry(port).or_insert(name);
                }
                "tcp.port" => {
                    tcp.entry(port).or_insert(name);
                }
                "tls.port" if port != 0 => {
                    tls.insert(port);
                }
                _ => {}
            }
        }
        Self {
            udp,
            tcp,
            tls,
            always_claim: ALWAYS_CLAIM.iter().copied().collect(),
            reaches_ip: REACHES_IP.iter().copied().collect(),
        }
    }

    pub fn udp(&self, src: u16, dst: u16) -> PortPick {
        self.pick(&self.udp, src, dst)
    }

    pub fn tcp(&self, src: u16, dst: u16) -> PortPick {
        self.pick(&self.tcp, src, dst)
    }

    /// tshark 4.6.9 `ssl_packet_from_server` before `ssl_set_server`:
    /// `dissector_get_uint_handle(ssl_associations, srcport) != 0`.
    /// `ssl_associations` is the `tls.port` table, not `tcp.port`.
    pub fn is_tls_port(&self, port: u16) -> bool {
        port != 0 && self.tls.contains(&port)
    }

    fn pick(&self, map: &HashMap<u16, &'static str>, src: u16, dst: u16) -> PortPick {
        let (low, high) = if src <= dst { (src, dst) } else { (dst, src) };
        let name = first_named(map, low).or_else(|| {
            if high != low {
                first_named(map, high)
            } else {
                None
            }
        });
        match name {
            None => PortPick {
                name: None,
                reaches_ip: false,
                may_reject: false,
            },
            Some(name) => PortPick {
                name: Some(name),
                reaches_ip: self.reaches_ip.contains(name),
                may_reject: !self.always_claim.contains(name),
            },
        }
    }
}

fn first_named(map: &HashMap<u16, &'static str>, port: u16) -> Option<&'static str> {
    if port == 0 {
        return None;
    }
    map.get(&port).copied()
}

fn parse_port(key: &str) -> Option<u16> {
    if let Some(hex) = key.strip_prefix("0x").or_else(|| key.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()?.try_into().ok()
    } else {
        key.parse().ok()
    }
}

/// Names the walker treats as always-claim, reaches-IP, or VXLAN.
///
/// The live dump pin only checks these. Official Windows tshark and the
/// CI source build of 4.6.9 register different optional dissectors
/// (OPC UA, EtherCAT, Gryphon vs UCI on 7000), so the full tables differ.
pub fn is_pinned_name(name: &str) -> bool {
    name == "vxlan" || ALWAYS_CLAIM.contains(&name) || REACHES_IP.contains(&name)
}

/// Raw dump text, for the live-tshark comparison test.
pub fn checked_in_decodes() -> &'static str {
    DECODES
}

/// `tls.port` dump text, for the live-tshark comparison test.
pub fn checked_in_tls_ports() -> &'static str {
    TLS_DECODES
}

pub fn checked_in_heuristics() -> &'static str {
    include_str!("../ports/heuristic-decodes.txt")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lower_udp_port_wins() {
        let tables = snapshot();
        let pick = tables.udp(4789, 53);
        assert_eq!(pick.name, Some("dns"));
        assert!(!pick.must_count());
        assert!(!pick.is_vxlan());
    }

    #[test]
    fn vxlan_on_the_low_port_is_walked() {
        let tables = snapshot();
        let pick = tables.udp(4789, 50000);
        assert_eq!(pick.name, Some("vxlan"));
        assert!(pick.is_vxlan());
        assert!(!pick.must_count());
    }

    #[test]
    fn unregistered_pair_counts() {
        let tables = snapshot();
        let pick = tables.udp(40000, 40001);
        assert_eq!(pick.name, None);
        assert!(pick.must_count());
    }

    #[test]
    fn discard_claims_and_does_not_reach_ip() {
        let tables = snapshot();
        let pick = tables.udp(12345, 9);
        assert_eq!(pick.name, Some("discard"));
        assert!(!pick.must_count());
    }

    #[test]
    fn tcp_443_is_tls() {
        let tables = snapshot();
        let pick = tables.tcp(50000, 443);
        assert_eq!(pick.name, Some("tls"));
        assert!(pick.is_tls());
        assert!(!pick.is_vxlan());
    }

    #[test]
    fn tls_port_is_the_source_port_not_the_pair() {
        let tables = snapshot();
        for port in [443u16, 465, 636, 853, 993, 995] {
            assert!(tables.is_tls_port(port), "{port}");
        }
        assert!(!tables.is_tls_port(50000));
        assert!(!tables.is_tls_port(40001));
        assert!(!tables.is_tls_port(0));
    }

    #[test]
    fn tls_port_is_ssl_associations_not_tcp_port() {
        let tables = snapshot();
        for port in [3389u16, 4420, 4460, 6514, 8009, 10050, 10051, 10809, 27017] {
            assert!(tables.is_tls_port(port), "{port}");
            assert_ne!(first_named(&tables.tcp, port), Some("tls"), "{port}");
        }
        assert_eq!(first_named(&tables.tcp, 3389), Some("tpkt"));
        assert!(first_named(&tables.tcp, 4460).is_none());
        assert!(first_named(&tables.tcp, 6514).is_none());
    }
}
