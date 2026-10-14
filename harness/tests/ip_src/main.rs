//! Oracle: `fin -T fields -e ip.src` against tshark 4.6.9.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use harness::{check_pair, run_pair, RunError, TsharkSession};

mod packets;

use packets::*;

const PAYLOAD: &[u8] = b"fin-ip-src\0\0\0\0\0";

#[test]
fn ip_src_matches_tshark_469() {
    let Some((tshark, fin)) = tools() else {
        return;
    };
    let dir = work_dir();
    let mut faults = Vec::new();
    for (name, file) in cases() {
        if let Some(fault) = check_one(&tshark, &fin, dir, name, &file) {
            faults.push(fault);
            if faults.len() >= 8 {
                break;
            }
        }
    }
    assert!(
        faults.is_empty(),
        "tshark 4.6.9 mismatches:\n{}",
        faults.join("\n")
    );
}

#[test]
fn unknown_flag_is_an_error() {
    let fin = fin_bin();
    let output = Command::new(&fin)
        .args(["-r", "x", "-Y", "ip", "-T", "fields", "-e", "ip.src"])
        .output()
        .expect("fin");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unrecognized flag"), "{stderr}");
}

#[test]
fn unknown_field_is_an_error() {
    let fin = fin_bin();
    let output = Command::new(&fin)
        .args(["-r", "x", "-T", "fields", "-e", "udp.srcport"])
        .output()
        .expect("fin");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unsupported field"), "{stderr}");
}

#[test]
fn claimed_preference_is_accepted() {
    let fin = fin_bin();
    let path = work_dir().join("claimed-o.pcap");
    fs::write(
        &path,
        pcap(LINK_ETHERNET, &[eth_ipv4_udp(OUTER, 12345, 9, PAYLOAD)]),
    )
    .unwrap();
    let output = Command::new(&fin)
        .arg("-r")
        .arg(&path)
        .args([
            "-n",
            "-T",
            "fields",
            "-e",
            "ip.src",
            "-o",
            "tcp.reassemble_out_of_order:TRUE",
        ])
        .output()
        .expect("fin");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(!stderr.contains("unrecognized flag"), "{stderr}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), "10.0.0.1\n");
}

fn cases() -> Vec<(&'static str, Vec<u8>)> {
    let mut files = fixed();
    files.extend(truncations());
    files.extend(random_cases());
    files.extend(on_disk());
    files
}

fn icmp_v6_rfc4884(typ: u8, orig_words: u8, flow_low: u16) -> Vec<u8> {
    let inner = ipv6_flow(
        4,
        flow_low,
        &ipv4(INNER, [10, 255, 255, 1], 17, &udp(9, 9, PAYLOAD)),
    );
    eth(
        0x0800,
        &ipv4(
            OUTER,
            [10, 255, 255, 1],
            1,
            &icmp_type_len(typ, orig_words, &inner),
        ),
    )
}

fn ipv6_routing_ipip(hdrlen: u8, typ: u8, specific: &[u8]) -> Vec<u8> {
    eth(
        0x86dd,
        &ipv6(
            43,
            &routing6(
                4,
                hdrlen,
                typ,
                specific,
                &ipv4(INNER, [10, 255, 255, 1], 17, &udp(9, 9, PAYLOAD)),
            ),
        ),
    )
}

fn ipv6_routing_ipip_segs(hdrlen: u8, typ: u8, segs_left: u8, specific: &[u8]) -> Vec<u8> {
    eth(
        0x86dd,
        &ipv6(
            43,
            &routing6_segs(
                4,
                hdrlen,
                typ,
                segs_left,
                specific,
                &ipv4(INNER, [10, 255, 255, 1], 17, &udp(9, 9, PAYLOAD)),
            ),
        ),
    )
}

fn ipv6_opts_ipip(ext: u8, options: &[u8]) -> Vec<u8> {
    eth(
        0x86dd,
        &ipv6(
            ext,
            &hopopt_opts(
                4,
                options,
                &ipv4(INNER, [10, 255, 255, 1], 17, &udp(9, 9, PAYLOAD)),
            ),
        ),
    )
}

fn fixed() -> Vec<(&'static str, Vec<u8>)> {
    let inner_eth = eth(
        0x0800,
        &ipv4(INNER, [10, 255, 255, 1], 17, &udp(9, 9, PAYLOAD)),
    );
    let ip_udp = ipv4(OUTER, [10, 255, 255, 1], 17, &udp(12345, 53, PAYLOAD));
    let mut ipv6_short_plen_vxlan = udp(50000, 4789, b"");
    ipv6_short_plen_vxlan.extend_from_slice(&vxlan(&inner_eth));
    let short_totlen: Vec<Vec<u8>> = (1..=19u16)
        .map(|total| {
            eth(
                0x0800,
                &ipv4_len(
                    OUTER,
                    [10, 255, 255, 1],
                    17,
                    total,
                    &udp(12345, 53, PAYLOAD),
                ),
            )
        })
        .collect();
    let icmp_inner = ipv4(EMBED, [10, 1, 1, 1], 17, &udp(1, 2, PAYLOAD));
    let icmp = icmp_error(&icmp_inner);
    let icmp_first = icmp[..24].to_vec();
    let icmp_rest = icmp[24..].to_vec();
    let v6_then_v4 = ipv6(4, &ipv4(INNER, [10, 255, 255, 1], 17, &udp(9, 9, PAYLOAD)));
    let icmpv6 = icmpv6_error(&v6_then_v4);
    let icmpv6_first = icmpv6[..32].to_vec();
    let icmpv6_rest = icmpv6[32..].to_vec();
    vec![
        (
            "eth-udp-discard",
            pcap(LINK_ETHERNET, &[eth_ipv4_udp(OUTER, 12345, 9, PAYLOAD)]),
        ),
        (
            "eth-udp-dns",
            pcap(LINK_ETHERNET, &[eth_ipv4_udp(OUTER, 12345, 53, PAYLOAD)]),
        ),
        (
            "vlan",
            pcap(
                LINK_ETHERNET,
                &[vlan(
                    0x0800,
                    &ipv4(OUTER, [10, 255, 255, 1], 17, &udp(12345, 53, PAYLOAD)),
                )],
            ),
        ),
        (
            "qinq",
            pcap(
                LINK_ETHERNET,
                &[qinq(&ipv4(
                    OUTER,
                    [10, 255, 255, 1],
                    17,
                    &udp(12345, 53, PAYLOAD),
                ))],
            ),
        ),
        (
            "vlan-9100",
            pcap(LINK_ETHERNET, &[vlan_etype(0x9100, 0x0800, &ip_udp)]),
        ),
        (
            "vlan-9200",
            pcap(LINK_ETHERNET, &[vlan_etype(0x9200, 0x0800, &ip_udp)]),
        ),
        (
            "vlan-9300",
            pcap(LINK_ETHERNET, &[vlan_etype(0x9300, 0x0800, &ip_udp)]),
        ),
        (
            "sll",
            pcap(
                LINK_SLL,
                &[sll(
                    0x0800,
                    &ipv4(OUTER, [10, 255, 255, 1], 17, &udp(12345, 53, PAYLOAD)),
                )],
            ),
        ),
        (
            "sll2",
            pcap(
                LINK_SLL2,
                &[sll2(
                    0x0800,
                    &ipv4(OUTER, [10, 255, 255, 1], 17, &udp(12345, 53, PAYLOAD)),
                )],
            ),
        ),
        (
            "ipv6-udp",
            pcap(
                LINK_ETHERNET,
                &[eth(0x86dd, &ipv6(17, &udp(12345, 53, PAYLOAD)))],
            ),
        ),
        (
            "ipv6-hop-ah",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x86dd,
                    &ipv6(0, &hopopt(51, &ah(17, &udp(12345, 53, PAYLOAD)))),
                )],
            ),
        ),
        (
            "ipv6-esp",
            pcap(LINK_ETHERNET, &[eth(0x86dd, &ipv6(50, PAYLOAD))]),
        ),
        (
            "icmp-error",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x0800,
                    &ipv4(
                        OUTER,
                        [10, 255, 255, 1],
                        1,
                        &icmp_error(&ipv4(EMBED, [10, 1, 1, 1], 17, &udp(1, 2, PAYLOAD))),
                    ),
                )],
            ),
        ),
        (
            "icmp-ipip-embed",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x0800,
                    &ipv4(
                        OUTER,
                        [10, 255, 255, 1],
                        1,
                        &icmp_error(&ipv4(
                            INNER,
                            [10, 1, 1, 1],
                            4,
                            &ipv4(EMBED, [10, 2, 2, 2], 17, &udp(9, 9, PAYLOAD)),
                        )),
                    ),
                )],
            ),
        ),
        (
            "icmp-frag",
            pcap(
                LINK_ETHERNET,
                &[
                    eth(
                        0x0800,
                        &ipv4_frag(OUTER, [10, 255, 255, 1], 1, 42, 0, true, &icmp_first),
                    ),
                    eth(
                        0x0800,
                        &ipv4_frag(OUTER, [10, 255, 255, 1], 1, 42, 3, false, &icmp_rest),
                    ),
                ],
            ),
        ),
        (
            "icmpv6-error",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x86dd,
                    &ipv6(
                        58,
                        &icmpv6_error(&ipv4(EMBED, [10, 1, 1, 1], 17, &udp(1, 2, PAYLOAD))),
                    ),
                )],
            ),
        ),
        (
            "icmpv6-frag",
            pcap(
                LINK_ETHERNET,
                &[
                    eth(0x86dd, &ipv6(44, &ipv6_frag(58, 0, true, 1, &icmpv6_first))),
                    eth(0x86dd, &ipv6(44, &ipv6_frag(58, 4, false, 1, &icmpv6_rest))),
                ],
            ),
        ),
        (
            "ipip",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x0800,
                    &ipv4(
                        OUTER,
                        [10, 255, 255, 1],
                        4,
                        &ipv4(INNER, [10, 1, 1, 1], 17, &udp(12345, 53, PAYLOAD)),
                    ),
                )],
            ),
        ),
        (
            "ipv4-ah",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x0800,
                    &ipv4(
                        OUTER,
                        [10, 255, 255, 1],
                        51,
                        &ah(4, &ipv4(INNER, [10, 255, 255, 1], 17, &udp(9, 9, PAYLOAD))),
                    ),
                )],
            ),
        ),
        (
            "etherip",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x0800,
                    &ipv4(OUTER, [10, 255, 255, 1], 97, &etherip(&inner_eth)),
                )],
            ),
        ),
        (
            "unknown-proto",
            pcap(
                LINK_ETHERNET,
                &[eth(0x0800, &ipv4(OUTER, [10, 255, 255, 1], 99, PAYLOAD))],
            ),
        ),
        (
            "ip-ipv6",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x0800,
                    &ipv4(OUTER, [10, 255, 255, 1], 41, &ipv6(17, PAYLOAD)),
                )],
            ),
        ),
        (
            "vxlan-high-src",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_udp(OUTER, 50000, 4789, &vxlan(&inner_eth))],
            ),
        ),
        (
            "vxlan-low-src",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_udp(OUTER, 4789, 50000, &vxlan(&inner_eth))],
            ),
        ),
        (
            "vxlan-dns-collision",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_udp(OUTER, 53, 4789, &vxlan(&inner_eth))],
            ),
        ),
        (
            "gre",
            pcap(
                LINK_ETHERNET,
                &[eth(0x0800, &ipv4(OUTER, [10, 255, 255, 1], 47, PAYLOAD))],
            ),
        ),
        ("mpls", pcap(LINK_ETHERNET, &[eth(0x8847, PAYLOAD)])),
        (
            "unregistered-udp",
            pcap(LINK_ETHERNET, &[eth_ipv4_udp(OUTER, 40000, 40001, PAYLOAD)]),
        ),
        (
            "unregistered-tcp",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x0800,
                    &ipv4(OUTER, [10, 255, 255, 1], 6, &tcp(40000, 40001, PAYLOAD)),
                )],
            ),
        ),
        (
            "may-reject-dhcp",
            pcap(LINK_ETHERNET, &[eth_ipv4_udp(OUTER, 12345, 67, PAYLOAD)]),
        ),
        (
            "udp-frag-first",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x0800,
                    &ipv4_frag(
                        OUTER,
                        [10, 255, 255, 1],
                        17,
                        7,
                        0,
                        true,
                        &udp(12345, 53, PAYLOAD),
                    ),
                )],
            ),
        ),
        (
            "udp-frag-group",
            pcap(
                LINK_ETHERNET,
                &[
                    eth(
                        0x0800,
                        &ipv4_frag(
                            OUTER,
                            [10, 255, 255, 1],
                            17,
                            8,
                            0,
                            true,
                            &udp(50000, 4789, &vxlan(&inner_eth)),
                        ),
                    ),
                    eth(
                        0x0800,
                        &ipv4_frag(OUTER, [10, 255, 255, 1], 17, 8, 24, false, PAYLOAD),
                    ),
                ],
            ),
        ),
        (
            "gre-frag",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x0800,
                    &ipv4_frag(OUTER, [10, 255, 255, 1], 47, 9, 0, true, PAYLOAD),
                )],
            ),
        ),
        (
            "bogus-version",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x0800,
                    &[
                        0x55, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 1, 1, 1,
                    ],
                )],
            ),
        ),
        (
            "empty-udp",
            pcap(LINK_ETHERNET, &[eth_ipv4_udp(OUTER, 12345, 53, b"")]),
        ),
        (
            "tcp-dns",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x0800,
                    &ipv4(OUTER, [10, 255, 255, 1], 6, &tcp(12345, 53, PAYLOAD)),
                )],
            ),
        ),
        ("arp", pcap(LINK_ETHERNET, &[eth(0x0806, &[0u8; 28])])),
        ("teb", pcap(LINK_ETHERNET, &[eth(0x6558, &inner_eth)])),
        (
            "ipv6-short-plen-vxlan",
            pcap(
                LINK_ETHERNET,
                &[eth(0x86dd, &ipv6_len(17, 8, &ipv6_short_plen_vxlan))],
            ),
        ),
        (
            "ipv6-zero-plen-ipip",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x86dd,
                    &ipv6_len(
                        4,
                        0,
                        &ipv4(INNER, [10, 255, 255, 1], 17, &udp(9, 9, PAYLOAD)),
                    ),
                )],
            ),
        ),
        (
            "ipv6-hopopt-jumbo-ipip",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x86dd,
                    &ipv6_len(
                        0,
                        0,
                        &hopopt_jumbo(
                            4,
                            65536,
                            &ipv4(INNER, [10, 255, 255, 1], 17, &udp(9, 9, PAYLOAD)),
                        ),
                    ),
                )],
            ),
        ),
        (
            "ipv6-hopopt-jumbo-vxlan",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x86dd,
                    &ipv6_len(
                        0,
                        0,
                        &hopopt_jumbo(17, 65536, &udp(50000, 4789, &vxlan(&inner_eth))),
                    ),
                )],
            ),
        ),
        (
            "ipv6-hopopt-jumbo-65535",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x86dd,
                    &ipv6_len(
                        0,
                        0,
                        &hopopt_jumbo(
                            4,
                            65535,
                            &ipv4(INNER, [10, 255, 255, 1], 17, &udp(9, 9, PAYLOAD)),
                        ),
                    ),
                )],
            ),
        ),
        (
            "ipv6-hopopt-jumbo-ffffffd7",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x86dd,
                    &ipv6_len(
                        0,
                        0,
                        &hopopt_jumbo(
                            4,
                            0xffff_ffd7,
                            &ipv4(INNER, [10, 255, 255, 1], 17, &udp(9, 9, PAYLOAD)),
                        ),
                    ),
                )],
            ),
        ),
        (
            "ipv6-hopopt-jumbo-ffffffd8",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x86dd,
                    &ipv6_len(
                        0,
                        0,
                        &hopopt_jumbo(
                            4,
                            0xffff_ffd8,
                            &ipv4(INNER, [10, 255, 255, 1], 17, &udp(9, 9, PAYLOAD)),
                        ),
                    ),
                )],
            ),
        ),
        (
            "ipv6-hopopt-jumbo-fffffffe",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x86dd,
                    &ipv6_len(
                        0,
                        0,
                        &hopopt_jumbo(
                            4,
                            0xffff_fffe,
                            &ipv4(INNER, [10, 255, 255, 1], 17, &udp(9, 9, PAYLOAD)),
                        ),
                    ),
                )],
            ),
        ),
        (
            "ipv6-hopopt-jumbo-ffffffff",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x86dd,
                    &ipv6_len(
                        0,
                        0,
                        &hopopt_jumbo(
                            4,
                            0xffff_ffff,
                            &ipv4(INNER, [10, 255, 255, 1], 17, &udp(9, 9, PAYLOAD)),
                        ),
                    ),
                )],
            ),
        ),
        (
            "ipv6-dstopts-jumbo-ipip",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x86dd,
                    &ipv6_len(
                        60,
                        0,
                        &hopopt_jumbo(
                            4,
                            65536,
                            &ipv4(INNER, [10, 255, 255, 1], 17, &udp(9, 9, PAYLOAD)),
                        ),
                    ),
                )],
            ),
        ),
        ("ipv4-short-totlen", pcap(LINK_ETHERNET, &short_totlen)),
        (
            "ipv4-short-totlen-ipip",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x0800,
                    &ipv4_len(
                        OUTER,
                        [10, 255, 255, 1],
                        4,
                        10,
                        &ipv4(INNER, [10, 255, 255, 1], 17, &udp(9, 9, PAYLOAD)),
                    ),
                )],
            ),
        ),
        (
            "ipv4-zero-totlen",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x0800,
                    &ipv4_len(OUTER, [10, 255, 255, 1], 17, 0, &udp(12345, 53, PAYLOAD)),
                )],
            ),
        ),
        (
            "ipv4-zero-totlen-ipip",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x0800,
                    &ipv4_len(
                        OUTER,
                        [10, 255, 255, 1],
                        4,
                        0,
                        &ipv4(INNER, [10, 255, 255, 1], 17, &udp(9, 9, PAYLOAD)),
                    ),
                )],
            ),
        ),
        (
            "udp-len-8-vxlan",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x0800,
                    &ipv4(
                        OUTER,
                        [10, 255, 255, 1],
                        17,
                        &udp_len(50000, 4789, 8, &vxlan(&inner_eth)),
                    ),
                )],
            ),
        ),
        (
            "udp-len-0-vxlan",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x0800,
                    &ipv4(
                        OUTER,
                        [10, 255, 255, 1],
                        17,
                        &udp_len(50000, 4789, 0, &vxlan(&inner_eth)),
                    ),
                )],
            ),
        ),
        (
            "udp-len-16-vxlan",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x0800,
                    &ipv4(
                        OUTER,
                        [10, 255, 255, 1],
                        17,
                        &udp_len(50000, 4789, 16, &vxlan(&inner_eth)),
                    ),
                )],
            ),
        ),
        (
            "ipv6-udp-len-8-vxlan",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x86dd,
                    &ipv6(17, &udp_len(50000, 4789, 8, &vxlan(&inner_eth))),
                )],
            ),
        ),
        (
            "ipv6-udp-len-0-vxlan",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x86dd,
                    &ipv6(17, &udp_len(50000, 4789, 0, &vxlan(&inner_eth))),
                )],
            ),
        ),
        (
            "ethertype-ip-as-ipv6",
            pcap(LINK_ETHERNET, &[eth(0x0800, &v6_then_v4)]),
        ),
        (
            "ipip-ipv6-as-v4",
            pcap(
                LINK_ETHERNET,
                &[eth(0x0800, &ipv4(OUTER, [10, 255, 255, 1], 4, &v6_then_v4))],
            ),
        ),
        (
            "ipv6-next4-ipv6-ipv4",
            pcap(LINK_ETHERNET, &[eth(0x86dd, &ipv6(4, &v6_then_v4))]),
        ),
        (
            "vxlan-inner-ip-as-ipv6",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_udp(
                    OUTER,
                    50000,
                    4789,
                    &vxlan(&eth(0x0800, &v6_then_v4)),
                )],
            ),
        ),
        (
            "icmp-3-embed-ipv6",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x0800,
                    &ipv4(OUTER, [10, 255, 255, 1], 1, &icmp_type(3, &v6_then_v4)),
                )],
            ),
        ),
        (
            "icmp-4-embed-ipv6",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x0800,
                    &ipv4(OUTER, [10, 255, 255, 1], 1, &icmp_type(4, &v6_then_v4)),
                )],
            ),
        ),
        (
            "icmp-11-embed-ipv6",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x0800,
                    &ipv4(OUTER, [10, 255, 255, 1], 1, &icmp_type(11, &v6_then_v4)),
                )],
            ),
        ),
        (
            "icmp-12-embed-ipv6",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x0800,
                    &ipv4(OUTER, [10, 255, 255, 1], 1, &icmp_type(12, &v6_then_v4)),
                )],
            ),
        ),
        (
            "icmp-5-embed-ipv6",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x0800,
                    &ipv4(OUTER, [10, 255, 255, 1], 1, &icmp_type(5, &v6_then_v4)),
                )],
            ),
        ),
        (
            "icmp-3-embed-ipv6-len-0-flow-0100",
            pcap(LINK_ETHERNET, &[icmp_v6_rfc4884(3, 0, 0x0100)]),
        ),
        (
            "icmp-3-embed-ipv6-len-1-flow-0100",
            pcap(LINK_ETHERNET, &[icmp_v6_rfc4884(3, 1, 0x0100)]),
        ),
        (
            "icmp-4-embed-ipv6-len-1-flow-0100",
            pcap(LINK_ETHERNET, &[icmp_v6_rfc4884(4, 1, 0x0100)]),
        ),
        (
            "icmp-11-embed-ipv6-len-1-flow-0100",
            pcap(LINK_ETHERNET, &[icmp_v6_rfc4884(11, 1, 0x0100)]),
        ),
        (
            "icmp-12-embed-ipv6-len-1-flow-0100",
            pcap(LINK_ETHERNET, &[icmp_v6_rfc4884(12, 1, 0x0100)]),
        ),
        (
            "icmp-3-embed-ipv6-len-1-flow-1",
            pcap(LINK_ETHERNET, &[icmp_v6_rfc4884(3, 1, 1)]),
        ),
        (
            "icmp-3-embed-ipv6-len-13-flow-0100",
            pcap(LINK_ETHERNET, &[icmp_v6_rfc4884(3, 13, 0x0100)]),
        ),
        (
            "icmp-3-embed-ipv6-len-14-flow-0100",
            pcap(LINK_ETHERNET, &[icmp_v6_rfc4884(3, 14, 0x0100)]),
        ),
        (
            "icmp-5-embed-ipv6-len-14",
            pcap(LINK_ETHERNET, &[icmp_v6_rfc4884(5, 14, 0x0100)]),
        ),
        (
            "icmp-3-embed-ipv4-len-1",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x0800,
                    &ipv4(
                        OUTER,
                        [10, 255, 255, 1],
                        1,
                        &icmp_type_len(3, 1, &ipv4(EMBED, [10, 1, 1, 1], 17, &udp(1, 2, PAYLOAD))),
                    ),
                )],
            ),
        ),
        (
            "icmp-embed-short-totlen",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x0800,
                    &ipv4(
                        OUTER,
                        [10, 255, 255, 1],
                        1,
                        &icmp_type(3, &ipv4_len(EMBED, [10, 255, 255, 1], 17, 10, b"")),
                    ),
                )],
            ),
        ),
        (
            "icmp-embed-short-totlen-ipip",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x0800,
                    &ipv4(
                        OUTER,
                        [10, 255, 255, 1],
                        1,
                        &icmp_type(
                            3,
                            &ipv4_len(
                                INNER,
                                [10, 255, 255, 1],
                                4,
                                10,
                                &ipv4(INNER, [10, 255, 255, 1], 17, &udp(9, 9, PAYLOAD)),
                            ),
                        ),
                    ),
                )],
            ),
        ),
        (
            "icmp-embed-zero-totlen",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x0800,
                    &ipv4(
                        OUTER,
                        [10, 255, 255, 1],
                        1,
                        &icmp_type(
                            3,
                            &ipv4_len(EMBED, [10, 255, 255, 1], 17, 0, &udp(1, 2, PAYLOAD)),
                        ),
                    ),
                )],
            ),
        ),
        (
            "ipv6-routing-type2-hdrlen0",
            pcap(LINK_ETHERNET, &[ipv6_routing_ipip(0, 2, &[])]),
        ),
        (
            "ipv6-routing-type2-hdrlen1",
            pcap(LINK_ETHERNET, &[ipv6_routing_ipip(1, 2, &[])]),
        ),
        (
            "ipv6-routing-type4-hdrlen0",
            pcap(LINK_ETHERNET, &[ipv6_routing_ipip(0, 4, &[])]),
        ),
        (
            "ipv6-routing-type4-hdrlen1",
            pcap(LINK_ETHERNET, &[ipv6_routing_ipip(1, 4, &[])]),
        ),
        (
            "ipv6-routing-type4-hdrlen2-last-entry-255",
            pcap(LINK_ETHERNET, &[ipv6_routing_ipip(2, 4, &[255])]),
        ),
        (
            "ipv6-routing-type0-hdrlen0",
            pcap(LINK_ETHERNET, &[ipv6_routing_ipip(0, 0, &[])]),
        ),
        (
            "ipv6-routing-type3-hdrlen0",
            pcap(LINK_ETHERNET, &[ipv6_routing_ipip(0, 3, &[])]),
        ),
        (
            "ipv6-routing-type99-hdrlen0",
            pcap(LINK_ETHERNET, &[ipv6_routing_ipip(0, 99, &[])]),
        ),
        (
            "ipv6-routing-type2-hdrlen2",
            pcap(LINK_ETHERNET, &[ipv6_routing_ipip(2, 2, &[])]),
        ),
        (
            "ipv6-routing-type4-hdrlen2",
            pcap(LINK_ETHERNET, &[ipv6_routing_ipip(2, 4, &[0])]),
        ),
        (
            "ipv6-routing-type3-hdrlen1",
            pcap(LINK_ETHERNET, &[ipv6_routing_ipip(1, 3, &[])]),
        ),
        (
            "ipv6-routing-type3-hdrlen1-cmpr11",
            pcap(LINK_ETHERNET, &[ipv6_routing_ipip(1, 3, &[0x11])]),
        ),
        (
            "ipv6-routing-type3-hdrlen2",
            pcap(LINK_ETHERNET, &[ipv6_routing_ipip(2, 3, &[])]),
        ),
        (
            "ipv6-routing-type5-hdrlen0-sids-0001",
            pcap(LINK_ETHERNET, &[ipv6_routing_ipip(0, 5, &[0, 1, 0, 1])]),
        ),
        (
            "ipv6-routing-type6-hdrlen0-sids-0001",
            pcap(LINK_ETHERNET, &[ipv6_routing_ipip(0, 6, &[0, 1, 0, 1])]),
        ),
        (
            "ipv6-routing-type5-hdrlen0",
            pcap(LINK_ETHERNET, &[ipv6_routing_ipip(0, 5, &[0, 0, 0, 0])]),
        ),
        (
            "ipv6-routing-type6-hdrlen0",
            pcap(LINK_ETHERNET, &[ipv6_routing_ipip(0, 6, &[0, 0, 0, 0])]),
        ),
        (
            "ipv6-routing-type5-hdrlen1-segleft-255",
            pcap(LINK_ETHERNET, &[ipv6_routing_ipip_segs(1, 5, 255, &[])]),
        ),
        (
            "ipv6-routing-type6-hdrlen1-segleft-255",
            pcap(LINK_ETHERNET, &[ipv6_routing_ipip_segs(1, 6, 255, &[])]),
        ),
        (
            "ipv6-hopopt-rtalert-255",
            pcap(LINK_ETHERNET, &[ipv6_opts_ipip(0, &[0x05, 255])]),
        ),
        (
            "ipv6-hopopt-five-pad1-type1",
            pcap(LINK_ETHERNET, &[ipv6_opts_ipip(0, &[0, 0, 0, 0, 0, 1])]),
        ),
        (
            "ipv6-dstopts-rtalert-255",
            pcap(LINK_ETHERNET, &[ipv6_opts_ipip(60, &[0x05, 255])]),
        ),
        (
            "ipv6-dstopts-five-pad1-type1",
            pcap(LINK_ETHERNET, &[ipv6_opts_ipip(60, &[0, 0, 0, 0, 0, 1])]),
        ),
        (
            "ipv6-hopopt-padn-overrun-header",
            pcap(LINK_ETHERNET, &[ipv6_opts_ipip(0, &[0x01, 6])]),
        ),
        (
            "ipv6-dstopts-padn-overrun-header",
            pcap(LINK_ETHERNET, &[ipv6_opts_ipip(60, &[0x01, 6])]),
        ),
    ]
}

fn truncations() -> Vec<(&'static str, Vec<u8>)> {
    let udp_frame = eth_ipv4_udp(OUTER, 12345, 53, PAYLOAD);
    let vlan_frame = vlan(
        0x0800,
        &ipv4(OUTER, [10, 255, 255, 1], 17, &udp(12345, 53, PAYLOAD)),
    );
    let ihl6 = eth(0x0800, &ipv4_ihl(OUTER, 6, &udp(12345, 53, PAYLOAD)));
    let ipv6_frame = eth(0x86dd, &ipv6(17, &udp(12345, 53, PAYLOAD)));
    let hop = eth(0x86dd, &ipv6(0, &hopopt(17, &udp(12345, 53, PAYLOAD))));
    let ah_frame = eth(0x86dd, &ipv6(51, &ah(17, &udp(12345, 53, PAYLOAD))));
    let icmp = eth(
        0x0800,
        &ipv4(
            OUTER,
            [10, 255, 255, 1],
            1,
            &icmp_error(&ipv4(EMBED, [10, 1, 1, 1], 17, &udp(1, 2, PAYLOAD))),
        ),
    );
    let ipip = eth(
        0x0800,
        &ipv4(
            OUTER,
            [10, 255, 255, 1],
            4,
            &ipv4(INNER, [10, 1, 1, 1], 17, &udp(12345, 53, PAYLOAD)),
        ),
    );
    let inner_eth = eth(
        0x0800,
        &ipv4(INNER, [10, 255, 255, 1], 17, &udp(9, 9, PAYLOAD)),
    );
    let vx = eth_ipv4_udp(OUTER, 50000, 4789, &vxlan(&inner_eth));
    let tcp_frame = eth(
        0x0800,
        &ipv4(OUTER, [10, 255, 255, 1], 6, &tcp(12345, 53, PAYLOAD)),
    );
    let sll_frame = sll(
        0x0800,
        &ipv4(OUTER, [10, 255, 255, 1], 17, &udp(12345, 53, PAYLOAD)),
    );
    let sll2_frame = sll2(
        0x0800,
        &ipv4(OUTER, [10, 255, 255, 1], 17, &udp(12345, 53, PAYLOAD)),
    );
    vec![
        ("cut-eth-10", pcap(LINK_ETHERNET, &[cut(&udp_frame, 10)])),
        ("cut-sll-10", pcap(LINK_SLL, &[cut(&sll_frame, 10)])),
        ("cut-sll2-12", pcap(LINK_SLL2, &[cut(&sll2_frame, 12)])),
        ("cut-vlan-16", pcap(LINK_ETHERNET, &[cut(&vlan_frame, 16)])),
        (
            "cut-ipv4-before-src",
            pcap(LINK_ETHERNET, &[cut(&udp_frame, 14 + 10)]),
        ),
        (
            "cut-ipv4-inside-src",
            pcap(LINK_ETHERNET, &[cut(&udp_frame, 14 + 14)]),
        ),
        (
            "cut-ipv4-after-src-ihl",
            pcap(LINK_ETHERNET, &[cut(&ihl6, 14 + 18)]),
        ),
        (
            "cut-ipv6-20",
            pcap(LINK_ETHERNET, &[cut(&ipv6_frame, 14 + 20)]),
        ),
        ("cut-hopopt", pcap(LINK_ETHERNET, &[cut(&hop, 14 + 40 + 2)])),
        (
            "cut-ah",
            pcap(LINK_ETHERNET, &[cut(&ah_frame, 14 + 40 + 8)]),
        ),
        (
            "cut-icmp-hdr",
            pcap(LINK_ETHERNET, &[cut(&icmp, 14 + 20 + 4)]),
        ),
        (
            "cut-icmp-embed",
            pcap(LINK_ETHERNET, &[cut(&icmp, 14 + 20 + 8 + 10)]),
        ),
        (
            "cut-ipip-inner",
            pcap(LINK_ETHERNET, &[cut(&ipip, 14 + 20 + 10)]),
        ),
        (
            "cut-udp-hdr",
            pcap(LINK_ETHERNET, &[cut(&udp_frame, 14 + 20 + 4)]),
        ),
        (
            "cut-tcp-hdr",
            pcap(LINK_ETHERNET, &[cut(&tcp_frame, 14 + 20 + 10)]),
        ),
        (
            "cut-vxlan-hdr",
            pcap(LINK_ETHERNET, &[cut(&vx, 14 + 20 + 8 + 4)]),
        ),
        (
            "cut-vxlan-inner-eth",
            pcap(LINK_ETHERNET, &[cut(&vx, 14 + 20 + 8 + 8 + 10)]),
        ),
    ]
}

fn random_cases() -> Vec<(&'static str, Vec<u8>)> {
    let base = eth_ipv4_udp(OUTER, 12345, 53, PAYLOAD);
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut files = Vec::new();
    for _ in 0..64 {
        let mut frame = base.clone();
        if rng.bit() {
            let len = 1 + rng.bounded(frame.len() as u16) as usize;
            frame.truncate(len.max(1));
        } else {
            let index = rng.bounded(frame.len() as u16) as usize;
            frame[index] ^= 1 + rng.bounded(255) as u8;
        }
        files.push(("random", pcap(LINK_ETHERNET, &[frame])));
    }
    files
}

fn on_disk() -> Vec<(&'static str, Vec<u8>)> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../study/corpus");
    let named = [
        ("corpus-eth-100", root.join("eth-ipv4-udp-100.pcap")),
        ("corpus-qinq-100", root.join("eth-qinq-ipv4-udp-100.pcap")),
        ("corpus-mixed-100", root.join("mixed-100.pcap")),
        (
            "challenge01",
            root.join("real/challenge01_ooo_stream.pcapng"),
        ),
        ("bigFlows", root.join("real/bigFlows.pcap")),
        ("vxlan-public", root.join("real/vxlan.pcap")),
    ];
    let mut out = Vec::new();
    for (name, path) in named {
        match fs::read(&path) {
            Ok(bytes) => out.push((name, bytes)),
            Err(_) => eprintln!("skip: {name} missing"),
        }
    }
    out
}

fn check_one(tshark: &Path, fin: &Path, dir: &Path, name: &str, file: &[u8]) -> Option<String> {
    static SEQ: OnceLock<std::sync::atomic::AtomicU64> = OnceLock::new();
    let seq = SEQ
        .get_or_init(|| std::sync::atomic::AtomicU64::new(0))
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = dir.join(format!("ip-src-{seq}.pcap"));
    fs::write(&path, file).unwrap();
    let mut args = vec![OsString::from("-r"), path.as_os_str().to_os_string()];
    args.extend(
        ["-n", "-T", "fields", "-e", "ip.src"]
            .into_iter()
            .map(OsString::from),
    );
    let output = match run_pair(tshark, fin, &args) {
        Ok(output) => output,
        Err(error) => return Some(format!("{name}: {error}")),
    };
    match check_pair(&output) {
        Ok(report) if report.faults.is_empty() => None,
        Ok(report) => Some(format!(
            "{name}: {report}tshark={:?} fin={:?} stderr={}",
            output.tshark_stdout.chars().take(80).collect::<String>(),
            output.fin_stdout.chars().take(80).collect::<String>(),
            output.fin_stderr.chars().take(200).collect::<String>()
        )),
        Err(error) => Some(format!("{name}: {error}")),
    }
}

fn tools() -> Option<(PathBuf, PathBuf)> {
    let Some(tshark) = tshark_path() else {
        eprintln!("skip: tshark 4.6.9 is not installed");
        return None;
    };
    match TsharkSession::open(&tshark) {
        Ok(_) => {}
        Err(RunError::Version { found }) => {
            eprintln!("skip: tshark version is {found}");
            return None;
        }
        Err(RunError::Spawn { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            eprintln!("skip: tshark 4.6.9 is not installed");
            return None;
        }
        Err(error) => panic!("{error}"),
    }
    Some((tshark, fin_bin()))
}

fn fin_bin() -> PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let status = Command::new(cargo)
            .args(["build", "-p", "fin", "--quiet"])
            .status()
            .expect("cargo build -p fin");
        assert!(status.success(), "cargo build -p fin");
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.pop();
        path.push("target");
        path.push(profile);
        path.push(format!("fin{}", env::consts::EXE_SUFFIX));
        path
    })
    .clone()
}

fn work_dir() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = env::temp_dir().join(format!("fin-ip-src-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    })
}

fn tshark_path() -> Option<PathBuf> {
    let windows = PathBuf::from(r"C:\Program Files\Wireshark\tshark.exe");
    if windows.is_file() {
        return Some(windows);
    }
    let local = PathBuf::from("/usr/local/bin/tshark");
    if local.is_file() {
        return Some(local);
    }
    on_path("tshark")
}

fn on_path(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path).find_map(|dir| {
        let unix = dir.join(name);
        if unix.is_file() {
            return Some(unix);
        }
        let windows = dir.join(format!("{name}.exe"));
        windows.is_file().then_some(windows)
    })
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn bounded(&mut self, max: u16) -> u16 {
        (self.next() % u64::from(max.max(1))) as u16
    }

    fn bit(&mut self) -> bool {
        self.bounded(2) == 1
    }
}
