//! Oracle: `fin -T fields -e tls.handshake.extensions_server_name` against tshark 4.6.9.

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

const FIELD: &str = "tls.handshake.extensions_server_name";

#[test]
fn tls_sni_matches_tshark_469() {
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
fn stdin_matches_the_file_path() {
    let fin = fin_bin();
    let path = work_dir().join("sni-stdin-vs-file.pcap");
    fs::write(
        &path,
        pcap(
            LINK_ETHERNET,
            &[eth_ipv4_tcp(
                OUTER,
                50000,
                443,
                &client_hello(Some("stdin.example")),
            )],
        ),
    )
    .unwrap();
    let file = Command::new(&fin)
        .arg("-r")
        .arg(&path)
        .args(["-n", "-T", "fields", "-e", FIELD])
        .output()
        .expect("fin file");
    let stdin = Command::new(&fin)
        .args(["-r", "-", "-n", "-T", "fields", "-e", FIELD])
        .stdin(fs::File::open(&path).unwrap())
        .output()
        .expect("fin stdin");
    assert_eq!(file.stdout, stdin.stdout, "stdout");
    assert_eq!(file.stderr, stdin.stderr, "stderr");
    assert_eq!(file.status.code(), stdin.status.code());
}

#[test]
fn combined_ip_src_and_sni_matches_tshark_469() {
    let Some((tshark, fin)) = tools() else {
        return;
    };
    let dir = work_dir();
    for (name, host) in [
        ("combined", client_hello(Some("www.example.com"))),
        ("combined-tab", client_hello_host(Some(b"ab\tcd"), 0x0301)),
        ("combined-nl", client_hello_host(Some(b"ab\ncd"), 0x0301)),
        ("combined-cr", client_hello_host(Some(b"ab\rcd"), 0x0301)),
        ("combined-bs", client_hello_host(Some(b"ab\\cd"), 0x0301)),
    ] {
        let file = pcap(LINK_ETHERNET, &[eth_ipv4_tcp(OUTER, 50000, 443, &host)]);
        let path = dir.join(format!("{name}.pcap"));
        fs::write(&path, file).unwrap();
        let mut args = vec![OsString::from("-r"), path.as_os_str().to_os_string()];
        args.extend(
            ["-n", "-T", "fields", "-e", "ip.src", "-e", FIELD]
                .into_iter()
                .map(OsString::from),
        );
        let output = run_pair(&tshark, &fin, &args).expect("pair");
        let report = check_pair(&output).expect("check");
        assert!(
            report.faults.is_empty(),
            "{name}: {report} tshark={:?} fin={:?}",
            output.tshark_stdout,
            output.fin_stdout
        );
    }
}

#[test]
fn unknown_field_is_still_an_error() {
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
fn fuzz_mutated_client_hello_matches_tshark_469() {
    let Some((tshark, fin)) = tools() else {
        return;
    };
    let dir = work_dir();
    let mut faults = Vec::new();
    for (index, file) in fuzz_cases().into_iter().enumerate() {
        let name = format!("fuzz-{index}");
        if let Some(fault) = check_one(&tshark, &fin, dir, &name, &file) {
            faults.push(fault);
            if faults.len() >= 8 {
                break;
            }
        }
    }
    assert!(
        faults.is_empty(),
        "tshark 4.6.9 fuzz mismatches:\n{}",
        faults.join("\n")
    );
}

fn cases() -> Vec<(&'static str, Vec<u8>)> {
    let hello = client_hello(Some("www.example.com"));
    let no_sni = client_hello(None);
    let mut truncated = hello.clone();
    truncated.truncate(truncated.len() - 8);
    let vlan_frame = vlan(0x0800, &ipv4(OUTER, 6, &tcp(50000, 443, &hello)));
    let ipv6_frame = eth(0x86dd, &ipv6(6, &tcp(50000, 443, &hello)));
    let sll_frame = sll(0x0800, &ipv4(OUTER, 6, &tcp(50000, 443, &hello)));
    let retransmit = vec![
        eth_ipv4_tcp(OUTER, 50000, 443, &hello),
        eth(0x0800, &ipv4(OUTER, 6, &tcp_seq(50000, 443, 1, &hello))),
    ];
    vec![
        (
            "sni-443",
            pcap(LINK_ETHERNET, &[eth_ipv4_tcp(OUTER, 50000, 443, &hello)]),
        ),
        ("sni-ipv6", pcap(LINK_ETHERNET, &[ipv6_frame])),
        ("sni-vlan", pcap(LINK_ETHERNET, &[vlan_frame])),
        ("sni-sll", pcap(LINK_SLL, &[sll_frame])),
        (
            "no-sni-hello",
            pcap(LINK_ETHERNET, &[eth_ipv4_tcp(OUTER, 50000, 443, &no_sni)]),
        ),
        (
            "http-on-443",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    443,
                    b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
                )],
            ),
        ),
        (
            "truncated-record",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(OUTER, 50000, 443, &truncated)],
            ),
        ),
        (
            "smtp-hello",
            pcap(LINK_ETHERNET, &[eth_ipv4_tcp(OUTER, 50000, 25, &hello)]),
        ),
        (
            "udp-dns",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_udp(OUTER, 12345, 53, b"not-tls-payload!!")],
            ),
        ),
        ("retransmit", pcap(LINK_ETHERNET, &retransmit)),
        (
            "sni-pcapng",
            pcapng(1, &[eth_ipv4_tcp(OUTER, 50000, 443, &hello)]),
        ),
        (
            "mixed",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp(OUTER, 50000, 443, &hello),
                    eth_ipv4_tcp(OUTER, 50000, 443, b"GET / HTTP/1.1\r\n"),
                    eth_ipv4_tcp(OUTER, 50000, 443, &no_sni),
                    eth_ipv4_udp(OUTER, 12345, 9, b"discard"),
                ],
            ),
        ),
        ("chunked-sni", chunked_sni()),
        ("split-hello", split_client_hello()),
        on_disk_named(),
    ]
    .into_iter()
    .chain(record_version_cases())
    .chain(review_cases())
    .filter(|(_, bytes)| !bytes.is_empty())
    .collect()
}

fn record_version_cases() -> Vec<(&'static str, Vec<u8>)> {
    [
        ("record-ver-0a0a", 0x0a0au16),
        ("record-ver-0002", 0x0002),
        ("record-ver-0100", 0x0100),
        ("record-ver-7f1c", 0x7f1c),
        ("record-ver-fb17", 0xfb17),
        ("record-ver-feff", 0xfeff),
        ("record-ver-fefd", 0xfefd),
        ("record-ver-fefc", 0xfefc),
    ]
    .into_iter()
    .map(|(name, version)| {
        let mut hello = client_hello(Some("www.example.com"));
        hello[1..3].copy_from_slice(&version.to_be_bytes());
        (
            name,
            pcap(LINK_ETHERNET, &[eth_ipv4_tcp(OUTER, 50000, 443, &hello)]),
        )
    })
    .collect()
}

fn split_client_hello() -> Vec<u8> {
    split_hello_at(40)
}

fn split_hello_at(cut: usize) -> Vec<u8> {
    let hello = client_hello(Some("www.example.com"));
    pcap(
        LINK_ETHERNET,
        &[
            eth_ipv4_tcp_seq(OUTER, 50000, 443, 1, &hello[..cut]),
            eth_ipv4_tcp_seq(OUTER, 50000, 443, 1 + cut as u32, &hello[cut..]),
        ],
    )
}

fn review_cases() -> Vec<(&'static str, Vec<u8>)> {
    let hello = client_hello(Some("www.example.com"));
    let mut hello_0304 = hello.clone();
    hello_0304[1..3].copy_from_slice(&0x0304u16.to_be_bytes());
    let grease = client_hello_host(Some(b"www.example.com"), 0x0a0a);
    let mut ccs_hello = ccs();
    ccs_hello.extend_from_slice(&hello);
    let mut alert_hello = vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
    alert_hello.extend_from_slice(&hello);
    let mut heartbeat_hello = vec![0x18, 0x03, 0x03, 0x00, 0x03, 0x01, 0x00, 0x00];
    heartbeat_hello.extend_from_slice(&hello);
    let mut app_hello = vec![0x17, 0x03, 0x03, 0x00, 0x01, 0x01];
    app_hello.extend_from_slice(&hello);
    let mut ccs_grease = ccs();
    ccs_grease.extend_from_slice(&grease);
    let mut alert_grease = vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
    alert_grease.extend_from_slice(&grease);
    let mut app_grease = vec![0x17, 0x03, 0x03, 0x00, 0x01, 0x01];
    app_grease.extend_from_slice(&grease);
    let mut heartbeat_grease = vec![0x18, 0x03, 0x03, 0x00, 0x03, 0x01, 0x00, 0x00];
    heartbeat_grease.extend_from_slice(&grease);
    vec![
        (
            "unnamed-0304",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(OUTER, 40001, 40002, &hello_0304)],
            ),
        ),
        (
            "unnamed-ccs-hello",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(OUTER, 40001, 40002, &ccs_hello)],
            ),
        ),
        (
            "unnamed-alert-hello",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(OUTER, 40001, 40002, &alert_hello)],
            ),
        ),
        (
            "unnamed-heartbeat-hello",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(OUTER, 40001, 40002, &heartbeat_hello)],
            ),
        ),
        (
            "unnamed-app-hello",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(OUTER, 40001, 40002, &app_hello)],
            ),
        ),
        (
            "sni-nul-mid",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    443,
                    &client_hello_host(Some(b"www\0.example"), 0x0301),
                )],
            ),
        ),
        (
            "sni-nul-trail",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    443,
                    &client_hello_host(Some(b"www.example\0"), 0x0301),
                )],
            ),
        ),
        (
            "sni-nul-multi",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    443,
                    &client_hello_host(Some(b"a\0b\0c"), 0x0301),
                )],
            ),
        ),
        (
            "sni-tab",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    443,
                    &client_hello_host(Some(b"ab\tcd"), 0x0301),
                )],
            ),
        ),
        (
            "sni-newline",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    443,
                    &client_hello_host(Some(b"ab\ncd"), 0x0301),
                )],
            ),
        ),
        (
            "sni-cr",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    443,
                    &client_hello_host(Some(b"ab\rcd"), 0x0301),
                )],
            ),
        ),
        (
            "sni-backslash",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    443,
                    &client_hello_host(Some(b"ab\\cd"), 0x0301),
                )],
            ),
        ),
        (
            "ccs-grease",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(OUTER, 50000, 443, &ccs_grease)],
            ),
        ),
        (
            "alert-grease",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(OUTER, 50000, 443, &alert_grease)],
            ),
        ),
        (
            "app-grease",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(OUTER, 50000, 443, &app_grease)],
            ),
        ),
        (
            "heartbeat-grease",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(OUTER, 50000, 443, &heartbeat_grease)],
            ),
        ),
        (
            "ccs-then-grease",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp_seq(OUTER, 50000, 443, 1, &ccs()),
                    eth_ipv4_tcp_seq(OUTER, 50000, 443, 1 + ccs().len() as u32, &grease),
                ],
            ),
        ),
        ("split-hello-1", split_hello_at(1)),
        ("split-hello-2", split_hello_at(2)),
        ("split-hello-3", split_hello_at(3)),
        ("split-hello-4", split_hello_at(4)),
        ("split-hello-5", split_hello_at(5)),
        ("ccs-grease-0305", ccs_then_hello(0x0305)),
        ("ccs-grease-7f1c", ccs_then_hello(0x7f1c)),
        ("ccs-grease-feff", ccs_then_hello(0xfeff)),
        ("ccs-grease-0002", ccs_then_hello(0x0002)),
        ("serverhello-grease", handshake_then_hello(2)),
        ("hs0-grease", handshake_then_hello(0)),
        ("hs4-grease", handshake_then_hello(4)),
        ("hs11-grease", handshake_then_hello(11)),
        ("hs14-grease", handshake_then_hello(14)),
        ("hs20-grease", handshake_then_hello(20)),
        (
            "serverhello-then-grease",
            handshake_then_hello_next_frame(2),
        ),
        ("clienthello-grease", client_hello_then_grease()),
        (
            "clienthello-then-grease",
            client_hello_then_grease_next_frame(),
        ),
        ("peer-ccs-443", peer_then_grease(443, 50000, &ccs())),
        ("peer-alert-443", peer_then_grease(443, 50000, &alert())),
        ("peer-app-443", peer_then_grease(443, 50000, &app_data())),
        (
            "peer-serverhello-443",
            peer_then_grease(443, 50000, &handshake_type_record(2, 0x0303)),
        ),
        ("peer-ccs-unnamed", peer_then_grease(40002, 40001, &ccs())),
        (
            "peer-alert-unnamed",
            peer_then_grease(40002, 40001, &alert()),
        ),
        (
            "peer-app-unnamed",
            peer_then_grease(40002, 40001, &app_data()),
        ),
        (
            "peer-serverhello-unnamed",
            peer_then_grease(40002, 40001, &handshake_type_record(2, 0x0303)),
        ),
        ("hs1-then-grease", short_handshake_then_grease(&[0x02])),
        (
            "hs2-then-grease",
            short_handshake_then_grease(&[0x02, 0x00]),
        ),
        (
            "hs3-then-grease",
            short_handshake_then_grease(&[0x02, 0x00, 0x00]),
        ),
        (
            "hs-overrun-then-grease",
            short_handshake_then_grease(&[0x02, 0x00, 0x00, 0x14]),
        ),
        (
            "peer-hs1-then-grease",
            peer_then_grease(443, 50000, &[0x16, 0x03, 0x03, 0x00, 0x01, 0x02]),
        ),
        (
            "tls13-sh-grease",
            tls13_server_hello_then_hello(0x0a0a, true),
        ),
        (
            "tls13-sh-then-grease",
            tls13_server_hello_then_hello(0x0a0a, false),
        ),
        ("tls13-sh-0301", tls13_server_hello_then_hello(0x0301, true)),
        (
            "tls13-sh-then-0301",
            tls13_server_hello_then_hello(0x0301, false),
        ),
        ("ccs-split-1", prefix_then_split_hello(&ccs(), 1, 0x0301)),
        ("ccs-split-5", prefix_then_split_hello(&ccs(), 5, 0x0301)),
        ("ccs-split-7", prefix_then_split_hello(&ccs(), 7, 0x0301)),
        (
            "alert-split-1",
            prefix_then_split_hello(&alert(), 1, 0x0301),
        ),
        (
            "alert-split-5",
            prefix_then_split_hello(&alert(), 5, 0x0301),
        ),
        (
            "alert-split-7",
            prefix_then_split_hello(&alert(), 7, 0x0301),
        ),
        (
            "app-split-1",
            prefix_then_split_hello(&app_data(), 1, 0x0301),
        ),
        (
            "app-split-5",
            prefix_then_split_hello(&app_data(), 5, 0x0301),
        ),
        (
            "app-split-7",
            prefix_then_split_hello(&app_data(), 7, 0x0301),
        ),
        (
            "hs0-split-1",
            prefix_then_split_hello(&handshake_type_record(0, 0x0303), 1, 0x0301),
        ),
        (
            "hs0-split-5",
            prefix_then_split_hello(&handshake_type_record(0, 0x0303), 5, 0x0301),
        ),
        (
            "hs0-split-7",
            prefix_then_split_hello(&handshake_type_record(0, 0x0303), 7, 0x0301),
        ),
        (
            "ccs-grease-split-1",
            prefix_then_split_hello(&ccs(), 1, 0x0a0a),
        ),
        (
            "ccs-grease-split-5",
            prefix_then_split_hello(&ccs(), 5, 0x0a0a),
        ),
        (
            "ccs-grease-split-7",
            prefix_then_split_hello(&ccs(), 7, 0x0a0a),
        ),
        ("split-hello-40", split_hello_at(40)),
        ("empty-hs-split-1", empty_then_split_hello(0x16, 1)),
        ("empty-hs-split-5", empty_then_split_hello(0x16, 5)),
        ("empty-hs-split-7", empty_then_split_hello(0x16, 7)),
        ("empty-ccs-split-1", empty_then_split_hello(0x14, 1)),
        ("empty-ccs-split-5", empty_then_split_hello(0x14, 5)),
        ("empty-ccs-split-7", empty_then_split_hello(0x14, 7)),
        ("empty-alert-split-1", empty_then_split_hello(0x15, 1)),
        ("empty-alert-split-5", empty_then_split_hello(0x15, 5)),
        ("empty-alert-split-7", empty_then_split_hello(0x15, 7)),
        ("empty-app-split-1", empty_then_split_hello(0x17, 1)),
        ("empty-app-split-5", empty_then_split_hello(0x17, 5)),
        ("empty-app-split-7", empty_then_split_hello(0x17, 7)),
        ("empty-hs-then-hello", empty_then_complete_hello(0x16)),
        ("empty-ccs-then-hello", empty_then_complete_hello(0x14)),
        ("empty-alert-then-hello", empty_then_complete_hello(0x15)),
        ("empty-app-then-hello", empty_then_complete_hello(0x17)),
        (
            "two-hellos-split-1",
            hello_then_split_hello("www.example.com", "other.example", 1),
        ),
        (
            "two-hellos-split-5",
            hello_then_split_hello("www.example.com", "other.example", 5),
        ),
        (
            "two-hellos-split-7",
            hello_then_split_hello("www.example.com", "other.example", 7),
        ),
        (
            "two-hellos-split-40",
            hello_then_split_hello("www.example.com", "other.example", 40),
        ),
        (
            "two-same-split-1",
            hello_then_split_hello("www.example.com", "www.example.com", 1),
        ),
        ("hello-grease-split-1", hello_then_split_grease(1)),
    ]
    .into_iter()
    .chain(tls13_session_cases())
    .collect()
}

fn tls13_session_cases() -> Vec<(&'static str, Vec<u8>)> {
    let grease = client_hello_host(Some(b"www.example.com"), 0x0a0a);
    let hello_0301 = client_hello(Some("www.example.com"));
    let middles = [
        (
            "tls13-sh-ccs-grease",
            "tls13-sh-then-ccs-then-grease",
            ccs(),
        ),
        (
            "tls13-sh-alert-grease",
            "tls13-sh-then-alert-then-grease",
            alert(),
        ),
        (
            "tls13-sh-app-grease",
            "tls13-sh-then-app-then-grease",
            app_data(),
        ),
        (
            "tls13-sh-heartbeat-grease",
            "tls13-sh-then-heartbeat-then-grease",
            heartbeat(),
        ),
        (
            "tls13-sh-cert-grease",
            "tls13-sh-then-cert-then-grease",
            handshake_type_record(11, 0x0303),
        ),
        (
            "tls13-sh-ee-grease",
            "tls13-sh-then-ee-then-grease",
            handshake_type_record(8, 0x0303),
        ),
        (
            "tls13-sh-finished-grease",
            "tls13-sh-then-finished-then-grease",
            handshake_type_record(20, 0x0303),
        ),
        (
            "tls13-sh-hs0-grease",
            "tls13-sh-then-hs0-then-grease",
            handshake_type_record(0, 0x0303),
        ),
    ];
    let mut cases = Vec::new();
    for (same, frames, middle) in middles {
        cases.push((
            same,
            three_records(&tls13_server_hello(), &middle, &grease, true),
        ));
        cases.push((
            frames,
            three_records(&tls13_server_hello(), &middle, &grease, false),
        ));
    }
    cases.push((
        "tls13-sh-then-ccs-then-0301",
        three_records(&tls13_server_hello(), &ccs(), &hello_0301, false),
    ));
    cases.push((
        "ccs-0304-ccs-0303-grease",
        three_records(&ccs_version(0x0304), &ccs(), &grease, true),
    ));
    cases.push((
        "ccs-0304-then-ccs-then-grease",
        three_records(&ccs_version(0x0304), &ccs(), &grease, false),
    ));
    cases.push((
        "ccs-0304-then-ccs-then-0301",
        three_records(&ccs_version(0x0304), &ccs(), &hello_0301, false),
    ));
    cases.push((
        "early-data-ccs-grease",
        three_records(&client_hello_early_data(), &ccs(), &grease, true),
    ));
    cases.push((
        "early-data-then-ccs-then-grease",
        three_records(&client_hello_early_data(), &ccs(), &grease, false),
    ));
    cases.push((
        "early-data-then-ccs-then-0301",
        three_records(&client_hello_early_data(), &ccs(), &hello_0301, false),
    ));
    cases
}

fn three_records(first: &[u8], second: &[u8], third: &[u8], same_payload: bool) -> Vec<u8> {
    if same_payload {
        let mut payload = first.to_vec();
        payload.extend_from_slice(second);
        payload.extend_from_slice(third);
        pcap(LINK_ETHERNET, &[eth_ipv4_tcp(OUTER, 50000, 443, &payload)])
    } else {
        let second_seq = 1 + first.len() as u32;
        let third_seq = second_seq + second.len() as u32;
        pcap(
            LINK_ETHERNET,
            &[
                eth_ipv4_tcp_seq(OUTER, 50000, 443, 1, first),
                eth_ipv4_tcp_seq(OUTER, 50000, 443, second_seq, second),
                eth_ipv4_tcp_seq(OUTER, 50000, 443, third_seq, third),
            ],
        )
    }
}

fn empty_then_split_hello(content: u8, cut: usize) -> Vec<u8> {
    prefix_then_split_hello(&empty_record(content), cut, 0x0301)
}

fn empty_then_complete_hello(content: u8) -> Vec<u8> {
    let first = empty_record(content);
    let hello = client_hello(Some("www.example.com"));
    pcap(
        LINK_ETHERNET,
        &[
            eth_ipv4_tcp_seq(OUTER, 50000, 443, 1, &first),
            eth_ipv4_tcp_seq(OUTER, 50000, 443, 1 + first.len() as u32, &hello),
        ],
    )
}

fn hello_then_split_hello(first_sni: &str, second_sni: &str, cut: usize) -> Vec<u8> {
    let first = client_hello(Some(first_sni));
    let second = client_hello(Some(second_sni));
    let mut start = first;
    start.extend_from_slice(&second[..cut]);
    pcap(
        LINK_ETHERNET,
        &[
            eth_ipv4_tcp_seq(OUTER, 50000, 443, 1, &start),
            eth_ipv4_tcp_seq(OUTER, 50000, 443, 1 + start.len() as u32, &second[cut..]),
        ],
    )
}

fn hello_then_split_grease(cut: usize) -> Vec<u8> {
    let first = client_hello(Some("www.example.com"));
    let grease = client_hello_host(Some(b"www.example.com"), 0x0a0a);
    let mut start = first;
    start.extend_from_slice(&grease[..cut]);
    pcap(
        LINK_ETHERNET,
        &[
            eth_ipv4_tcp_seq(OUTER, 50000, 443, 1, &start),
            eth_ipv4_tcp_seq(OUTER, 50000, 443, 1 + start.len() as u32, &grease[cut..]),
        ],
    )
}

fn tls13_server_hello_then_hello(version: u16, same_payload: bool) -> Vec<u8> {
    let first = tls13_server_hello();
    let hello = client_hello_host(Some(b"www.example.com"), version);
    if same_payload {
        let mut payload = first;
        payload.extend_from_slice(&hello);
        pcap(LINK_ETHERNET, &[eth_ipv4_tcp(OUTER, 50000, 443, &payload)])
    } else {
        pcap(
            LINK_ETHERNET,
            &[
                eth_ipv4_tcp_seq(OUTER, 50000, 443, 1, &first),
                eth_ipv4_tcp_seq(OUTER, 50000, 443, 1 + first.len() as u32, &hello),
            ],
        )
    }
}

fn prefix_then_split_hello(prefix: &[u8], cut: usize, version: u16) -> Vec<u8> {
    let hello = client_hello_host(Some(b"www.example.com"), version);
    let mut first = prefix.to_vec();
    first.extend_from_slice(&hello[..cut]);
    pcap(
        LINK_ETHERNET,
        &[
            eth_ipv4_tcp_seq(OUTER, 50000, 443, 1, &first),
            eth_ipv4_tcp_seq(OUTER, 50000, 443, 1 + first.len() as u32, &hello[cut..]),
        ],
    )
}

fn short_handshake_then_grease(body: &[u8]) -> Vec<u8> {
    let mut rec = vec![0x16, 0x03, 0x03];
    rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
    rec.extend_from_slice(body);
    let grease = client_hello_host(Some(b"www.example.com"), 0x0a0a);
    pcap(
        LINK_ETHERNET,
        &[
            eth_ipv4_tcp_seq(OUTER, 50000, 443, 1, &rec),
            eth_ipv4_tcp_seq(OUTER, 50000, 443, 1 + rec.len() as u32, &grease),
        ],
    )
}

fn peer_then_grease(server_port: u16, client_port: u16, first: &[u8]) -> Vec<u8> {
    let grease = client_hello_host(Some(b"www.example.com"), 0x0a0a);
    pcap(
        LINK_ETHERNET,
        &[
            eth_ipv4_tcp_flow(PEER, OUTER, server_port, client_port, 1, first),
            eth_ipv4_tcp_flow(OUTER, PEER, client_port, server_port, 1, &grease),
        ],
    )
}

fn handshake_then_hello(msg_type: u8) -> Vec<u8> {
    let mut payload = handshake_type_record(msg_type, 0x0303);
    payload.extend_from_slice(&client_hello_host(Some(b"www.example.com"), 0x0a0a));
    pcap(LINK_ETHERNET, &[eth_ipv4_tcp(OUTER, 50000, 443, &payload)])
}

fn handshake_then_hello_next_frame(msg_type: u8) -> Vec<u8> {
    let first = handshake_type_record(msg_type, 0x0303);
    let grease = client_hello_host(Some(b"www.example.com"), 0x0a0a);
    pcap(
        LINK_ETHERNET,
        &[
            eth_ipv4_tcp_seq(OUTER, 50000, 443, 1, &first),
            eth_ipv4_tcp_seq(OUTER, 50000, 443, 1 + first.len() as u32, &grease),
        ],
    )
}

fn client_hello_then_grease() -> Vec<u8> {
    let mut payload = client_hello(None);
    payload.extend_from_slice(&client_hello_host(Some(b"www.example.com"), 0x0a0a));
    pcap(LINK_ETHERNET, &[eth_ipv4_tcp(OUTER, 50000, 443, &payload)])
}

fn client_hello_then_grease_next_frame() -> Vec<u8> {
    let first = client_hello(None);
    let grease = client_hello_host(Some(b"www.example.com"), 0x0a0a);
    pcap(
        LINK_ETHERNET,
        &[
            eth_ipv4_tcp_seq(OUTER, 50000, 443, 1, &first),
            eth_ipv4_tcp_seq(OUTER, 50000, 443, 1 + first.len() as u32, &grease),
        ],
    )
}

fn ccs_then_hello(version: u16) -> Vec<u8> {
    let mut payload = ccs();
    payload.extend_from_slice(&client_hello_host(Some(b"www.example.com"), version));
    pcap(LINK_ETHERNET, &[eth_ipv4_tcp(OUTER, 50000, 443, &payload)])
}

fn chunked_sni() -> Vec<u8> {
    let hello = client_hello(Some("chunk.example"));
    let frame = eth_ipv4_tcp(OUTER, 50000, 443, &hello);
    let mut frames = Vec::new();
    for i in 0..8000u16 {
        let mut packet = frame.clone();
        packet[26] = (i >> 8) as u8;
        packet[27] = i as u8;
        frames.push(packet);
    }
    pcap(LINK_ETHERNET, &frames)
}

fn on_disk_named() -> (&'static str, Vec<u8>) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../study/corpus");
    for (name, path) in [
        ("bigFlows", root.join("real/bigFlows.pcap")),
        (
            "challenge01",
            root.join("real/challenge01_ooo_stream.pcapng"),
        ),
    ] {
        if let Ok(bytes) = fs::read(&path) {
            return (name, bytes);
        }
        eprintln!("skip: {name} missing");
    }
    ("missing-corpus", Vec::new())
}

fn fuzz_cases() -> Vec<Vec<u8>> {
    let base = client_hello(Some("fuzz.example"));
    let frame = eth_ipv4_tcp(OUTER, 50000, 443, &base);
    let payload_at = frame.len() - base.len();
    let mut files = vec![pcap(LINK_ETHERNET, &[frame.clone()])];
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..64 {
        let mut packet = frame.clone();
        let n = 1 + rng.bounded(4) as usize;
        for _ in 0..n {
            let span = (packet.len() - payload_at) as u16;
            if span == 0 {
                break;
            }
            let index = payload_at + rng.bounded(span) as usize;
            packet[index] ^= 1 + rng.bounded(255) as u8;
        }
        files.push(pcap(LINK_ETHERNET, &[packet]));
    }
    files
}

fn check_one(tshark: &Path, fin: &Path, dir: &Path, name: &str, file: &[u8]) -> Option<String> {
    static SEQ: OnceLock<std::sync::atomic::AtomicU64> = OnceLock::new();
    let seq = SEQ
        .get_or_init(|| std::sync::atomic::AtomicU64::new(0))
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = dir.join(format!("tls-sni-{seq}.pcap"));
    fs::write(&path, file).unwrap();
    let mut args = vec![OsString::from("-r"), path.as_os_str().to_os_string()];
    args.extend(
        ["-n", "-T", "fields", "-e", FIELD]
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
        let dir = env::temp_dir().join(format!("fin-tls-sni-{}", std::process::id()));
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
}
