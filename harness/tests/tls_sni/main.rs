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
fn uncertain_last_hello_ext_counts_tls_hello_ext_uncertain() {
    let fin = fin_bin();
    let other = client_hello(Some("other.example"));
    let first = client_hello_exts(
        Some("www.example.com"),
        &[(47, &[0x00, 0x06, 0x00, 0x04, 0x30, 0x02, 0x31, 0x05])],
    );
    let same = two_client_hellos_record(&first, &other);
    let path = work_dir().join("hello-ext-uncertain-reason.pcap");
    fs::write(
        &path,
        pcap(LINK_ETHERNET, &[eth_ipv4_tcp(OUTER, 50000, 443, &same)]),
    )
    .unwrap();
    let output = Command::new(&fin)
        .arg("-r")
        .arg(&path)
        .args(["-n", "-T", "fields", "-e", FIELD])
        .output()
        .expect("fin");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("www.example.com"),
        "stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        !stdout.contains("other.example"),
        "stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stderr.contains("counted 1 tls-hello-ext-uncertain"),
        "stderr={stderr:?}"
    );
    assert!(!output.status.success(), "exit={:?}", output.status.code());
}

#[test]
fn truncated_grease_after_ccs_counts_the_completing_segment() {
    let fin = fin_bin();
    let path = work_dir().join("ccs-then-split-grease-40.pcap");
    fs::write(&path, split_grease_after(&ccs(), 40, 0x0a0a)).unwrap();
    let output = Command::new(&fin)
        .arg("-r")
        .arg(&path)
        .args(["-n", "-T", "fields", "-e", FIELD])
        .output()
        .expect("fin");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let rows: Vec<&str> = stdout.lines().collect();
    assert_eq!(rows, ["", "", ""], "stdout={stdout:?} stderr={stderr:?}");
    assert!(
        stderr.contains("counted 2 tls-handshake"),
        "stderr={stderr:?}"
    );
    assert!(
        stderr.contains("counted 3 tls-handshake"),
        "stderr={stderr:?}"
    );
    assert!(stderr.contains("total 2"), "stderr={stderr:?}");
    assert!(!output.status.success(), "exit={:?}", output.status.code());
}

#[test]
fn incomplete_grease_handshake_after_ccs_does_not_print_later_hello() {
    let fin = fin_bin();
    let cases: Vec<(&str, Vec<u8>, usize, &[&str])> = vec![
        (
            "ccs-then-overrun-grease-then-hello",
            incomplete_grease_then_later_hello(&ccs(), 0x0a0a),
            3,
            &["counted 2 tls-handshake", "counted 3 tls-handshake"],
        ),
        (
            "alert-then-overrun-grease-then-hello",
            incomplete_grease_then_later_hello(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28], 0x0a0a),
            3,
            &["counted 2 tls-handshake", "counted 3 tls-handshake"],
        ),
        (
            "app-data-then-overrun-grease-then-hello",
            incomplete_grease_then_later_hello(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x01], 0x0a0a),
            3,
            &["counted 2 tls-handshake", "counted 3 tls-handshake"],
        ),
        (
            "heartbeat-then-overrun-grease-then-hello",
            incomplete_grease_then_later_hello(
                &[0x18, 0x03, 0x03, 0x00, 0x03, 0x01, 0x00, 0x00],
                0x0a0a,
            ),
            3,
            &["counted 2 tls-handshake", "counted 3 tls-handshake"],
        ),
        (
            "hello-request-then-overrun-grease-then-hello",
            incomplete_grease_then_later_hello(
                &[0x16, 0x03, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00],
                0x0a0a,
            ),
            3,
            &["counted 2 tls-handshake", "counted 3 tls-handshake"],
        ),
        (
            "ccs-then-overrun-draft-0002-then-hello",
            incomplete_grease_then_later_hello(&ccs(), 0x0002),
            3,
            &["counted 2 tls-handshake", "counted 3 tls-handshake"],
        ),
        (
            "ccs-then-overrun-draft-0305-then-hello",
            incomplete_grease_then_later_hello(&ccs(), 0x0305),
            3,
            &["counted 2 tls-handshake", "counted 3 tls-handshake"],
        ),
        (
            "ccs-then-overrun-draft-7f1c-then-hello",
            incomplete_grease_then_later_hello(&ccs(), 0x7f1c),
            3,
            &["counted 2 tls-handshake", "counted 3 tls-handshake"],
        ),
        (
            "same-payload-ccs-overrun-grease-then-hello",
            same_payload_ccs_incomplete_grease_then_later_hello(),
            2,
            &["counted 1 tls-handshake", "counted 2 tls-handshake"],
        ),
        (
            "ccs-then-1-byte-grease-then-hello",
            short_grease_then_later_hello(&ccs(), &[0x01]),
            3,
            &["counted 2 tls-handshake", "counted 3 tls-handshake"],
        ),
        (
            "ccs-then-3-byte-grease-then-hello",
            short_grease_then_later_hello(&ccs(), &[0x01, 0x00, 0x00]),
            3,
            &["counted 2 tls-handshake", "counted 3 tls-handshake"],
        ),
    ];
    for (name, file, frames, counted) in cases {
        let path = work_dir().join(format!("{name}.pcap"));
        fs::write(&path, file).unwrap();
        let output = Command::new(&fin)
            .arg("-r")
            .arg(&path)
            .args(["-n", "-T", "fields", "-e", FIELD])
            .output()
            .expect("fin");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let rows: Vec<&str> = stdout.lines().collect();
        assert_eq!(
            rows,
            vec![""; frames],
            "{name} stdout={stdout:?} stderr={stderr:?}"
        );
        assert!(
            !stdout.contains("www.example.com"),
            "{name} stdout={stdout:?} stderr={stderr:?}"
        );
        assert!(
            !stdout.contains("other.example"),
            "{name} stdout={stdout:?} stderr={stderr:?}"
        );
        for line in counted {
            assert!(
                stderr.contains(line),
                "{name} missing {line} stderr={stderr:?}"
            );
        }
        assert!(
            !output.status.success(),
            "{name} exit={:?}",
            output.status.code()
        );
    }
}

#[test]
fn complete_grease_then_truncated_hello_counts_the_completing_segment() {
    let fin = fin_bin();
    let path = work_dir().join("ccs-then-complete-grease-split-hello-40.pcap");
    fs::write(&path, complete_grease_then_split_hello(&ccs(), 40, 0x0a0a)).unwrap();
    let output = Command::new(&fin)
        .arg("-r")
        .arg(&path)
        .args(["-n", "-T", "fields", "-e", FIELD])
        .output()
        .expect("fin");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let rows: Vec<&str> = stdout.lines().collect();
    assert_eq!(rows, ["", "", ""], "stdout={stdout:?} stderr={stderr:?}");
    assert!(
        !stdout.contains("www.example.com"),
        "stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        !stdout.contains("other.example"),
        "stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stderr.contains("counted 2 tls-handshake"),
        "stderr={stderr:?}"
    );
    assert!(
        stderr.contains("counted 3 tls-handshake"),
        "stderr={stderr:?}"
    );
    assert!(!output.status.success(), "exit={:?}", output.status.code());
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
        ("split-hello", split_hello_at(40)),
        on_disk_named(),
    ]
    .into_iter()
    .chain(record_version_cases())
    .chain(review_cases())
    .chain(hello_ext_throw_cases())
    .chain(complete_grease_leftover_cases())
    .chain(incomplete_grease_handshake_cases())
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

fn hello_ext_throw_cases() -> Vec<(&'static str, Vec<u8>)> {
    let other = client_hello(Some("other.example"));
    let hello = client_hello(Some("www.example.com"));
    let then_other = |tag: &'static str, typ: u16, data: &[u8], sport: u16, dport: u16| {
        let first = client_hello_exts(Some("www.example.com"), &[(typ, data)]);
        let same = two_client_hellos_record(&first, &other);
        (
            tag,
            pcap(LINK_ETHERNET, &[eth_ipv4_tcp(OUTER, sport, dport, &same)]),
        )
    };
    let maxfrag = client_hello_exts(Some("www.example.com"), &[(1, &[])]);
    let empty_maxfrag = client_hello_exts(None, &[(1, &[])]);
    let mut leftover = maxfrag.clone();
    leftover.push(0x00);
    vec![
        then_other("hello-ext-maxfrag-0-then-other-443", 1, &[], 50000, 443),
        then_other(
            "hello-ext-maxfrag-0-then-other-unnamed",
            1,
            &[],
            40001,
            40002,
        ),
        then_other(
            "hello-ext-compress-cert-even-then-other-443",
            27,
            &[0x02, 0x00, 0x01],
            50000,
            443,
        ),
        then_other(
            "hello-ext-compress-cert-odd-2-then-other-443",
            27,
            &[0x01, 0x00],
            50000,
            443,
        ),
        then_other(
            "hello-ext-alpn-0000-then-other-443",
            16,
            &[0x00, 0x00],
            50000,
            443,
        ),
        then_other(
            "hello-ext-psk-0000-then-other-443",
            41,
            &[0x00, 0x00],
            50000,
            443,
        ),
        then_other("hello-ext-quic-tp-v1-0-then-other-443", 57, &[], 50000, 443),
        then_other("hello-ext-esni-0-then-other-443", 65486, &[], 50000, 443),
        then_other(
            "hello-ext-cert-auth-0006000430023105-then-other-443",
            47,
            &[0x00, 0x06, 0x00, 0x04, 0x30, 0x02, 0x31, 0x05],
            50000,
            443,
        ),
        (
            "hello-ext-maxfrag-0-only-then-www-443",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    443,
                    &two_client_hellos_record(&empty_maxfrag, &hello),
                )],
            ),
        ),
        (
            "hello-ext-maxfrag-0-leftover-00-then-0301",
            sequential_payloads(50000, 443, &[&leftover, &hello]),
        ),
        (
            "hello-ext-maxfrag-0-next-payload-other",
            sequential_payloads(50000, 443, &[&maxfrag, &other]),
        ),
    ]
}

fn two_client_hellos_record(first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut body = first[5..].to_vec();
    body.extend_from_slice(&second[5..]);
    let mut rec = handshake_record(&body);
    rec[1..3].copy_from_slice(&0x0301u16.to_be_bytes());
    rec
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

fn split_hello_after_prefix(prefix: &[u8], cut: usize) -> Vec<u8> {
    let hello = client_hello(Some("www.example.com"));
    let mut first = prefix.to_vec();
    first.extend_from_slice(&hello[..cut]);
    sequential_payloads(50000, 443, &[&first, &hello[cut..]])
}

fn complete_hello_then_split_second() -> Vec<u8> {
    let first = client_hello(Some("www.example.com"));
    let second = client_hello(Some("other.example"));
    let mut payload = first.clone();
    payload.extend_from_slice(&second[..10]);
    sequential_payloads(50000, 443, &[&payload, &second[10..]])
}

fn later_grease_after(prefix: &[u8]) -> Vec<u8> {
    let mut grease = client_hello(Some("www.example.com"));
    grease[1..3].copy_from_slice(&0x0a0au16.to_be_bytes());
    sequential_payloads(50000, 443, &[prefix, &grease])
}

fn later_grease_after_server_hello() -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0x22u8; 32]);
    body.push(0);
    body.extend_from_slice(&[0x00, 0x2f]);
    body.push(0);
    later_grease_after(&handshake_messages_record(0x0303, &[(2, &body)]))
}

fn reverse_ccs_then_grease() -> Vec<u8> {
    let mut grease = client_hello(Some("www.example.com"));
    grease[1..3].copy_from_slice(&0x0a0au16.to_be_bytes());
    pcap(
        LINK_ETHERNET,
        &[
            eth_ipv4_tcp_flow(PEER, OUTER, 443, 50000, 1, &ccs()),
            eth_ipv4_tcp_flow(OUTER, PEER, 50000, 443, 1, &grease),
        ],
    )
}

fn grease_hello(version: u16) -> Vec<u8> {
    let mut hello = client_hello(Some("www.example.com"));
    hello[1..3].copy_from_slice(&version.to_be_bytes());
    hello
}

fn split_grease_after(prefix: &[u8], cut: usize, version: u16) -> Vec<u8> {
    let hello = grease_hello(version);
    sequential_payloads(50000, 443, &[prefix, &hello[..cut], &hello[cut..]])
}

fn reverse_ccs_then_split_grease(cut: usize) -> Vec<u8> {
    let hello = grease_hello(0x0a0a);
    pcap(
        LINK_ETHERNET,
        &[
            eth_ipv4_tcp_flow(PEER, OUTER, 443, 50000, 1, &ccs()),
            eth_ipv4_tcp_flow(OUTER, PEER, 50000, 443, 1, &hello[..cut]),
            eth_ipv4_tcp_flow(OUTER, PEER, 50000, 443, 1 + cut as u32, &hello[cut..]),
        ],
    )
}

fn same_payload_ccs_then_split_grease(cut: usize) -> Vec<u8> {
    let hello = grease_hello(0x0a0a);
    let mut first = ccs();
    first.extend_from_slice(&hello[..cut]);
    sequential_payloads(50000, 443, &[&first, &hello[cut..]])
}

fn complete_grease_then_split_hello(prefix: &[u8], cut: usize, version: u16) -> Vec<u8> {
    let grease = grease_hello(version);
    let hello = client_hello(Some("other.example"));
    let mut second = grease;
    second.extend_from_slice(&hello[..cut]);
    sequential_payloads(50000, 443, &[prefix, &second, &hello[cut..]])
}

fn reverse_ccs_then_complete_grease_split_hello(cut: usize) -> Vec<u8> {
    let grease = grease_hello(0x0a0a);
    let hello = client_hello(Some("other.example"));
    let mut second = grease;
    second.extend_from_slice(&hello[..cut]);
    pcap(
        LINK_ETHERNET,
        &[
            eth_ipv4_tcp_flow(PEER, OUTER, 443, 50000, 1, &ccs()),
            eth_ipv4_tcp_flow(OUTER, PEER, 50000, 443, 1, &second),
            eth_ipv4_tcp_flow(
                OUTER,
                PEER,
                50000,
                443,
                1 + second.len() as u32,
                &hello[cut..],
            ),
        ],
    )
}

fn same_payload_ccs_complete_grease_then_split_hello(cut: usize) -> Vec<u8> {
    let grease = grease_hello(0x0a0a);
    let hello = client_hello(Some("other.example"));
    let mut first = ccs();
    first.extend_from_slice(&grease);
    first.extend_from_slice(&hello[..cut]);
    sequential_payloads(50000, 443, &[&first, &hello[cut..]])
}

fn split_grease_completing_then_split_hello(grease_cut: usize, hello_cut: usize) -> Vec<u8> {
    let grease = grease_hello(0x0a0a);
    let hello = client_hello(Some("other.example"));
    let mut third = grease[grease_cut..].to_vec();
    third.extend_from_slice(&hello[..hello_cut]);
    sequential_payloads(
        50000,
        443,
        &[&ccs(), &grease[..grease_cut], &third, &hello[hello_cut..]],
    )
}

fn later_hello_after_complete_grease() -> Vec<u8> {
    sequential_payloads(
        50000,
        443,
        &[
            &ccs(),
            &grease_hello(0x0a0a),
            &client_hello(Some("other.example")),
        ],
    )
}

fn lone_grease_then_split_hello(cut: usize) -> Vec<u8> {
    let grease = grease_hello(0x0a0a);
    let hello = client_hello(Some("other.example"));
    let mut first = grease;
    first.extend_from_slice(&hello[..cut]);
    sequential_payloads(50000, 443, &[&first, &hello[cut..]])
}

fn empty_ccs_then_complete_grease_split_hello(cut: usize) -> Vec<u8> {
    let empty = [0x14, 0x03, 0x03, 0x00, 0x00];
    let grease = grease_hello(0x0a0a);
    let hello = client_hello(Some("other.example"));
    let mut second = grease;
    second.extend_from_slice(&hello[..cut]);
    sequential_payloads(50000, 443, &[&empty, &second, &hello[cut..]])
}

fn complete_grease_leftover_cases() -> Vec<(&'static str, Vec<u8>)> {
    let alert = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
    let app = [0x17, 0x03, 0x03, 0x00, 0x01, 0x01];
    let hello_request = [0x16, 0x03, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00];
    let mut server_body = vec![0x03, 0x03];
    server_body.extend_from_slice(&[0x22u8; 32]);
    server_body.push(0);
    server_body.extend_from_slice(&[0x00, 0x2f]);
    server_body.push(0);
    let server = handshake_messages_record(0x0303, &[(2, &server_body)]);
    vec![
        (
            "ccs-then-complete-grease-split-hello-40",
            complete_grease_then_split_hello(&ccs(), 40, 0x0a0a),
        ),
        (
            "alert-then-complete-grease-split-hello-40",
            complete_grease_then_split_hello(&alert, 40, 0x0a0a),
        ),
        (
            "app-data-then-complete-grease-split-hello-40",
            complete_grease_then_split_hello(&app, 40, 0x0a0a),
        ),
        (
            "hello-request-then-complete-grease-split-hello-40",
            complete_grease_then_split_hello(&hello_request, 40, 0x0a0a),
        ),
        (
            "server-hello-then-complete-grease-split-hello-40",
            complete_grease_then_split_hello(&server, 40, 0x0a0a),
        ),
        (
            "reverse-ccs-then-complete-grease-split-hello-40",
            reverse_ccs_then_complete_grease_split_hello(40),
        ),
        (
            "ccs-then-complete-grease-ver-0002-split-hello-40",
            complete_grease_then_split_hello(&ccs(), 40, 0x0002),
        ),
        (
            "ccs-then-complete-grease-ver-0305-split-hello-40",
            complete_grease_then_split_hello(&ccs(), 40, 0x0305),
        ),
        (
            "ccs-then-complete-grease-split-hello-3",
            complete_grease_then_split_hello(&ccs(), 3, 0x0a0a),
        ),
        (
            "ccs-then-complete-grease-split-hello-4",
            complete_grease_then_split_hello(&ccs(), 4, 0x0a0a),
        ),
        (
            "ccs-then-complete-grease-split-hello-5",
            complete_grease_then_split_hello(&ccs(), 5, 0x0a0a),
        ),
        (
            "ccs-then-complete-grease-split-hello-10",
            complete_grease_then_split_hello(&ccs(), 10, 0x0a0a),
        ),
        (
            "same-payload-ccs-complete-grease-split-hello-40",
            same_payload_ccs_complete_grease_then_split_hello(40),
        ),
        (
            "split-grease-completing-then-split-hello-40",
            split_grease_completing_then_split_hello(40, 40),
        ),
        (
            "later-hello-after-complete-grease",
            later_hello_after_complete_grease(),
        ),
        (
            "lone-grease-then-split-hello-40",
            lone_grease_then_split_hello(40),
        ),
        (
            "empty-ccs-then-complete-grease-split-hello-40",
            empty_ccs_then_complete_grease_split_hello(40),
        ),
    ]
}

fn incomplete_grease_then_later_hello(prefix: &[u8], version: u16) -> Vec<u8> {
    sequential_payloads(
        50000,
        443,
        &[
            prefix,
            &bump_handshake_u24(grease_hello(version), 40),
            &client_hello(Some("other.example")),
        ],
    )
}

fn same_payload_ccs_incomplete_grease_then_later_hello() -> Vec<u8> {
    let mut first = ccs();
    first.extend_from_slice(&bump_handshake_u24(grease_hello(0x0a0a), 40));
    sequential_payloads(50000, 443, &[&first, &client_hello(Some("other.example"))])
}

fn short_grease_then_later_hello(prefix: &[u8], body: &[u8]) -> Vec<u8> {
    sequential_payloads(
        50000,
        443,
        &[
            prefix,
            &handshake_body_record(0x0a0a, body),
            &client_hello(Some("other.example")),
        ],
    )
}

fn incomplete_grease_handshake_cases() -> Vec<(&'static str, Vec<u8>)> {
    let alert = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
    let app = [0x17, 0x03, 0x03, 0x00, 0x01, 0x01];
    let heartbeat = [0x18, 0x03, 0x03, 0x00, 0x03, 0x01, 0x00, 0x00];
    let hello_request = [0x16, 0x03, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00];
    vec![
        (
            "ccs-then-overrun-grease-then-hello",
            incomplete_grease_then_later_hello(&ccs(), 0x0a0a),
        ),
        (
            "alert-then-overrun-grease-then-hello",
            incomplete_grease_then_later_hello(&alert, 0x0a0a),
        ),
        (
            "app-data-then-overrun-grease-then-hello",
            incomplete_grease_then_later_hello(&app, 0x0a0a),
        ),
        (
            "heartbeat-then-overrun-grease-then-hello",
            incomplete_grease_then_later_hello(&heartbeat, 0x0a0a),
        ),
        (
            "hello-request-then-overrun-grease-then-hello",
            incomplete_grease_then_later_hello(&hello_request, 0x0a0a),
        ),
        (
            "ccs-then-overrun-draft-0002-then-hello",
            incomplete_grease_then_later_hello(&ccs(), 0x0002),
        ),
        (
            "ccs-then-overrun-draft-0305-then-hello",
            incomplete_grease_then_later_hello(&ccs(), 0x0305),
        ),
        (
            "ccs-then-overrun-draft-7f1c-then-hello",
            incomplete_grease_then_later_hello(&ccs(), 0x7f1c),
        ),
        (
            "same-payload-ccs-overrun-grease-then-hello",
            same_payload_ccs_incomplete_grease_then_later_hello(),
        ),
        (
            "ccs-then-1-byte-grease-then-hello",
            short_grease_then_later_hello(&ccs(), &[0x01]),
        ),
        (
            "ccs-then-3-byte-grease-then-hello",
            short_grease_then_later_hello(&ccs(), &[0x01, 0x00, 0x00]),
        ),
        (
            "ccs-then-overrun-0301-then-hello",
            incomplete_grease_then_later_hello(&ccs(), 0x0301),
        ),
    ]
}

fn review_cases() -> Vec<(&'static str, Vec<u8>)> {
    let hello = client_hello(Some("www.example.com"));
    let mut hello_0304 = hello.clone();
    hello_0304[1..3].copy_from_slice(&0x0304u16.to_be_bytes());
    let mut ccs_hello = ccs();
    ccs_hello.extend_from_slice(&hello);
    let mut grease = hello.clone();
    grease[1..3].copy_from_slice(&0x0a0au16.to_be_bytes());
    let mut ccs_grease = ccs();
    ccs_grease.extend_from_slice(&grease);
    vec![
        (
            "unnamed-0304",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(OUTER, 40001, 40002, &hello_0304)],
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
        ("split-hello-1", split_hello_at(1)),
        (
            "ccs-then-hello",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(OUTER, 50000, 443, &ccs_hello)],
            ),
        ),
        (
            "ccs-then-grease",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(OUTER, 50000, 443, &ccs_grease)],
            ),
        ),
        (
            "rst-hello",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_flow_flags(
                    OUTER, PEER, 50000, 443, 1, 0x14, &hello,
                )],
            ),
        ),
        ("leftover-00-then-hello", leftover_then_hello(&[0x00])),
        (
            "throwing-handshake-then-hello",
            throwing_handshake_then_hello(),
        ),
        ("ccs-then-split-hello", split_hello_after_prefix(&ccs(), 40)),
        (
            "empty-ccs-then-split-hello",
            split_hello_after_prefix(&[0x14, 0x03, 0x03, 0x00, 0x00], 40),
        ),
        (
            "alert-then-split-hello",
            split_hello_after_prefix(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28], 40),
        ),
        (
            "app-data-then-split-hello",
            split_hello_after_prefix(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x01], 40),
        ),
        (
            "hello-request-then-split-hello",
            split_hello_after_prefix(&[0x16, 0x03, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00], 40),
        ),
        (
            "complete-hello-then-split-second",
            complete_hello_then_split_second(),
        ),
        ("ccs-then-later-grease", later_grease_after(&ccs())),
        (
            "alert-then-later-grease",
            later_grease_after(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]),
        ),
        (
            "app-data-then-later-grease",
            later_grease_after(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x01]),
        ),
        (
            "hello-request-then-later-grease",
            later_grease_after(&[0x16, 0x03, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00]),
        ),
        (
            "server-hello-then-later-grease",
            later_grease_after_server_hello(),
        ),
        ("reverse-ccs-then-later-grease", reverse_ccs_then_grease()),
        (
            "ccs-then-split-grease-40",
            split_grease_after(&ccs(), 40, 0x0a0a),
        ),
        (
            "ccs-then-split-grease-5",
            split_grease_after(&ccs(), 5, 0x0a0a),
        ),
        (
            "ccs-then-split-grease-50",
            split_grease_after(&ccs(), 50, 0x0a0a),
        ),
        (
            "alert-then-split-grease-40",
            split_grease_after(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28], 40, 0x0a0a),
        ),
        (
            "heartbeat-then-split-grease-40",
            split_grease_after(
                &[0x18, 0x03, 0x03, 0x00, 0x03, 0x01, 0x00, 0x00],
                40,
                0x0a0a,
            ),
        ),
        (
            "server-hello-then-split-grease-40",
            split_grease_after_server_hello(40),
        ),
        (
            "reverse-ccs-then-split-grease-40",
            reverse_ccs_then_split_grease(40),
        ),
        (
            "same-payload-ccs-split-grease-40",
            same_payload_ccs_then_split_grease(40),
        ),
        (
            "ccs-then-split-grease-ver-0002-40",
            split_grease_after(&ccs(), 40, 0x0002),
        ),
    ]
}

fn split_grease_after_server_hello(cut: usize) -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0x22u8; 32]);
    body.push(0);
    body.extend_from_slice(&[0x00, 0x2f]);
    body.push(0);
    split_grease_after(
        &handshake_messages_record(0x0303, &[(2, &body)]),
        cut,
        0x0a0a,
    )
}

fn sequential_payloads(sport: u16, dport: u16, payloads: &[&[u8]]) -> Vec<u8> {
    let mut frames = Vec::new();
    let mut seq = 1u32;
    for payload in payloads {
        frames.push(eth_ipv4_tcp_flow(OUTER, PEER, sport, dport, seq, payload));
        seq += payload.len() as u32;
    }
    pcap(LINK_ETHERNET, &frames)
}

fn leftover_then_hello(leftover: &[u8]) -> Vec<u8> {
    let hello = client_hello(Some("www.example.com"));
    pcap(
        LINK_ETHERNET,
        &[
            eth_ipv4_tcp_seq(OUTER, 50000, 443, 1, leftover),
            eth_ipv4_tcp_seq(OUTER, 50000, 443, 1 + leftover.len() as u32, &hello),
        ],
    )
}

fn throwing_handshake_then_hello() -> Vec<u8> {
    let hello = client_hello(Some("www.example.com"))[9..].to_vec();
    pcap(
        LINK_ETHERNET,
        &[eth_ipv4_tcp(
            OUTER,
            50000,
            443,
            &handshake_messages_record(0x0303, &[(2, &[]), (1, &hello)]),
        )],
    )
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
    let mut files = vec![pcap(LINK_ETHERNET, std::slice::from_ref(&frame))];
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..8 {
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
