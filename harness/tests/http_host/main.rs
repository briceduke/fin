//! Oracle: `fin -T fields -e http.host` against tshark 4.6.9.

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

const FIELD: &str = "http.host";

#[test]
fn http_host_matches_tshark_469() {
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
    let path = work_dir().join("http-stdin-vs-file.pcap");
    fs::write(
        &path,
        pcap(
            LINK_ETHERNET,
            &[eth_ipv4_tcp(OUTER, 50000, 80, &get("stdin.example"))],
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
fn combined_ip_src_and_http_host_matches_tshark_469() {
    let Some((tshark, fin)) = tools() else {
        return;
    };
    let dir = work_dir();
    for (name, payload) in [
        ("combined", get("www.example.com")),
        (
            "combined-tab",
            b"GET / HTTP/1.1\r\nHost: ab\tcd\r\n\r\n".to_vec(),
        ),
        (
            "combined-bs",
            b"GET / HTTP/1.1\r\nHost: ab\\cd\r\n\r\n".to_vec(),
        ),
    ] {
        let file = pcap(LINK_ETHERNET, &[eth_ipv4_tcp(OUTER, 50000, 80, &payload)]);
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
fn combined_tls_and_http_host_matches_tshark_469() {
    let Some((tshark, fin)) = tools() else {
        return;
    };
    let dir = work_dir();
    let file = pcap(
        LINK_ETHERNET,
        &[
            eth_ipv4_tcp(OUTER, 50000, 443, &client_hello("sni.example")),
            eth_ipv4_tcp(OUTER, 50000, 80, &get("www.example.com")),
        ],
    );
    let path = dir.join("combined-tls-http.pcap");
    fs::write(&path, file).unwrap();
    let mut args = vec![OsString::from("-r"), path.as_os_str().to_os_string()];
    args.extend(
        [
            "-n",
            "-T",
            "fields",
            "-e",
            "tls.handshake.extensions_server_name",
            "-e",
            FIELD,
        ]
        .into_iter()
        .map(OsString::from),
    );
    let output = run_pair(&tshark, &fin, &args).expect("pair");
    let report = check_pair(&output).expect("check");
    assert!(
        report.faults.is_empty(),
        "{report} tshark={:?} fin={:?} stderr={}",
        output.tshark_stdout,
        output.fin_stdout,
        output.fin_stderr
    );
}

#[test]
fn combined_three_fields_matches_tshark_469() {
    let Some((tshark, fin)) = tools() else {
        return;
    };
    let dir = work_dir();
    let file = pcap(
        LINK_ETHERNET,
        &[
            eth_ipv4_tcp(OUTER, 50000, 443, &client_hello("sni.example")),
            eth_ipv4_tcp(OUTER, 50000, 80, &get("www.example.com")),
        ],
    );
    let path = dir.join("combined-three.pcap");
    fs::write(&path, file).unwrap();
    let mut args = vec![OsString::from("-r"), path.as_os_str().to_os_string()];
    args.extend(
        [
            "-n",
            "-T",
            "fields",
            "-e",
            "ip.src",
            "-e",
            "tls.handshake.extensions_server_name",
            "-e",
            FIELD,
        ]
        .into_iter()
        .map(OsString::from),
    );
    let output = run_pair(&tshark, &fin, &args).expect("pair");
    let report = check_pair(&output).expect("check");
    assert!(
        report.faults.is_empty(),
        "{report} tshark={:?} fin={:?} stderr={}",
        output.tshark_stdout,
        output.fin_stdout,
        output.fin_stderr
    );
}

#[test]
fn unknown_field_is_still_an_error() {
    let fin = fin_bin();
    let output = Command::new(&fin)
        .args(["-r", "x", "-T", "fields", "-e", "http.request.method"])
        .output()
        .expect("fin");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unsupported field"), "{stderr}");
}

#[test]
fn heuristic_http_counts_http_heuristic() {
    let fin = fin_bin();
    let path = work_dir().join("http-heuristic-reason.pcap");
    fs::write(
        &path,
        pcap(
            LINK_ETHERNET,
            &[eth_ipv4_tcp(OUTER, 50000, 12345, &get("heur.example"))],
        ),
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
        !stdout.contains("heur.example"),
        "stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stderr.contains("counted 1 http-heuristic"),
        "stderr={stderr:?}"
    );
    assert!(!output.status.success(), "exit={:?}", output.status.code());
}

#[test]
fn fuzz_mutated_http_matches_tshark_469() {
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

fn req_resp_get(req: &[u8], resp: &[u8], later: &[u8]) -> [Vec<u8>; 3] {
    [
        eth_ipv4_tcp_to(OUTER, PEER, 50000, 80, 1, req),
        eth_ipv4_tcp_to(PEER, OUTER, 80, 50000, 1, resp),
        eth_ipv4_tcp_to(OUTER, PEER, 50000, 80, 1 + req.len() as u32, later),
    ]
}

fn cases() -> Vec<(&'static str, Vec<u8>)> {
    let req = get("www.example.com");
    let vlan_frame = vlan(0x0800, &ipv4(OUTER, 6, &tcp(50000, 80, &req)));
    let ipv6_frame = eth(0x86dd, &ipv6(6, &tcp(50000, 80, &req)));
    let sll_frame = sll(0x0800, &ipv4(OUTER, 6, &tcp(50000, 80, &req)));
    let retransmit = vec![
        eth_ipv4_tcp(OUTER, 50000, 80, &req),
        eth(0x0800, &ipv4(OUTER, 6, &tcp_seq(50000, 80, 1, &req))),
    ];
    let split = {
        let full = get("split.example.com");
        let cut = full.len() / 2;
        vec![
            eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, &full[..cut]),
            eth_ipv4_tcp_seq(OUTER, 50000, 80, 1 + cut as u32, &full[cut..]),
        ]
    };
    vec![
        (
            "host-80",
            pcap(LINK_ETHERNET, &[eth_ipv4_tcp(OUTER, 50000, 80, &req)]),
        ),
        (
            "host-8080",
            pcap(LINK_ETHERNET, &[eth_ipv4_tcp(OUTER, 50000, 8080, &req)]),
        ),
        (
            "host-3128",
            pcap(LINK_ETHERNET, &[eth_ipv4_tcp(OUTER, 50000, 3128, &req)]),
        ),
        (
            "host-3689",
            pcap(LINK_ETHERNET, &[eth_ipv4_tcp(OUTER, 50000, 3689, &req)]),
        ),
        (
            "host-1900",
            pcap(LINK_ETHERNET, &[eth_ipv4_tcp(OUTER, 50000, 1900, &req)]),
        ),
        ("host-ipv6", pcap(LINK_ETHERNET, &[ipv6_frame])),
        ("host-vlan", pcap(LINK_ETHERNET, &[vlan_frame])),
        ("host-sll", pcap(LINK_SLL, &[sll_frame])),
        (
            "host-443-heuristic",
            pcap(LINK_ETHERNET, &[eth_ipv4_tcp(OUTER, 50000, 443, &req)]),
        ),
        (
            "host-12345-heuristic",
            pcap(LINK_ETHERNET, &[eth_ipv4_tcp(OUTER, 50000, 12345, &req)]),
        ),
        (
            "host-case",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"GET / HTTP/1.1\r\nHOST: Mixed.Example\r\n\r\n",
                )],
            ),
        ),
        (
            "host-ows",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"GET / HTTP/1.1\r\nHost:\t  example.com \r\n\r\n",
                )],
            ),
        ),
        (
            "host-multi",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n",
                )],
            ),
        ),
        (
            "host-comma",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"GET / HTTP/1.1\r\nHost: a,b.example\r\n\r\n",
                )],
            ),
        ),
        (
            "host-tab",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"GET / HTTP/1.1\r\nHost: ab\tcd.example\r\n\r\n",
                )],
            ),
        ),
        (
            "host-backslash",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"GET / HTTP/1.1\r\nHost: ab\\cd.example\r\n\r\n",
                )],
            ),
        ),
        (
            "host-high-byte",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"GET / HTTP/1.1\r\nHost: x\xffy\r\n\r\n",
                )],
            ),
        ),
        (
            "host-nul",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"GET / HTTP/1.1\r\nHost: ab\x00cd.example\r\n\r\n",
                )],
            ),
        ),
        (
            "no-host",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"GET / HTTP/1.1\r\nUser-Agent: x\r\n\r\n",
                )],
            ),
        ),
        (
            "post-complete",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"POST / HTTP/1.1\r\nHost: post.example\r\nContent-Length: 4\r\n\r\nbody",
                )],
            ),
        ),
        (
            "post-short-body",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"POST / HTTP/1.1\r\nHost: post.example\r\nContent-Length: 100\r\n\r\nno",
                )],
            ),
        ),
        (
            "resp-204",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    PEER,
                    80,
                    50000,
                    b"HTTP/1.1 204 No Content\r\nHost: x\r\n\r\n",
                )],
            ),
        ),
        (
            "resp-200-fin",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_fin(
                    PEER,
                    80,
                    50000,
                    b"HTTP/1.1 200 OK\r\nHost: x\r\n\r\nhello",
                )],
            ),
        ),
        (
            "resp-200-no-fin",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    PEER,
                    80,
                    50000,
                    b"HTTP/1.1 200 OK\r\nHost: x\r\n\r\nhello",
                )],
            ),
        ),
        (
            "pipeline",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"GET /a HTTP/1.1\r\nHost: a.example\r\n\r\nGET /b HTTP/1.1\r\nHost: b.example\r\n\r\n",
                )],
            ),
        ),
        (
            "get-plus-junk",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\njunk",
                )],
            ),
        ),
        (
            "chunked",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"POST / HTTP/1.1\r\nHost: chunk.example\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
                )],
            ),
        ),
        (
            "http2-pri",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(OUTER, 50000, 80, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")],
            ),
        ),
        (
            "connect",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
                )],
            ),
        ),
        (
            "leading-crlf",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"\r\nGET / HTTP/1.1\r\nHost: lead.example\r\n\r\n",
                )],
            ),
        ),
        (
            "lf-only",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"GET / HTTP/1.1\nHost: lf.example\n\n",
                )],
            ),
        ),
        (
            "m-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"M-GET / HTTP/1.1\r\nHost: ext.example\r\n\r\n",
                )],
            ),
        ),
        (
            "lowercase-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"get / HTTP/1.1\r\nHost: lower-get.example\r\n\r\n",
                )],
            ),
        ),
        (
            "incomplete-headers",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(OUTER, 50000, 80, b"GET / HTTP/1.1\r\nHost: cut.example")],
            ),
        ),
        ("retransmit", pcap(LINK_ETHERNET, &retransmit)),
        ("split-headers", pcap(LINK_ETHERNET, &split)),
        (
            "split-headers-heuristic",
            pcap(
                LINK_ETHERNET,
                &{
                    let full = get("split-heur.example");
                    let cut = full.len() / 2;
                    vec![
                        eth_ipv4_tcp_seq(OUTER, 50000, 12345, 1, &full[..cut]),
                        eth_ipv4_tcp_seq(OUTER, 50000, 12345, 1 + cut as u32, &full[cut..]),
                    ]
                },
            ),
        ),
        (
            "host-fold",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"GET / HTTP/1.1\r\nHost: ab\r\n cd\r\n\r\n",
                )],
            ),
        ),
        (
            "icy",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_fin(
                    PEER,
                    80,
                    50000,
                    b"ICY 200 OK\r\nHost: icy.example\r\n\r\n",
                )],
            ),
        ),
        (
            "ssdp-udp",
            pcap(
                LINK_ETHERNET,
                &[eth(
                    0x0800,
                    &ipv4(
                        OUTER,
                        17,
                        &{
                            let payload = b"NOTIFY * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\n\r\n";
                            let mut udp = Vec::from(1900u16.to_be_bytes());
                            udp.extend_from_slice(&1900u16.to_be_bytes());
                            udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
                            udp.extend_from_slice(&[0, 0]);
                            udp.extend_from_slice(payload);
                            udp
                        },
                    ),
                )],
            ),
        ),
        (
            "host-pcapng",
            pcapng(1, &[eth_ipv4_tcp(OUTER, 50000, 80, &req)]),
        ),
        (
            "mixed",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp(OUTER, 50000, 80, &req),
                    eth_ipv4_tcp(OUTER, 50000, 443, &client_hello("sni.example")),
                    eth_ipv4_tcp(OUTER, 50000, 80, b"GET / HTTP/1.1\r\n"),
                    eth_ipv4_tcp(OUTER, 50000, 80, b"GET / HTTP/1.1\r\nUser-Agent: x\r\n\r\n"),
                ],
            ),
        ),
        (
            "sstp-then-get",
            pcap(
                LINK_ETHERNET,
                &req_resp_get(
                    b"SSTP_DUPLEX_POST / HTTP/1.1\r\nHost: sstp.example\r\n\r\n",
                    b"HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n",
                    b"GET / HTTP/1.1\r\nHost: inner.example\r\n\r\n",
                ),
            ),
        ),
        (
            "upgrade-websocket-then-get",
            pcap(
                LINK_ETHERNET,
                &req_resp_get(
                    b"GET /chat HTTP/1.1\r\nHost: ws.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nHost: sw.example\r\n\r\n",
                    b"GET / HTTP/1.1\r\nHost: after-upgrade.example\r\n\r\n",
                ),
            ),
        ),
        (
            "upgrade-h2c-then-get",
            pcap(
                LINK_ETHERNET,
                &req_resp_get(
                    b"GET /chat HTTP/1.1\r\nHost: ws.example\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n",
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nConnection: Upgrade\r\nHost: sw.example\r\n\r\n",
                    b"GET / HTTP/1.1\r\nHost: after-upgrade.example\r\n\r\n",
                ),
            ),
        ),
        (
            "101-no-upgrade-then-get",
            pcap(
                LINK_ETHERNET,
                &req_resp_get(
                    b"GET /chat HTTP/1.1\r\nHost: ws.example\r\n\r\n",
                    b"HTTP/1.1 101 Switching Protocols\r\nHost: sw.example\r\n\r\n",
                    b"GET / HTTP/1.1\r\nHost: after-upgrade.example\r\n\r\n",
                ),
            ),
        ),
        (
            "connect-200-then-get",
            pcap(
                LINK_ETHERNET,
                &req_resp_get(
                    b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
                    b"HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n",
                    b"GET / HTTP/1.1\r\nHost: after-connect.example\r\n\r\n",
                ),
            ),
        ),
        (
            "content-length-lead-vt",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"POST / HTTP/1.1\r\nHost: cllead.example\r\nContent-Length: \x0b4\r\n\r\n",
                )],
            ),
        ),
        (
            "content-length-lead-ff",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"POST / HTTP/1.1\r\nHost: cllead.example\r\nContent-Length: \x0c4\r\n\r\n",
                )],
            ),
        ),
        (
            "content-length-trail-nul",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"POST / HTTP/1.1\r\nHost: cllead.example\r\nContent-Length: 4\x00\r\n\r\n",
                )],
            ),
        ),
        (
            "content-length-trail-ff",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"POST / HTTP/1.1\r\nHost: cllead.example\r\nContent-Length: 4\x0c\r\n\r\n",
                )],
            ),
        ),
        (
            "content-length-four-byte-body",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"POST / HTTP/1.1\r\nHost: cllead.example\r\nContent-Length: 4\r\n\r\nbody",
                )],
            ),
        ),
        (
            "content-length-lead-vt-body",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"POST / HTTP/1.1\r\nHost: cllead.example\r\nContent-Length: \x0b4\r\n\r\nbody",
                )],
            ),
        ),
        (
            "content-length-lead-ff-body",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"POST / HTTP/1.1\r\nHost: cllead.example\r\nContent-Length: \x0c4\r\n\r\nbody",
                )],
            ),
        ),
        (
            "content-length-trail-nul-body",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"POST / HTTP/1.1\r\nHost: cllead.example\r\nContent-Length: 4\x00\r\n\r\nbody",
                )],
            ),
        ),
        (
            "content-length-trail-ff-body",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"POST / HTTP/1.1\r\nHost: cllead.example\r\nContent-Length: 4\x0c\r\n\r\nbody",
                )],
            ),
        ),
        (
            "upgrade-websocket-same-segment-leftover",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp_to(
                        OUTER,
                        PEER,
                        50000,
                        80,
                        1,
                        b"GET /chat HTTP/1.1\r\nHost: ws.example\r\nUpgrade: websocket\r\n\r\n",
                    ),
                    eth_ipv4_tcp_to(
                        PEER,
                        OUTER,
                        80,
                        50000,
                        1,
                        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nHost: sw.example\r\n\r\nGET / HTTP/1.1\r\nHost: after.example\r\n\r\n",
                    ),
                ],
            ),
        ),
        (
            "upgrade-foo-same-segment-leftover",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp_to(
                        OUTER,
                        PEER,
                        50000,
                        80,
                        1,
                        b"GET /chat HTTP/1.1\r\nHost: ws.example\r\nUpgrade: foo\r\n\r\n",
                    ),
                    eth_ipv4_tcp_to(
                        PEER,
                        OUTER,
                        80,
                        50000,
                        1,
                        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: foo\r\nHost: sw.example\r\n\r\nGET / HTTP/1.1\r\nHost: after.example\r\n\r\n",
                    ),
                ],
            ),
        ),
        (
            "upgrade-no-host-same-segment-leftover",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp_to(
                        OUTER,
                        PEER,
                        50000,
                        80,
                        1,
                        b"GET /chat HTTP/1.1\r\nHost: ws.example\r\nUpgrade: websocket\r\n\r\n",
                    ),
                    eth_ipv4_tcp_to(
                        PEER,
                        OUTER,
                        80,
                        50000,
                        1,
                        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\nGET / HTTP/1.1\r\nHost: after.example\r\n\r\n",
                    ),
                ],
            ),
        ),
        (
            "sstp-same-segment-leftover",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp_to(
                        OUTER,
                        PEER,
                        50000,
                        80,
                        1,
                        b"SSTP_DUPLEX_POST / HTTP/1.1\r\nHost: sstp.example\r\n\r\n",
                    ),
                    eth_ipv4_tcp_to(
                        PEER,
                        OUTER,
                        80,
                        50000,
                        1,
                        b"HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\nGET / HTTP/1.1\r\nHost: after.example\r\n\r\n",
                    ),
                ],
            ),
        ),
        (
            "sstp-same-segment-leftover-cl4",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp_to(
                        OUTER,
                        PEER,
                        50000,
                        80,
                        1,
                        b"SSTP_DUPLEX_POST / HTTP/1.1\r\nHost: sstp.example\r\n\r\n",
                    ),
                    eth_ipv4_tcp_to(
                        PEER,
                        OUTER,
                        80,
                        50000,
                        1,
                        b"HTTP/1.1 200 Connection Established\r\nContent-Length: 4\r\nHost: resp.example\r\n\r\nxxxxGET / HTTP/1.1\r\nHost: after.example\r\n\r\n",
                    ),
                ],
            ),
        ),
        (
            "extra-crlf-pipeline",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"GET /a HTTP/1.1\r\nHost: a.example\r\n\r\n\r\nGET /b HTTP/1.1\r\nHost: b.example\r\n\r\n",
                )],
            ),
        ),
        (
            "extra-crlf-post-then-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 0\r\n\r\n\r\nGET /b HTTP/1.1\r\nHost: b.example\r\n\r\n",
                )],
            ),
        ),
        (
            "two-extra-crlf-pipeline",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"GET /a HTTP/1.1\r\nHost: a.example\r\n\r\n\r\n\r\nGET /b HTTP/1.1\r\nHost: b.example\r\n\r\n",
                )],
            ),
        ),
        (
            "status-1010",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    PEER,
                    80,
                    50000,
                    b"HTTP/1.1 1010 X\r\nHost: st.example\r\n\r\nhello",
                )],
            ),
        ),
        (
            "status-2040",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    PEER,
                    80,
                    50000,
                    b"HTTP/1.1 2040 X\r\nHost: st.example\r\n\r\nhello",
                )],
            ),
        ),
        (
            "status-3040",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    PEER,
                    80,
                    50000,
                    b"HTTP/1.1 3040 X\r\nHost: st.example\r\n\r\nhello",
                )],
            ),
        ),
        (
            "status-1000",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    PEER,
                    80,
                    50000,
                    b"HTTP/1.1 1000 X\r\nHost: st.example\r\n\r\nhello",
                )],
            ),
        ),
        (
            "status-101x",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    PEER,
                    80,
                    50000,
                    b"HTTP/1.1 101X X\r\nHost: st.example\r\n\r\nhello",
                )],
            ),
        ),
        (
            "status-204x",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    PEER,
                    80,
                    50000,
                    b"HTTP/1.1 204X X\r\nHost: st.example\r\n\r\nhello",
                )],
            ),
        ),
        (
            "icy-1010",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    PEER,
                    80,
                    50000,
                    b"ICY 1010 X\r\nHost: st.example\r\n\r\nhello",
                )],
            ),
        ),
        (
            "status-1010-fin",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_fin(
                    PEER,
                    80,
                    50000,
                    b"HTTP/1.1 1010 X\r\nHost: st.example\r\n\r\nhello",
                )],
            ),
        ),
        (
            "status-101",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    PEER,
                    80,
                    50000,
                    b"HTTP/1.1 101 Switching Protocols\r\nHost: st.example\r\n\r\n",
                )],
            ),
        ),
        (
            "trailing-cr-blank",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"GET / HTTP/1.1\r\nHost: cr.example\r\n\r",
                )],
            ),
        ),
        (
            "trailing-cr-only-lines",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"GET / HTTP/1.1\rHost: cr.example\r\r",
                )],
            ),
        ),
    ]
    .into_iter()
    .chain(on_disk())
    .filter(|(_, bytes)| !bytes.is_empty())
    .collect()
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

fn fuzz_cases() -> Vec<Vec<u8>> {
    let base = get("fuzz.example");
    let frame = eth_ipv4_tcp(OUTER, 50000, 80, &base);
    let payload_at = frame.len() - base.len();
    let mut files = vec![pcap(LINK_ETHERNET, std::slice::from_ref(&frame))];
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
    let path = dir.join(format!("http-host-{seq}.pcap"));
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
        let dir = env::temp_dir().join(format!("fin-http-host-{}", std::process::id()));
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
