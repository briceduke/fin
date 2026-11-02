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

fn req_interim_resp_get(req: &[u8], interim: &[u8], resp: &[u8], later: &[u8]) -> [Vec<u8>; 4] {
    [
        eth_ipv4_tcp_to(OUTER, PEER, 50000, 80, 1, req),
        eth_ipv4_tcp_to(PEER, OUTER, 80, 50000, 1, interim),
        eth_ipv4_tcp_to(PEER, OUTER, 80, 50000, 1 + interim.len() as u32, resp),
        eth_ipv4_tcp_to(OUTER, PEER, 50000, 80, 1 + req.len() as u32, later),
    ]
}

const SSTP_REQ: &[u8] = b"SSTP_DUPLEX_POST / HTTP/1.1\r\nHost: sstp.example\r\n\r\n";
const SSTP_200: &[u8] = b"HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n";
const INNER_GET: &[u8] = b"GET / HTTP/1.1\r\nHost: inner.example\r\n\r\n";
const CONTINUE_100: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";
const HTTP2_MAGIC: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const HTTP2_PREFIX: &[u8] = b"PRI * HTTP/2.0\r\n\r\n";
const HTTP2_FIRST_LINE: &[u8] = b"PRI * HTTP/2.0\r\n";
const GET_A: &[u8] = b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n";
const POST_CL0_A: &[u8] = b"POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 0\r\n\r\n";
const RESP_204_A: &[u8] = b"HTTP/1.1 204 No Content\r\nHost: a.example\r\n\r\n";
const NOTIFY_A: &[u8] = b"NOTIFY / HTTP/1.1\r\nHost: a.example\r\n\r\n";

fn sstp_interim_leftover_get(interim: &[u8]) -> [Vec<u8>; 3] {
    let mut leftover = SSTP_200.to_vec();
    leftover.extend_from_slice(INNER_GET);
    [
        eth_ipv4_tcp_to(OUTER, PEER, 50000, 80, 1, SSTP_REQ),
        eth_ipv4_tcp_to(PEER, OUTER, 80, 50000, 1, interim),
        eth_ipv4_tcp_to(PEER, OUTER, 80, 50000, 1 + interim.len() as u32, &leftover),
    ]
}

fn cl_then(status: &[u8], pad: &[u8]) -> Vec<u8> {
    let mut payload = status.to_vec();
    payload.extend_from_slice(b"\r\nHost: st.example\r\nContent-Length: 4\r\n\r\n");
    payload.extend_from_slice(pad);
    payload.extend_from_slice(b"GET / HTTP/1.1\r\nHost: after.example\r\n\r\n");
    payload
}

fn eth_ipv6_tcp(src: [u8; 16], dst: [u8; 16], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    eth_ipv6_tcp_to(src, dst, sport, dport, 1, payload)
}

fn req_resp_get_ports(
    sport: u16,
    dport: u16,
    req: &[u8],
    resp: &[u8],
    later: &[u8],
) -> [Vec<u8>; 3] {
    [
        eth_ipv4_tcp_to(OUTER, PEER, sport, dport, 1, req),
        eth_ipv4_tcp_to(PEER, OUTER, dport, sport, 1, resp),
        eth_ipv4_tcp_to(OUTER, PEER, sport, dport, 1 + req.len() as u32, later),
    ]
}

fn sstp_then(resp: &[u8]) -> [Vec<u8>; 3] {
    req_resp_get(SSTP_REQ, resp, INNER_GET)
}

fn concat_bytes(first: &[u8], leftover: &[u8]) -> Vec<u8> {
    let mut payload = first.to_vec();
    payload.extend_from_slice(leftover);
    payload
}

fn leading_crlf_magic() -> Vec<u8> {
    concat_bytes(b"\r\n", HTTP2_MAGIC)
}

fn http2_then_inner(first: &[u8]) -> Vec<u8> {
    pcap(
        LINK_ETHERNET,
        &[
            eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, first),
            eth_ipv4_tcp_seq(OUTER, 50000, 80, 1 + first.len() as u32, INNER_GET),
        ],
    )
}

fn req_resp_same_dir(req: &[u8], resp: &[u8], later: &[u8]) -> [Vec<u8>; 3] {
    [
        eth_ipv4_tcp_to(OUTER, PEER, 50000, 80, 1, req),
        eth_ipv4_tcp_to(PEER, OUTER, 80, 50000, 1, resp),
        eth_ipv4_tcp_to(PEER, OUTER, 80, 50000, 1 + resp.len() as u32, later),
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
            "sstp-100-then-200-then-get",
            pcap(
                LINK_ETHERNET,
                &req_interim_resp_get(SSTP_REQ, CONTINUE_100, SSTP_200, INNER_GET),
            ),
        ),
        (
            "sstp-100-then-200-leftover-get",
            pcap(LINK_ETHERNET, &sstp_interim_leftover_get(CONTINUE_100)),
        ),
        (
            "sstp-102-then-200-leftover-get",
            pcap(
                LINK_ETHERNET,
                &sstp_interim_leftover_get(b"HTTP/1.1 102 Processing\r\n\r\n"),
            ),
        ),
        (
            "sstp-103-then-200-leftover-get",
            pcap(
                LINK_ETHERNET,
                &sstp_interim_leftover_get(b"HTTP/1.1 103 Early Hints\r\n\r\n"),
            ),
        ),
        (
            "sstp-101-no-upgrade-then-200-leftover-get",
            pcap(
                LINK_ETHERNET,
                &sstp_interim_leftover_get(b"HTTP/1.1 101 Switching Protocols\r\n\r\n"),
            ),
        ),
        (
            "sstp-102-then-200-then-get",
            pcap(
                LINK_ETHERNET,
                &req_interim_resp_get(
                    SSTP_REQ,
                    b"HTTP/1.1 102 Processing\r\n\r\n",
                    SSTP_200,
                    INNER_GET,
                ),
            ),
        ),
        (
            "sstp-103-then-200-then-get",
            pcap(
                LINK_ETHERNET,
                &req_interim_resp_get(
                    SSTP_REQ,
                    b"HTTP/1.1 103 Early Hints\r\n\r\n",
                    SSTP_200,
                    INNER_GET,
                ),
            ),
        ),
        (
            "sstp-101-no-upgrade-then-200-then-get",
            pcap(
                LINK_ETHERNET,
                &req_interim_resp_get(
                    SSTP_REQ,
                    b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
                    SSTP_200,
                    INNER_GET,
                ),
            ),
        ),
        (
            "sstp-two-100s-then-200-then-get",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp_to(OUTER, PEER, 50000, 80, 1, SSTP_REQ),
                    eth_ipv4_tcp_to(PEER, OUTER, 80, 50000, 1, CONTINUE_100),
                    eth_ipv4_tcp_to(
                        PEER,
                        OUTER,
                        80,
                        50000,
                        1 + CONTINUE_100.len() as u32,
                        CONTINUE_100,
                    ),
                    eth_ipv4_tcp_to(
                        PEER,
                        OUTER,
                        80,
                        50000,
                        1 + 2 * CONTINUE_100.len() as u32,
                        SSTP_200,
                    ),
                    eth_ipv4_tcp_to(
                        OUTER,
                        PEER,
                        50000,
                        80,
                        1 + SSTP_REQ.len() as u32,
                        INNER_GET,
                    ),
                ],
            ),
        ),
        (
            "sstp-and-100-same-segment-then-200-then-get",
            pcap(
                LINK_ETHERNET,
                &req_resp_get(
                    &{
                        let mut payload = SSTP_REQ.to_vec();
                        payload.extend_from_slice(CONTINUE_100);
                        payload
                    },
                    SSTP_200,
                    INNER_GET,
                ),
            ),
        ),
        (
            "sstp-same-segment-100-and-200-leftover",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp_to(OUTER, PEER, 50000, 80, 1, SSTP_REQ),
                    eth_ipv4_tcp_to(
                        PEER,
                        OUTER,
                        80,
                        50000,
                        1,
                        &{
                            let mut payload = CONTINUE_100.to_vec();
                            payload.extend_from_slice(SSTP_200);
                            payload.extend_from_slice(INNER_GET);
                            payload
                        },
                    ),
                ],
            ),
        ),
        (
            "sstp-201-then-200-then-get",
            pcap(
                LINK_ETHERNET,
                &req_interim_resp_get(
                    SSTP_REQ,
                    b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n",
                    SSTP_200,
                    INNER_GET,
                ),
            ),
        ),
        (
            "sstp-203-then-200-then-get",
            pcap(
                LINK_ETHERNET,
                &req_interim_resp_get(
                    SSTP_REQ,
                    b"HTTP/1.1 203 Non-Authoritative Information\r\nContent-Length: 0\r\n\r\n",
                    SSTP_200,
                    INNER_GET,
                ),
            ),
        ),
        (
            "sstp-204-then-200-then-get",
            pcap(
                LINK_ETHERNET,
                &req_interim_resp_get(
                    SSTP_REQ,
                    b"HTTP/1.1 204 No Content\r\n\r\n",
                    SSTP_200,
                    INNER_GET,
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
            "content-length-trail-vt-then-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    &cl_trail_then_inner(b"\x0b", b"xxxx"),
                )],
            ),
        ),
        (
            "content-length-trail-vt",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"POST / HTTP/1.1\r\nHost: cl.example\r\nContent-Length: 4\x0b\r\n\r\n",
                )],
            ),
        ),
        (
            "content-length-trail-ff-then-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    &cl_trail_then_inner(b"\x0c", b"xxxx"),
                )],
            ),
        ),
        (
            "content-length-trail-tab-then-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    &cl_trail_then_inner(b"\t", b"xxxx"),
                )],
            ),
        ),
        (
            "content-length-trail-sp-then-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    &cl_trail_then_inner(b" ", b"xxxx"),
                )],
            ),
        ),
        (
            "content-length-trail-nul-then-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    &cl_trail_then_inner(b"\x00", b"xxxx"),
                )],
            ),
        ),
        (
            "content-length-lead-vt-then-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(OUTER, 50000, 80, &{
                    let mut payload = b"POST / HTTP/1.1\r\nHost: cllead.example\r\nContent-Length: \x0b4\r\n\r\nxxxx"
                        .to_vec();
                    payload.extend_from_slice(INNER_GET);
                    payload
                })],
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
            "sstp-request-and-200-same-segment-client",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_to(
                    OUTER,
                    PEER,
                    50000,
                    80,
                    1,
                    b"SSTP_DUPLEX_POST / HTTP/1.1\r\nHost: sstp.example\r\n\r\nHTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\nGET / HTTP/1.1\r\nHost: after.example\r\n\r\n",
                )],
            ),
        ),
        (
            "sstp-request-and-200-same-segment-server",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_to(
                    PEER,
                    OUTER,
                    80,
                    50000,
                    1,
                    b"SSTP_DUPLEX_POST / HTTP/1.1\r\nHost: sstp.example\r\n\r\nHTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\nGET / HTTP/1.1\r\nHost: after.example\r\n\r\n",
                )],
            ),
        ),
        (
            "sstp-request-and-200-same-segment-resp-host-client",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_to(
                    OUTER,
                    PEER,
                    50000,
                    80,
                    1,
                    b"SSTP_DUPLEX_POST / HTTP/1.1\r\nHost: sstp.example\r\n\r\nHTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\nHost: resp.example\r\n\r\nGET / HTTP/1.1\r\nHost: after.example\r\n\r\n",
                )],
            ),
        ),
        (
            "sstp-request-and-200-same-segment-resp-host-server",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_to(
                    PEER,
                    OUTER,
                    80,
                    50000,
                    1,
                    b"SSTP_DUPLEX_POST / HTTP/1.1\r\nHost: sstp.example\r\n\r\nHTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\nHost: resp.example\r\n\r\nGET / HTTP/1.1\r\nHost: after.example\r\n\r\n",
                )],
            ),
        ),
        (
            "204-cl-extra",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_to(
                    PEER,
                    OUTER,
                    80,
                    50000,
                    1,
                    &cl_then(b"HTTP/1.1 204 No Content", b""),
                )],
            ),
        ),
        (
            "204-cl-drop",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_to(
                    PEER,
                    OUTER,
                    80,
                    50000,
                    1,
                    &cl_then(b"HTTP/1.1 204 No Content", b"xxxx"),
                )],
            ),
        ),
        (
            "100-cl-extra",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_to(
                    PEER,
                    OUTER,
                    80,
                    50000,
                    1,
                    &cl_then(b"HTTP/1.1 100 Continue", b""),
                )],
            ),
        ),
        (
            "100-cl-drop",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_to(
                    PEER,
                    OUTER,
                    80,
                    50000,
                    1,
                    &cl_then(b"HTTP/1.1 100 Continue", b"xxxx"),
                )],
            ),
        ),
        (
            "101-cl-extra",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_to(
                    PEER,
                    OUTER,
                    80,
                    50000,
                    1,
                    &cl_then(b"HTTP/1.1 101 Switching Protocols", b""),
                )],
            ),
        ),
        (
            "101-cl-drop",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_to(
                    PEER,
                    OUTER,
                    80,
                    50000,
                    1,
                    &cl_then(b"HTTP/1.1 101 Switching Protocols", b"xxxx"),
                )],
            ),
        ),
        (
            "102-cl-extra",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_to(
                    PEER,
                    OUTER,
                    80,
                    50000,
                    1,
                    &cl_then(b"HTTP/1.1 102 Processing", b""),
                )],
            ),
        ),
        (
            "102-cl-drop",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_to(
                    PEER,
                    OUTER,
                    80,
                    50000,
                    1,
                    &cl_then(b"HTTP/1.1 102 Processing", b"xxxx"),
                )],
            ),
        ),
        (
            "304-cl-extra",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_to(
                    PEER,
                    OUTER,
                    80,
                    50000,
                    1,
                    &cl_then(b"HTTP/1.1 304 Not Modified", b""),
                )],
            ),
        ),
        (
            "304-cl-drop",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_to(
                    PEER,
                    OUTER,
                    80,
                    50000,
                    1,
                    &cl_then(b"HTTP/1.1 304 Not Modified", b"xxxx"),
                )],
            ),
        ),
        (
            "icy-204-cl-extra",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_to(
                    PEER,
                    OUTER,
                    80,
                    50000,
                    1,
                    &cl_then(b"ICY 204 No Content", b""),
                )],
            ),
        ),
        (
            "icy-204-cl-drop",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_to(
                    PEER,
                    OUTER,
                    80,
                    50000,
                    1,
                    &cl_then(b"ICY 204 No Content", b"xxxx"),
                )],
            ),
        ),
        (
            "204-cl-extra-src-80",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(OUTER, 80, 50000, &cl_then(b"HTTP/1.1 204 No Content", b""))],
            ),
        ),
        (
            "204-cl-drop-src-80",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    80,
                    50000,
                    &cl_then(b"HTTP/1.1 204 No Content", b"xxxx"),
                )],
            ),
        ),
        (
            "204-cl-extra-ipv6",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv6_tcp(
                    PEER_V6,
                    OUTER_V6,
                    80,
                    50000,
                    &cl_then(b"HTTP/1.1 204 No Content", b""),
                )],
            ),
        ),
        (
            "204-cl-drop-ipv6",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv6_tcp(
                    PEER_V6,
                    OUTER_V6,
                    80,
                    50000,
                    &cl_then(b"HTTP/1.1 204 No Content", b"xxxx"),
                )],
            ),
        ),
        (
            "101-upgrade-same-segment-one-frame",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_to(
                    PEER,
                    OUTER,
                    80,
                    50000,
                    1,
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nHost: sw.example\r\n\r\nGET / HTTP/1.1\r\nHost: after.example\r\n\r\n",
                )],
            ),
        ),
        (
            "200-cl-extra",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_to(
                    PEER,
                    OUTER,
                    80,
                    50000,
                    1,
                    &cl_then(b"HTTP/1.1 200 OK", b""),
                )],
            ),
        ),
        (
            "200-cl-drop",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_to(
                    PEER,
                    OUTER,
                    80,
                    50000,
                    1,
                    &cl_then(b"HTTP/1.1 200 OK", b"xxxx"),
                )],
            ),
        ),
        (
            "203-cl-extra",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_to(
                    PEER,
                    OUTER,
                    80,
                    50000,
                    1,
                    &cl_then(b"HTTP/1.1 203 Non-Authoritative Information", b""),
                )],
            ),
        ),
        (
            "203-cl-drop",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_to(
                    PEER,
                    OUTER,
                    80,
                    50000,
                    1,
                    &cl_then(b"HTTP/1.1 203 Non-Authoritative Information", b"xxxx"),
                )],
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
            "sstp-200-no-cl",
            pcap(
                LINK_ETHERNET,
                &sstp_then(b"HTTP/1.1 200 Connection Established\r\n\r\n"),
            ),
        ),
        (
            "sstp-200-cl100",
            pcap(
                LINK_ETHERNET,
                &sstp_then(
                    b"HTTP/1.1 200 Connection Established\r\nContent-Length: 100\r\n\r\n",
                ),
            ),
        ),
        (
            "sstp-200-te-identity",
            pcap(
                LINK_ETHERNET,
                &sstp_then(
                    b"HTTP/1.1 200 Connection Established\r\nTransfer-Encoding: identity\r\n\r\n",
                ),
            ),
        ),
        (
            "sstp-200-te-chunked",
            pcap(
                LINK_ETHERNET,
                &sstp_then(
                    b"HTTP/1.1 200 Connection Established\r\nTransfer-Encoding: chunked\r\n\r\n",
                ),
            ),
        ),
        (
            "sstp-icy-200",
            pcap(
                LINK_ETHERNET,
                &sstp_then(b"ICY 200 Connection Established\r\n\r\n"),
            ),
        ),
        (
            "sstp-http10-200",
            pcap(
                LINK_ETHERNET,
                &sstp_then(b"HTTP/1.0 200 Connection Established\r\n\r\n"),
            ),
        ),
        (
            "sstp-200-no-cl-dport-80",
            pcap(
                LINK_ETHERNET,
                &req_resp_get_ports(
                    50000,
                    80,
                    SSTP_REQ,
                    b"HTTP/1.1 200 Connection Established\r\n\r\n",
                    INNER_GET,
                ),
            ),
        ),
        (
            "sstp-200-no-cl-dport-8080",
            pcap(
                LINK_ETHERNET,
                &req_resp_get_ports(
                    50000,
                    8080,
                    SSTP_REQ,
                    b"HTTP/1.1 200 Connection Established\r\n\r\n",
                    INNER_GET,
                ),
            ),
        ),
        (
            "sstp-200-no-cl-dport-3128",
            pcap(
                LINK_ETHERNET,
                &req_resp_get_ports(
                    50000,
                    3128,
                    SSTP_REQ,
                    b"HTTP/1.1 200 Connection Established\r\n\r\n",
                    INNER_GET,
                ),
            ),
        ),
        (
            "sstp-200-no-cl-src-80",
            pcap(
                LINK_ETHERNET,
                &req_resp_get_ports(
                    80,
                    50000,
                    SSTP_REQ,
                    b"HTTP/1.1 200 Connection Established\r\n\r\n",
                    INNER_GET,
                ),
            ),
        ),
        (
            "sstp-200-no-cl-src-8080",
            pcap(
                LINK_ETHERNET,
                &req_resp_get_ports(
                    8080,
                    50000,
                    SSTP_REQ,
                    b"HTTP/1.1 200 Connection Established\r\n\r\n",
                    INNER_GET,
                ),
            ),
        ),
        (
            "sstp-200-no-cl-src-3128",
            pcap(
                LINK_ETHERNET,
                &req_resp_get_ports(
                    3128,
                    50000,
                    SSTP_REQ,
                    b"HTTP/1.1 200 Connection Established\r\n\r\n",
                    INNER_GET,
                ),
            ),
        ),
        (
            "sstp-200-no-cl-ipv6",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv6_tcp_to(OUTER_V6, PEER_V6, 50000, 80, 1, SSTP_REQ),
                    eth_ipv6_tcp_to(
                        PEER_V6,
                        OUTER_V6,
                        80,
                        50000,
                        1,
                        b"HTTP/1.1 200 Connection Established\r\n\r\n",
                    ),
                    eth_ipv6_tcp_to(
                        OUTER_V6,
                        PEER_V6,
                        50000,
                        80,
                        1 + SSTP_REQ.len() as u32,
                        INNER_GET,
                    ),
                ],
            ),
        ),
        (
            "sstp-200-fin-no-cl",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp_to(OUTER, PEER, 50000, 80, 1, SSTP_REQ),
                    eth(
                        0x0800,
                        &ipv4_to(
                            PEER,
                            OUTER,
                            6,
                            &tcp_seq_flags(
                                80,
                                50000,
                                1,
                                0x19,
                                b"HTTP/1.1 200 Connection Established\r\n\r\n",
                            ),
                        ),
                    ),
                    eth_ipv4_tcp_to(
                        OUTER,
                        PEER,
                        50000,
                        80,
                        1 + SSTP_REQ.len() as u32,
                        INNER_GET,
                    ),
                ],
            ),
        ),
        (
            "connect-200-no-cl-then-get",
            pcap(
                LINK_ETHERNET,
                &req_resp_get(
                    b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
                    b"HTTP/1.1 200 Connection Established\r\n\r\n",
                    INNER_GET,
                ),
            ),
        ),
        (
            "upgrade-101-te-identity-then-get",
            pcap(
                LINK_ETHERNET,
                &req_resp_get(
                    b"GET /chat HTTP/1.1\r\nHost: ws.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nTransfer-Encoding: identity\r\n\r\n",
                    INNER_GET,
                ),
            ),
        ),
        (
            "same-seq-longer",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"),
                    eth_ipv4_tcp_seq(
                        OUTER,
                        50000,
                        80,
                        1,
                        b"GET / HTTP/1.1\r\nHost: inner.example\r\n\r\n",
                    ),
                ],
            ),
        ),
        (
            "same-seq-partial-then-full",
            pcap(
                LINK_ETHERNET,
                &{
                    let full = b"GET / HTTP/1.1\r\nHost: split.example\r\n\r\n";
                    vec![
                        eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, &full[..20]),
                        eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, full),
                    ]
                },
            ),
        ),
        (
            "same-seq-same-length-retransmit",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"),
                    eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, b"GET / HTTP/1.1\r\nHost: b.example\r\n\r\n"),
                ],
            ),
        ),
        (
            "same-seq-shorter-retransmit",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp_seq(
                        OUTER,
                        50000,
                        80,
                        1,
                        b"GET / HTTP/1.1\r\nHost: inner.example\r\n\r\n",
                    ),
                    eth_ipv4_tcp_seq(
                        OUTER,
                        50000,
                        80,
                        1,
                        b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n",
                    ),
                ],
            ),
        ),
        (
            "desegment-200-no-cl-same-dir",
            pcap(
                LINK_ETHERNET,
                &req_resp_same_dir(
                    b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n",
                    b"HTTP/1.1 200 OK\r\nHost: resp.example\r\n\r\n",
                    INNER_GET,
                ),
            ),
        ),
        (
            "desegment-200-cl100-same-dir",
            pcap(
                LINK_ETHERNET,
                &req_resp_same_dir(
                    b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n",
                    b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n",
                    INNER_GET,
                ),
            ),
        ),
        (
            "desegment-200-te-identity-same-dir",
            pcap(
                LINK_ETHERNET,
                &req_resp_same_dir(
                    b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n",
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: identity\r\n\r\n",
                    INNER_GET,
                ),
            ),
        ),
        (
            "desegment-200-te-chunked-same-dir",
            pcap(
                LINK_ETHERNET,
                &req_resp_same_dir(
                    b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n",
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
                    INNER_GET,
                ),
            ),
        ),
        (
            "desegment-post-cl100-then-get",
            pcap(
                LINK_ETHERNET,
                &{
                    let post =
                        b"POST / HTTP/1.1\r\nHost: post.example\r\nContent-Length: 100\r\n\r\n";
                    vec![
                        eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, post),
                        eth_ipv4_tcp_seq(OUTER, 50000, 80, 1 + post.len() as u32, INNER_GET),
                    ]
                },
            ),
        ),
        (
            "desegment-get-then-post-cl100-then-get",
            pcap(
                LINK_ETHERNET,
                &{
                    let mut pipeline = b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n".to_vec();
                    pipeline.extend_from_slice(
                        b"POST / HTTP/1.1\r\nHost: post.example\r\nContent-Length: 100\r\n\r\n",
                    );
                    vec![
                        eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, &pipeline),
                        eth_ipv4_tcp_seq(OUTER, 50000, 80, 1 + pipeline.len() as u32, INNER_GET),
                    ]
                },
            ),
        ),
        (
            "desegment-200-opposite-get",
            pcap(
                LINK_ETHERNET,
                &req_resp_get(
                    b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n",
                    b"HTTP/1.1 200 OK\r\nHost: resp.example\r\n\r\n",
                    INNER_GET,
                ),
            ),
        ),
        (
            "head-200-then-get",
            pcap(
                LINK_ETHERNET,
                &req_resp_get(
                    b"HEAD / HTTP/1.1\r\nHost: a.example\r\n\r\n",
                    b"HTTP/1.1 200 OK\r\nHost: resp.example\r\n\r\n",
                    INNER_GET,
                ),
            ),
        ),
        (
            "rst-ack-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_flags(
                    OUTER,
                    50000,
                    80,
                    0x14,
                    b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n",
                )],
            ),
        ),
        (
            "rst-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_flags(
                    OUTER,
                    50000,
                    80,
                    0x04,
                    b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n",
                )],
            ),
        ),
        (
            "rst-psh-ack-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_flags(
                    OUTER,
                    50000,
                    80,
                    0x1c,
                    b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n",
                )],
            ),
        ),
        (
            "fin-rst-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_flags(
                    OUTER,
                    50000,
                    80,
                    0x05,
                    b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n",
                )],
            ),
        ),
        (
            "syn-rst-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_flags(
                    OUTER,
                    50000,
                    80,
                    0x06,
                    b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n",
                )],
            ),
        ),
        (
            "ack-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_flags(
                    OUTER,
                    50000,
                    80,
                    0x10,
                    b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n",
                )],
            ),
        ),
        (
            "fin-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_flags(
                    OUTER,
                    50000,
                    80,
                    0x01,
                    b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n",
                )],
            ),
        ),
        (
            "syn-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_flags(
                    OUTER,
                    50000,
                    80,
                    0x02,
                    b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n",
                )],
            ),
        ),
        (
            "syn-ack-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_flags(
                    OUTER,
                    50000,
                    80,
                    0x12,
                    b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n",
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
        (
            "notify-leftover-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"NOTIFY / HTTP/1.1\r\nHost: n.example\r\n\r\nGET / HTTP/1.1\r\nHost: inner.example\r\n\r\n",
                )],
            ),
        ),
        (
            "subscribe-leftover-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"SUBSCRIBE / HTTP/1.1\r\nHost: n.example\r\n\r\nGET / HTTP/1.1\r\nHost: inner.example\r\n\r\n",
                )],
            ),
        ),
        (
            "unsubscribe-leftover-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"UNSUBSCRIBE / HTTP/1.1\r\nHost: n.example\r\n\r\nGET / HTTP/1.1\r\nHost: inner.example\r\n\r\n",
                )],
            ),
        ),
        (
            "m-notify-leftover-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"M-NOTIFY / HTTP/1.1\r\nHost: n.example\r\n\r\nGET / HTTP/1.1\r\nHost: inner.example\r\n\r\n",
                )],
            ),
        ),
        (
            "notify-leftover-notify",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"NOTIFY / HTTP/1.1\r\nHost: n.example\r\n\r\nNOTIFY / HTTP/1.1\r\nHost: n2.example\r\n\r\n",
                )],
            ),
        ),
        (
            "notify-cl0-leftover-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"NOTIFY / HTTP/1.1\r\nHost: n.example\r\nContent-Length: 0\r\n\r\nGET / HTTP/1.1\r\nHost: inner.example\r\n\r\n",
                )],
            ),
        ),
        (
            "search-leftover-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"SEARCH / HTTP/1.1\r\nHost: n.example\r\n\r\nGET / HTTP/1.1\r\nHost: inner.example\r\n\r\n",
                )],
            ),
        ),
        (
            "poll-leftover-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"POLL / HTTP/1.1\r\nHost: n.example\r\n\r\nGET / HTTP/1.1\r\nHost: inner.example\r\n\r\n",
                )],
            ),
        ),
        (
            "http2-magic-then-get",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, HTTP2_MAGIC),
                    eth_ipv4_tcp_seq(
                        OUTER,
                        50000,
                        80,
                        1 + HTTP2_MAGIC.len() as u32,
                        INNER_GET,
                    ),
                ],
            ),
        ),
        (
            "http2-magic-then-opposite-get",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp_to(OUTER, PEER, 50000, 80, 1, HTTP2_MAGIC),
                    eth_ipv4_tcp_to(PEER, OUTER, 80, 50000, 1, INNER_GET),
                ],
            ),
        ),
        (
            "http2-prefix-then-get",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, HTTP2_PREFIX),
                    eth_ipv4_tcp_seq(
                        OUTER,
                        50000,
                        80,
                        1 + HTTP2_PREFIX.len() as u32,
                        INNER_GET,
                    ),
                ],
            ),
        ),
        (
            "http2-prefix-then-opposite-get",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp_to(OUTER, PEER, 50000, 80, 1, HTTP2_PREFIX),
                    eth_ipv4_tcp_to(PEER, OUTER, 80, 50000, 1, INNER_GET),
                ],
            ),
        ),
        (
            "http2-magic-leftover-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    &{
                        let mut payload = HTTP2_MAGIC.to_vec();
                        payload.extend_from_slice(INNER_GET);
                        payload
                    },
                )],
            ),
        ),
        (
            "http2-first-line-then-get",
            http2_then_inner(HTTP2_FIRST_LINE),
        ),
        (
            "http2-first-line-then-opposite-get",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp_to(OUTER, PEER, 50000, 80, 1, HTTP2_FIRST_LINE),
                    eth_ipv4_tcp_to(PEER, OUTER, 80, 50000, 1, INNER_GET),
                ],
            ),
        ),
        (
            "http2-leading-crlf-magic-then-get",
            http2_then_inner(&leading_crlf_magic()),
        ),
        (
            "http2-leading-crlf-magic-then-opposite-get",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp_to(OUTER, PEER, 50000, 80, 1, &leading_crlf_magic()),
                    eth_ipv4_tcp_to(PEER, OUTER, 80, 50000, 1, INNER_GET),
                ],
            ),
        ),
        (
            "http2-get-leftover-magic-then-get",
            http2_then_inner(&concat_bytes(GET_A, HTTP2_MAGIC)),
        ),
        (
            "http2-get-leftover-first-line-then-get",
            http2_then_inner(&concat_bytes(GET_A, HTTP2_FIRST_LINE)),
        ),
        (
            "http2-post-cl0-leftover-magic-then-get",
            http2_then_inner(&concat_bytes(POST_CL0_A, HTTP2_MAGIC)),
        ),
        (
            "http2-204-leftover-magic-then-get",
            http2_then_inner(&concat_bytes(RESP_204_A, HTTP2_MAGIC)),
        ),
        (
            "http2-notify-leftover-magic-then-get",
            http2_then_inner(&concat_bytes(NOTIFY_A, HTTP2_MAGIC)),
        ),
        (
            "http2-get-leftover-magic-ipv6",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv6_tcp_to(OUTER_V6, PEER_V6, 50000, 80, 1, &concat_bytes(GET_A, HTTP2_MAGIC)),
                    eth_ipv6_tcp_to(
                        OUTER_V6,
                        PEER_V6,
                        50000,
                        80,
                        1 + GET_A.len() as u32 + HTTP2_MAGIC.len() as u32,
                        INNER_GET,
                    ),
                ],
            ),
        ),
        (
            "http2-get-leftover-magic-vlan",
            pcap(
                LINK_ETHERNET,
                &[
                    vlan(
                        0x0800,
                        &ipv4(OUTER, 6, &tcp_seq(50000, 80, 1, &concat_bytes(GET_A, HTTP2_MAGIC))),
                    ),
                    vlan(
                        0x0800,
                        &ipv4(
                            OUTER,
                            6,
                            &tcp_seq(
                                50000,
                                80,
                                1 + GET_A.len() as u32 + HTTP2_MAGIC.len() as u32,
                                INNER_GET,
                            ),
                        ),
                    ),
                ],
            ),
        ),
        (
            "http2-get-leftover-magic-src-80",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp_to(PEER, OUTER, 80, 50000, 1, &concat_bytes(GET_A, HTTP2_MAGIC)),
                    eth_ipv4_tcp_to(
                        PEER,
                        OUTER,
                        80,
                        50000,
                        1 + GET_A.len() as u32 + HTTP2_MAGIC.len() as u32,
                        INNER_GET,
                    ),
                ],
            ),
        ),
        (
            "http2-get-leftover-magic-8080",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp_seq(OUTER, 50000, 8080, 1, &concat_bytes(GET_A, HTTP2_MAGIC)),
                    eth_ipv4_tcp_seq(
                        OUTER,
                        50000,
                        8080,
                        1 + GET_A.len() as u32 + HTTP2_MAGIC.len() as u32,
                        INNER_GET,
                    ),
                ],
            ),
        ),
        (
            "http2-first-line-ipv6",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv6_tcp_to(OUTER_V6, PEER_V6, 50000, 80, 1, HTTP2_FIRST_LINE),
                    eth_ipv6_tcp_to(
                        OUTER_V6,
                        PEER_V6,
                        50000,
                        80,
                        1 + HTTP2_FIRST_LINE.len() as u32,
                        INNER_GET,
                    ),
                ],
            ),
        ),
        (
            "http2-first-line-vlan",
            pcap(
                LINK_ETHERNET,
                &[
                    vlan(0x0800, &ipv4(OUTER, 6, &tcp_seq(50000, 80, 1, HTTP2_FIRST_LINE))),
                    vlan(
                        0x0800,
                        &ipv4(
                            OUTER,
                            6,
                            &tcp_seq(50000, 80, 1 + HTTP2_FIRST_LINE.len() as u32, INNER_GET),
                        ),
                    ),
                ],
            ),
        ),
        (
            "http2-first-line-src-80",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp_to(PEER, OUTER, 80, 50000, 1, HTTP2_FIRST_LINE),
                    eth_ipv4_tcp_to(
                        PEER,
                        OUTER,
                        80,
                        50000,
                        1 + HTTP2_FIRST_LINE.len() as u32,
                        INNER_GET,
                    ),
                ],
            ),
        ),
        (
            "http2-first-line-8080",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp_seq(OUTER, 50000, 8080, 1, HTTP2_FIRST_LINE),
                    eth_ipv4_tcp_seq(
                        OUTER,
                        50000,
                        8080,
                        1 + HTTP2_FIRST_LINE.len() as u32,
                        INNER_GET,
                    ),
                ],
            ),
        ),
        (
            "http2-leading-crlf-magic-ipv6",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv6_tcp_to(OUTER_V6, PEER_V6, 50000, 80, 1, &leading_crlf_magic()),
                    eth_ipv6_tcp_to(
                        OUTER_V6,
                        PEER_V6,
                        50000,
                        80,
                        1 + leading_crlf_magic().len() as u32,
                        INNER_GET,
                    ),
                ],
            ),
        ),
        (
            "http2-leading-crlf-magic-vlan",
            pcap(
                LINK_ETHERNET,
                &[
                    vlan(
                        0x0800,
                        &ipv4(OUTER, 6, &tcp_seq(50000, 80, 1, &leading_crlf_magic())),
                    ),
                    vlan(
                        0x0800,
                        &ipv4(
                            OUTER,
                            6,
                            &tcp_seq(
                                50000,
                                80,
                                1 + leading_crlf_magic().len() as u32,
                                INNER_GET,
                            ),
                        ),
                    ),
                ],
            ),
        ),
        (
            "http2-leading-crlf-magic-src-80",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp_to(PEER, OUTER, 80, 50000, 1, &leading_crlf_magic()),
                    eth_ipv4_tcp_to(
                        PEER,
                        OUTER,
                        80,
                        50000,
                        1 + leading_crlf_magic().len() as u32,
                        INNER_GET,
                    ),
                ],
            ),
        ),
        (
            "http2-leading-crlf-magic-8080",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp_seq(OUTER, 50000, 8080, 1, &leading_crlf_magic()),
                    eth_ipv4_tcp_seq(
                        OUTER,
                        50000,
                        8080,
                        1 + leading_crlf_magic().len() as u32,
                        INNER_GET,
                    ),
                ],
            ),
        ),
    ]
    .into_iter()
    .chain(connect_cases())
    .chain(http2_cl24_cases())
    .chain(junk_header_cases())
    .chain(on_disk())
    .filter(|(_, bytes)| !bytes.is_empty())
    .collect()
}

fn connect_req(uri: &str) -> Vec<u8> {
    let mut req = b"CONNECT ".to_vec();
    req.extend_from_slice(uri.as_bytes());
    req.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    req.extend_from_slice(uri.as_bytes());
    req.extend_from_slice(b"\r\n\r\n");
    req
}

fn connect_cases() -> Vec<(&'static str, Vec<u8>)> {
    const CONNECT_200: &[u8] = b"HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n";
    const CONNECT_201: &[u8] = b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n";
    const TUNNEL: &[(&str, &str)] = &[
        ("connect-21-200-then-get", "example.com:21"),
        ("connect-22-200-then-get", "example.com:22"),
        ("connect-23-200-then-get", "example.com:23"),
        ("connect-25-200-then-get", "example.com:25"),
        ("connect-53-200-then-get", "example.com:53"),
        ("connect-110-200-then-get", "example.com:110"),
        ("connect-143-200-then-get", "example.com:143"),
        ("connect-587-200-then-get", "example.com:587"),
        ("connect-1194-200-then-get", "example.com:1194"),
        ("connect-1883-200-then-get", "example.com:1883"),
        ("connect-3306-200-then-get", "example.com:3306"),
        ("connect-5060-200-then-get", "example.com:5060"),
        ("connect-5432-200-then-get", "example.com:5432"),
        ("connect-5900-200-then-get", "example.com:5900"),
        ("connect-6379-200-then-get", "example.com:6379"),
    ];
    const STAY: &[(&str, &str)] = &[
        ("connect-443-200-then-get", "example.com:443"),
        ("connect-80-200-then-get", "example.com:80"),
        ("connect-8080-200-then-get", "example.com:8080"),
        ("connect-465-200-then-get", "example.com:465"),
        ("connect-993-200-then-get", "example.com:993"),
        ("connect-995-200-then-get", "example.com:995"),
    ];
    const LEFTOVER: &[(&str, &str)] = &[
        ("connect-443-200-leftover-get", "example.com:443"),
        ("connect-22-200-leftover-get", "example.com:22"),
        ("connect-80-200-leftover-get", "example.com:80"),
    ];
    let mut out = Vec::new();
    for (name, uri) in TUNNEL {
        out.push((
            *name,
            pcap(
                LINK_ETHERNET,
                &req_resp_get(&connect_req(uri), CONNECT_200, INNER_GET),
            ),
        ));
    }
    out.push((
        "connect-noport-200-then-get",
        pcap(
            LINK_ETHERNET,
            &req_resp_get(&connect_req("example.com"), CONNECT_200, INNER_GET),
        ),
    ));
    out.push((
        "connect-noport-201-then-get",
        pcap(
            LINK_ETHERNET,
            &req_resp_get(&connect_req("example.com"), CONNECT_201, INNER_GET),
        ),
    ));
    out.push((
        "connect-22-201-then-get",
        pcap(
            LINK_ETHERNET,
            &req_resp_get(&connect_req("example.com:22"), CONNECT_201, INNER_GET),
        ),
    ));
    out.push((
        "connect-22-201-no-cl-then-get",
        pcap(
            LINK_ETHERNET,
            &req_resp_get(
                &connect_req("example.com:22"),
                b"HTTP/1.1 201 Created\r\n\r\n",
                INNER_GET,
            ),
        ),
    ));
    for (name, uri) in STAY {
        out.push((
            *name,
            pcap(
                LINK_ETHERNET,
                &req_resp_get(&connect_req(uri), CONNECT_200, INNER_GET),
            ),
        ));
    }
    for (name, uri) in LEFTOVER {
        let mut leftover = CONNECT_200.to_vec();
        leftover.extend_from_slice(INNER_GET);
        out.push((
            *name,
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp_to(OUTER, PEER, 50000, 80, 1, &connect_req(uri)),
                    eth_ipv4_tcp_to(PEER, OUTER, 80, 50000, 1, &leftover),
                ],
            ),
        ));
    }
    out
}

fn junk_then_inner(first: &[u8]) -> Vec<u8> {
    let mut payload = first.to_vec();
    payload.extend_from_slice(INNER_GET);
    payload
}

fn cl_trail_then_inner(trail: &[u8], body: &[u8]) -> Vec<u8> {
    let mut payload = b"POST / HTTP/1.1\r\nHost: cl.example\r\nContent-Length: 4".to_vec();
    payload.extend_from_slice(trail);
    payload.extend_from_slice(b"\r\n\r\n");
    payload.extend_from_slice(body);
    payload.extend_from_slice(INNER_GET);
    payload
}

fn junk_cl4_then_inner(start: &[u8], after_junk: &[u8]) -> Vec<u8> {
    let mut payload = start.to_vec();
    payload.extend_from_slice(b"\r\nHost: a.example\r\nContent-Length: 4\r\nnot-a-header\r\n");
    payload.extend_from_slice(after_junk);
    payload.extend_from_slice(INNER_GET);
    payload
}

fn junk_header_frame(sport: u16, dport: u16, first: &[u8]) -> Vec<u8> {
    pcap(
        LINK_ETHERNET,
        &[eth_ipv4_tcp(OUTER, sport, dport, &junk_then_inner(first))],
    )
}

fn junk_header_cases() -> Vec<(&'static str, Vec<u8>)> {
    const JUNK: &[u8] = b"GET / HTTP/1.1\r\nHost: a.example\r\nnot-a-header\r\n\r\n";
    vec![
        ("junk-header-then-get", junk_header_frame(50000, 80, JUNK)),
        (
            "junk-obs-fold-then-get",
            junk_header_frame(50000, 80, b"GET / HTTP/1.1\r\nHost: ab\r\n cd\r\n\r\n"),
        ),
        (
            "junk-tab-fold-then-get",
            junk_header_frame(50000, 80, b"GET / HTTP/1.1\r\nHost: ab\r\n\tcd\r\n\r\n"),
        ),
        (
            "junk-space-only-then-get",
            junk_header_frame(50000, 80, b"GET / HTTP/1.1\r\nHost: a.example\r\n \r\n\r\n"),
        ),
        (
            "junk-x-foo-then-get",
            junk_header_frame(
                50000,
                80,
                b"GET / HTTP/1.1\r\nHost: a.example\r\nX-Foo\r\n\r\n",
            ),
        ),
        (
            "junk-post-cl0-then-get",
            junk_header_frame(
                50000,
                80,
                b"POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 0\r\nnot-a-header\r\n\r\n",
            ),
        ),
        (
            "junk-204-then-get",
            junk_header_frame(
                50000,
                80,
                b"HTTP/1.1 204 No Content\r\nHost: a.example\r\nnot-a-header\r\n\r\n",
            ),
        ),
        (
            "junk-200-cl0-then-get",
            junk_header_frame(
                50000,
                80,
                b"HTTP/1.1 200 OK\r\nHost: a.example\r\nContent-Length: 0\r\nnot-a-header\r\n\r\n",
            ),
        ),
        (
            "junk-two-lines-then-get",
            junk_header_frame(
                50000,
                80,
                b"GET / HTTP/1.1\r\nHost: a.example\r\nnot-a-header\r\njunk2\r\n\r\n",
            ),
        ),
        (
            "junk-header-src-80",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_to(
                    PEER,
                    OUTER,
                    80,
                    50000,
                    1,
                    &junk_then_inner(JUNK),
                )],
            ),
        ),
        ("junk-header-8080", junk_header_frame(50000, 8080, JUNK)),
        (
            "junk-header-later-frame-get",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, JUNK),
                    eth_ipv4_tcp_seq(OUTER, 50000, 80, 1 + JUNK.len() as u32, INNER_GET),
                ],
            ),
        ),
        (
            "notify-leftover-junk-then-get",
            junk_header_frame(
                50000,
                80,
                b"NOTIFY / HTTP/1.1\r\nHost: n.example\r\n\r\nnot-a-header\r\n",
            ),
        ),
        (
            "junk-colon-value-then-get",
            junk_header_frame(
                50000,
                80,
                b"GET / HTTP/1.1\r\nHost: a.example\r\n:value\r\n\r\n",
            ),
        ),
        (
            "junk-foo-bar-colon-then-get",
            junk_header_frame(
                50000,
                80,
                b"GET / HTTP/1.1\r\nHost: a.example\r\nFoo Bar: x\r\n\r\n",
            ),
        ),
        (
            "junk-header-no-blank",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"GET / HTTP/1.1\r\nHost: fuzz.example\r\nnot-a-header\r\n",
                )],
            ),
        ),
        (
            "junk-cl4-200-xxxx-then-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    &junk_cl4_then_inner(b"HTTP/1.1 200 OK", b"xxxx"),
                )],
            ),
        ),
        (
            "junk-cl4-200-then-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    &junk_cl4_then_inner(b"HTTP/1.1 200 OK", b""),
                )],
            ),
        ),
        (
            "junk-cl4-201-xxxx-then-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    &junk_cl4_then_inner(b"HTTP/1.1 201 Created", b"xxxx"),
                )],
            ),
        ),
        (
            "junk-cl4-302-xxxx-then-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    &junk_cl4_then_inner(b"HTTP/1.1 302 Found", b"xxxx"),
                )],
            ),
        ),
        (
            "junk-cl4-404-xxxx-then-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    &junk_cl4_then_inner(b"HTTP/1.1 404 Not Found", b"xxxx"),
                )],
            ),
        ),
        (
            "junk-cl4-206-xxxx-then-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    &junk_cl4_then_inner(b"HTTP/1.1 206 Partial Content", b"xxxx"),
                )],
            ),
        ),
        (
            "junk-cl4-post-xxxx-then-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    &junk_cl4_then_inner(b"POST / HTTP/1.1", b"xxxx"),
                )],
            ),
        ),
        (
            "junk-cl4-get-xxxx-then-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    &junk_cl4_then_inner(b"GET / HTTP/1.1", b"xxxx"),
                )],
            ),
        ),
        (
            "junk-cl4-200-blank-body-then-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    &junk_cl4_then_inner(b"HTTP/1.1 200 OK", b"\r\nxxxx"),
                )],
            ),
        ),
        (
            "junk-cl4-post-blank-body-then-get",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    &junk_cl4_then_inner(b"POST / HTTP/1.1", b"\r\nxxxx"),
                )],
            ),
        ),
        (
            "junk-304-then-get",
            junk_header_frame(
                50000,
                80,
                b"HTTP/1.1 304 Not Modified\r\nHost: a.example\r\nnot-a-header\r\n\r\n",
            ),
        ),
        (
            "junk-cl4-200-xxxx-fin",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_fin(
                    OUTER,
                    50000,
                    80,
                    &junk_cl4_then_inner(b"HTTP/1.1 200 OK", b"xxxx"),
                )],
            ),
        ),
        (
            "junk-later-cl100-post-then-get",
            junk_header_frame(
                50000,
                80,
                b"POST / HTTP/1.1\r\nHost: a.example\r\nnot-a-header\r\nContent-Length: 100\r\n\r\n",
            ),
        ),
        (
            "junk-later-cl4-get-nobody",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"GET / HTTP/1.1\r\nHost: a.example\r\nnot-a-header\r\nContent-Length: 4\r\n\r\n",
                )],
            ),
        ),
        (
            "junk-two-lines-later-cl50",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"POST / HTTP/1.1\r\nHost: a.example\r\nnot-a-header\r\njunk2\r\nContent-Length: 50\r\n\r\n",
                )],
            ),
        ),
        (
            "junk-obs-fold-later-cl50",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"POST / HTTP/1.1\r\nHost: a.example\r\n extra\r\nContent-Length: 50\r\n\r\n",
                )],
            ),
        ),
        (
            "junk-later-cl100-notify-then-get",
            junk_header_frame(
                50000,
                80,
                b"NOTIFY / HTTP/1.1\r\nHost: a.example\r\nnot-a-header\r\nContent-Length: 100\r\n\r\n",
            ),
        ),
        (
            "junk-later-cl100-options-then-get",
            junk_header_frame(
                50000,
                80,
                b"OPTIONS / HTTP/1.1\r\nHost: a.example\r\nnot-a-header\r\nContent-Length: 100\r\n\r\n",
            ),
        ),
        (
            "junk-later-chunked",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"POST / HTTP/1.1\r\nHost: a.example\r\nnot-a-header\r\nTransfer-Encoding: chunked\r\n\r\n",
                )],
            ),
        ),
        (
            "junk-later-chunked-leftover-1",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(
                    OUTER,
                    50000,
                    80,
                    b"POST / HTTP/1.1\r\nHost: a.example\r\nnot-a-header\r\nTransfer-Encoding: chunked\r\n\r\n1",
                )],
            ),
        ),
        (
            "junk-later-chunked-0-then-get",
            junk_header_frame(
                50000,
                80,
                b"POST / HTTP/1.1\r\nHost: a.example\r\nnot-a-header\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            ),
        ),
        (
            "junk-later-cl4-body-then-get",
            junk_header_frame(
                50000,
                80,
                b"POST / HTTP/1.1\r\nHost: a.example\r\nnot-a-header\r\nContent-Length: 4\r\n\r\nxxxx",
            ),
        ),
        (
            "junk-later-cl100-204-then-get",
            junk_header_frame(
                50000,
                80,
                b"HTTP/1.1 204 No Content\r\nHost: a.example\r\nnot-a-header\r\nContent-Length: 100\r\n\r\n",
            ),
        ),
        (
            "junk-later-cl100-post-fin",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_fin(
                    OUTER,
                    50000,
                    80,
                    &junk_then_inner(
                        b"POST / HTTP/1.1\r\nHost: a.example\r\nnot-a-header\r\nContent-Length: 100\r\n\r\n",
                    ),
                )],
            ),
        ),
    ]
}

fn cl24_magic_then_get(start: &[u8]) -> Vec<u8> {
    let mut payload = start.to_vec();
    payload.extend_from_slice(b"\r\nHost: a.example\r\nContent-Length: 24\r\n\r\n");
    payload.extend_from_slice(HTTP2_MAGIC);
    payload.extend_from_slice(INNER_GET);
    payload
}

fn http2_cl24_cases() -> Vec<(&'static str, Vec<u8>)> {
    let starts: [(&'static str, &[u8]); 6] = [
        ("http2-cl24-get-leftover-get", b"GET / HTTP/1.1"),
        ("http2-cl24-put-leftover-get", b"PUT / HTTP/1.1"),
        ("http2-cl24-options-leftover-get", b"OPTIONS / HTTP/1.1"),
        ("http2-cl24-post-leftover-get", b"POST / HTTP/1.1"),
        ("http2-cl24-200-leftover-get", b"HTTP/1.1 200 OK"),
        ("http2-cl24-204-leftover-get", b"HTTP/1.1 204 No Content"),
    ];
    let mut out = Vec::new();
    for (name, start) in starts {
        out.push((
            name,
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp(OUTER, 50000, 80, &cl24_magic_then_get(start))],
            ),
        ));
    }
    out.push((
        "http2-get-cl0-leftover-magic-then-get",
        pcap(
            LINK_ETHERNET,
            &[eth_ipv4_tcp(OUTER, 50000, 80, &{
                let mut payload =
                    b"GET / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 0\r\n\r\n".to_vec();
                payload.extend_from_slice(HTTP2_MAGIC);
                payload.extend_from_slice(INNER_GET);
                payload
            })],
        ),
    ));
    let mut first = b"POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 24\r\n\r\n".to_vec();
    first.extend_from_slice(HTTP2_MAGIC);
    out.push(("http2-cl24-post-then-later-get", http2_then_inner(&first)));
    out
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
