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
fn http_host_without_tcp_reassemble_matches_tshark_469() {
    let Some((tshark, fin)) = tools() else {
        return;
    };
    let dir = work_dir();
    let file = pcap(
        LINK_ETHERNET,
        &[eth_ipv4_tcp(OUTER, 50000, 80, &get("www.example.com"))],
    );
    let path = dir.join("http-host-default-no-o.pcap");
    fs::write(&path, file).unwrap();
    let mut args = vec![OsString::from("-r"), path.as_os_str().to_os_string()];
    args.extend(
        ["-n", "-T", "fields", "-e", FIELD]
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

const SSTP_REQ: &[u8] = b"SSTP_DUPLEX_POST / HTTP/1.1\r\nHost: sstp.example\r\n\r\n";
const SSTP_200: &[u8] = b"HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n";
const INNER_GET: &[u8] = b"GET / HTTP/1.1\r\nHost: inner.example\r\n\r\n";
const CONTINUE_100: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";
const HTTP2_MAGIC: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const GET_A: &[u8] = b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n";
const JUNK: &[u8] = b"GET / HTTP/1.1\r\nHost: a.example\r\nnot-a-header\r\n\r\n";

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

fn req_resp_same_dir(req: &[u8], resp: &[u8], later: &[u8]) -> [Vec<u8>; 3] {
    [
        eth_ipv4_tcp_to(OUTER, PEER, 50000, 80, 1, req),
        eth_ipv4_tcp_to(PEER, OUTER, 80, 50000, 1, resp),
        eth_ipv4_tcp_to(PEER, OUTER, 80, 50000, 1 + resp.len() as u32, later),
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

fn overlap_past_nxtseq(seq: u32, suffix: &[u8]) -> Vec<u8> {
    let nxtseq = 1 + GET_A.len() as u32;
    let pad = nxtseq.saturating_sub(seq) as usize;
    let mut payload = vec![b'X'; pad];
    payload.extend_from_slice(suffix);
    payload
}

fn truncated_prefix_extend(cut: &[u8]) -> Vec<Vec<u8>> {
    let mut mid = GET_A.to_vec();
    mid.extend_from_slice(cut);
    let mut last = GET_A.to_vec();
    last.extend_from_slice(INNER_GET);
    vec![
        eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, GET_A),
        eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, &mid),
        eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, &last),
    ]
}

fn truncated_suffix_then_inner(cut: &[u8]) -> Vec<Vec<u8>> {
    let mut mid = GET_A.to_vec();
    mid.extend_from_slice(cut);
    vec![
        eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, GET_A),
        eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, &mid),
        eth_ipv4_tcp_seq(OUTER, 50000, 80, 1 + mid.len() as u32, INNER_GET),
    ]
}

fn empty_syn_then_get(flags: u8, seq: u32) -> Vec<Vec<u8>> {
    vec![
        eth_ipv4_tcp_to_flags(OUTER, PEER, 50000, 80, 0, flags, b""),
        eth_ipv4_tcp_seq(OUTER, 50000, 80, seq, GET_A),
    ]
}

fn syn_then_inner(flags: u8, seq: u32) -> Vec<Vec<u8>> {
    vec![
        eth_ipv4_tcp_to_flags(OUTER, PEER, 50000, 80, 0, flags, GET_A),
        eth_ipv4_tcp_seq(OUTER, 50000, 80, seq, INNER_GET),
    ]
}

fn cl_then(status: &[u8], pad: &[u8]) -> Vec<u8> {
    let mut payload = status.to_vec();
    payload.extend_from_slice(b"\r\nHost: st.example\r\nContent-Length: 4\r\n\r\n");
    payload.extend_from_slice(pad);
    payload.extend_from_slice(b"GET / HTTP/1.1\r\nHost: after.example\r\n\r\n");
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

fn connect_req(uri: &str) -> Vec<u8> {
    let mut req = b"CONNECT ".to_vec();
    req.extend_from_slice(uri.as_bytes());
    req.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    req.extend_from_slice(uri.as_bytes());
    req.extend_from_slice(b"\r\n\r\n");
    req
}

fn junk_then_inner(first: &[u8]) -> Vec<u8> {
    let mut payload = first.to_vec();
    payload.extend_from_slice(INNER_GET);
    payload
}

fn tcp80(payload: &[u8]) -> Vec<u8> {
    pcap(LINK_ETHERNET, &[eth_ipv4_tcp(OUTER, 50000, 80, payload)])
}

fn tcp_http_ports(payload: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            "8080",
            pcap(LINK_ETHERNET, &[eth_ipv4_tcp(OUTER, 50000, 8080, payload)]),
        ),
        (
            "3128",
            pcap(LINK_ETHERNET, &[eth_ipv4_tcp(OUTER, 50000, 3128, payload)]),
        ),
        (
            "src80",
            pcap(
                LINK_ETHERNET,
                &[eth_ipv4_tcp_to(PEER, OUTER, 80, 50000, 1, payload)],
            ),
        ),
        (
            "ipv6",
            pcap(
                LINK_ETHERNET,
                &[eth(0x86dd, &ipv6(6, &tcp(50000, 80, payload)))],
            ),
        ),
    ]
}

fn tcp80_seq(frames: &[Vec<u8>]) -> Vec<u8> {
    pcap(LINK_ETHERNET, frames)
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
    let mut out = vec![
        (
            "host-80",
            pcap(LINK_ETHERNET, &[eth_ipv4_tcp(OUTER, 50000, 80, &req)]),
        ),
        (
            "host-3689",
            pcap(LINK_ETHERNET, &[eth_ipv4_tcp(OUTER, 50000, 3689, &req)]),
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
            tcp80(b"GET / HTTP/1.1\r\nHOST: Mixed.Example\r\n\r\n"),
        ),
        (
            "host-ows",
            tcp80(b"GET / HTTP/1.1\r\nHost:\t  example.com \r\n\r\n"),
        ),
        (
            "host-multi",
            tcp80(b"GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n"),
        ),
        (
            "host-comma",
            tcp80(b"GET / HTTP/1.1\r\nHost: a,b.example\r\n\r\n"),
        ),
        (
            "host-tab",
            tcp80(b"GET / HTTP/1.1\r\nHost: ab\tcd.example\r\n\r\n"),
        ),
        (
            "host-backslash",
            tcp80(b"GET / HTTP/1.1\r\nHost: ab\\cd.example\r\n\r\n"),
        ),
        (
            "host-high-byte",
            tcp80(b"GET / HTTP/1.1\r\nHost: x\xffy\r\n\r\n"),
        ),
        (
            "host-nul",
            tcp80(b"GET / HTTP/1.1\r\nHost: ab\x00cd.example\r\n\r\n"),
        ),
        (
            "no-host",
            tcp80(b"GET / HTTP/1.1\r\nUser-Agent: x\r\n\r\n"),
        ),
        (
            "post-complete",
            tcp80(b"POST / HTTP/1.1\r\nHost: post.example\r\nContent-Length: 4\r\n\r\nbody"),
        ),
        (
            "post-short-body",
            tcp80(b"POST / HTTP/1.1\r\nHost: post.example\r\nContent-Length: 100\r\n\r\nno"),
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
            tcp80(b"GET /a HTTP/1.1\r\nHost: a.example\r\n\r\nGET /b HTTP/1.1\r\nHost: b.example\r\n\r\n"),
        ),
        (
            "get-plus-junk",
            tcp80(b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\njunk"),
        ),
        (
            "chunked",
            tcp80(b"POST / HTTP/1.1\r\nHost: chunk.example\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"),
        ),
        (
            "http2-pri",
            tcp80(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
        ),
        (
            "connect",
            tcp80(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"),
        ),
        (
            "leading-crlf",
            tcp80(b"\r\nGET / HTTP/1.1\r\nHost: lead.example\r\n\r\n"),
        ),
        (
            "lf-only",
            tcp80(b"GET / HTTP/1.1\nHost: lf.example\n\n"),
        ),
        (
            "m-get",
            tcp80(b"M-GET / HTTP/1.1\r\nHost: ext.example\r\n\r\n"),
        ),
        (
            "lowercase-get",
            tcp80(b"get / HTTP/1.1\r\nHost: lower-get.example\r\n\r\n"),
        ),
        (
            "incomplete-headers",
            tcp80(b"GET / HTTP/1.1\r\nHost: cut.example"),
        ),
        ("retransmit", pcap(LINK_ETHERNET, &retransmit)),
        ("split-headers", pcap(LINK_ETHERNET, &split)),
        (
            "host-fold",
            tcp80(b"GET / HTTP/1.1\r\nHost: ab\r\n cd\r\n\r\n"),
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
            pcap(LINK_ETHERNET, &req_resp_get(SSTP_REQ, SSTP_200, INNER_GET)),
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
            "content-length-lead-vt",
            tcp80(b"POST / HTTP/1.1\r\nHost: cllead.example\r\nContent-Length: \x0b4\r\n\r\n"),
        ),
        (
            "content-length-lead-vt-body",
            tcp80(b"POST / HTTP/1.1\r\nHost: cllead.example\r\nContent-Length: \x0b4\r\n\r\nbody"),
        ),
        (
            "content-length-four-byte-body",
            tcp80(b"POST / HTTP/1.1\r\nHost: cllead.example\r\nContent-Length: 4\r\n\r\nbody"),
        ),
        (
            "content-length-trail-vt-then-get",
            tcp80(&cl_trail_then_inner(b"\x0b", b"xxxx")),
        ),
        (
            "content-length-trail-sp-then-get",
            tcp80(&cl_trail_then_inner(b" ", b"xxxx")),
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
            "sstp-same-segment-leftover",
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
                        b"HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\nGET / HTTP/1.1\r\nHost: after.example\r\n\r\n",
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
            "extra-crlf-pipeline",
            tcp80(b"GET /a HTTP/1.1\r\nHost: a.example\r\n\r\n\r\nGET /b HTTP/1.1\r\nHost: b.example\r\n\r\n"),
        ),
        (
            "two-extra-crlf-pipeline",
            tcp80(b"GET /a HTTP/1.1\r\nHost: a.example\r\n\r\n\r\n\r\nGET /b HTTP/1.1\r\nHost: b.example\r\n\r\n"),
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
            tcp80_seq(&[
                eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, GET_A),
                eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, INNER_GET),
            ]),
        ),
        (
            "same-seq-partial-then-full",
            tcp80_seq(&{
                let full = b"GET / HTTP/1.1\r\nHost: split.example\r\n\r\n";
                vec![
                    eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, &full[..20]),
                    eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, full),
                ]
            }),
        ),
        (
            "same-seq-same-length-retransmit",
            tcp80_seq(&[
                eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"),
                eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, b"GET / HTTP/1.1\r\nHost: b.example\r\n\r\n"),
            ]),
        ),
        (
            "overlap-seq-2",
            tcp80_seq(&[
                eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, GET_A),
                eth_ipv4_tcp_seq(OUTER, 50000, 80, 2, INNER_GET),
            ]),
        ),
        (
            "in-order-seq-36",
            tcp80_seq(&[
                eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, GET_A),
                eth_ipv4_tcp_seq(OUTER, 50000, 80, 36, INNER_GET),
            ]),
        ),
        (
            "gap-seq-37",
            tcp80_seq(&[
                eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, GET_A),
                eth_ipv4_tcp_seq(OUTER, 50000, 80, 37, INNER_GET),
            ]),
        ),
        (
            "overlap-seq-35-x-then-get",
            tcp80_seq(&[
                eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, GET_A),
                eth_ipv4_tcp_seq(OUTER, 50000, 80, 35, &overlap_past_nxtseq(35, INNER_GET)),
            ]),
        ),
        (
            "same-seq-truncated-prefix-extend-then-complete",
            tcp80_seq(&truncated_prefix_extend(b"GET / HTTP/1.1\r\nHost: ")),
        ),
        (
            "same-seq-prefix-extension",
            tcp80_seq(&[
                eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, GET_A),
                eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, &concat_bytes(GET_A, INNER_GET)),
            ]),
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
            "desegment-post-cl100-then-get",
            tcp80_seq(&{
                let post = b"POST / HTTP/1.1\r\nHost: post.example\r\nContent-Length: 100\r\n\r\n";
                vec![
                    eth_ipv4_tcp_seq(OUTER, 50000, 80, 1, post),
                    eth_ipv4_tcp_seq(OUTER, 50000, 80, 1 + post.len() as u32, INNER_GET),
                ]
            }),
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
            "trailing-cr-blank",
            tcp80(b"GET / HTTP/1.1\r\nHost: cr.example\r\n\r"),
        ),
        (
            "notify-leftover-get",
            tcp80(b"NOTIFY / HTTP/1.1\r\nHost: n.example\r\n\r\nGET / HTTP/1.1\r\nHost: inner.example\r\n\r\n"),
        ),
        (
            "notify-cl0-leftover-get",
            tcp80(b"NOTIFY / HTTP/1.1\r\nHost: n.example\r\nContent-Length: 0\r\n\r\nGET / HTTP/1.1\r\nHost: inner.example\r\n\r\n"),
        ),
        (
            "search-leftover-get",
            tcp80(b"SEARCH / HTTP/1.1\r\nHost: n.example\r\n\r\nGET / HTTP/1.1\r\nHost: inner.example\r\n\r\n"),
        ),
        (
            "http2-magic-then-get",
            http2_then_inner(HTTP2_MAGIC),
        ),
        (
            "http2-get-leftover-magic-then-get",
            http2_then_inner(&concat_bytes(GET_A, HTTP2_MAGIC)),
        ),
        (
            "http2-cl24-get-leftover-get",
            tcp80(&{
                let mut payload = b"GET / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 24\r\n\r\n".to_vec();
                payload.extend_from_slice(HTTP2_MAGIC);
                payload.extend_from_slice(INNER_GET);
                payload
            }),
        ),
        (
            "empty-syn-then-get-seq-0",
            tcp80_seq(&empty_syn_then_get(0x02, 0)),
        ),
        (
            "empty-syn-then-get-seq-1",
            tcp80_seq(&empty_syn_then_get(0x02, 1)),
        ),
        (
            "empty-syn-then-get-seq-2",
            tcp80_seq(&empty_syn_then_get(0x02, 2)),
        ),
        (
            "syn-get-then-seq-35",
            tcp80_seq(&syn_then_inner(0x02, 35)),
        ),
        (
            "syn-get-then-seq-36",
            tcp80_seq(&syn_then_inner(0x02, 36)),
        ),
        (
            "empty-syn-rst-then-get-seq-0",
            tcp80_seq(&empty_syn_then_get(0x06, 0)),
        ),
        (
            "empty-syn-rst-then-get-seq-1",
            tcp80_seq(&empty_syn_then_get(0x06, 1)),
        ),
        (
            "syn-rst-get-then-inner-seq-1",
            tcp80_seq(&syn_then_inner(0x06, 1)),
        ),
        (
            "prefix-extend-cut-1-then-inner",
            tcp80_seq(&truncated_suffix_then_inner(&INNER_GET[..1])),
        ),
        (
            "connect-22-200-then-get",
            pcap(
                LINK_ETHERNET,
                &req_resp_get(&connect_req("example.com:22"), SSTP_200, INNER_GET),
            ),
        ),
        (
            "connect-443-200-then-get",
            pcap(
                LINK_ETHERNET,
                &req_resp_get(&connect_req("example.com:443"), SSTP_200, INNER_GET),
            ),
        ),
        (
            "connect-noport-200-then-get",
            pcap(
                LINK_ETHERNET,
                &req_resp_get(&connect_req("example.com"), SSTP_200, INNER_GET),
            ),
        ),
        (
            "connect-22-200-leftover-get",
            pcap(
                LINK_ETHERNET,
                &[
                    eth_ipv4_tcp_to(OUTER, PEER, 50000, 80, 1, &connect_req("example.com:22")),
                    eth_ipv4_tcp_to(
                        PEER,
                        OUTER,
                        80,
                        50000,
                        1,
                        &concat_bytes(SSTP_200, INNER_GET),
                    ),
                ],
            ),
        ),
        (
            "junk-header-then-get",
            tcp80(&junk_then_inner(JUNK)),
        ),
        (
            "junk-colon-value-then-get",
            tcp80(&junk_then_inner(
                b"GET / HTTP/1.1\r\nHost: a.example\r\n:value\r\n\r\n",
            )),
        ),
        (
            "junk-header-no-blank",
            tcp80(b"GET / HTTP/1.1\r\nHost: fuzz.example\r\nnot-a-header\r\n"),
        ),
        (
            "junk-later-cl4-get-nobody",
            tcp80(b"GET / HTTP/1.1\r\nHost: a.example\r\nnot-a-header\r\nContent-Length: 4\r\n\r\n"),
        ),
        (
            "junk-later-chunked-0-then-get",
            tcp80(&junk_then_inner(
                b"POST / HTTP/1.1\r\nHost: a.example\r\nnot-a-header\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            )),
        ),
        (
            "junk-later-cl4-body-then-get",
            tcp80(&junk_then_inner(
                b"POST / HTTP/1.1\r\nHost: a.example\r\nnot-a-header\r\nContent-Length: 4\r\n\r\nxxxx",
            )),
        ),
        (
            "junk-cl4-200-blank-body-then-get",
            tcp80(&{
                let mut payload =
                    b"HTTP/1.1 200 OK\r\nHost: a.example\r\nContent-Length: 4\r\nnot-a-header\r\n\r\nxxxx"
                        .to_vec();
                payload.extend_from_slice(INNER_GET);
                payload
            }),
        ),
        (
            "junk-later-cl100-post-then-get",
            tcp80(&junk_then_inner(
                b"POST / HTTP/1.1\r\nHost: a.example\r\nnot-a-header\r\nContent-Length: 100\r\n\r\n",
            )),
        ),
        (
            "get-then-notify",
            tcp80(&concat_bytes(
                GET_A,
                b"NOTIFY / HTTP/1.1\r\nHost: n.example\r\n\r\n",
            )),
        ),
        (
            "get-then-subscribe",
            tcp80(&concat_bytes(
                GET_A,
                b"SUBSCRIBE / HTTP/1.1\r\nHost: n.example\r\n\r\n",
            )),
        ),
        (
            "get-then-unsubscribe",
            tcp80(&concat_bytes(
                GET_A,
                b"UNSUBSCRIBE / HTTP/1.1\r\nHost: n.example\r\n\r\n",
            )),
        ),
        (
            "get-then-m-notify",
            tcp80(&concat_bytes(
                GET_A,
                b"M-NOTIFY / HTTP/1.1\r\nHost: n.example\r\n\r\n",
            )),
        ),
        (
            "get-then-search",
            tcp80(&concat_bytes(
                GET_A,
                b"SEARCH / HTTP/1.1\r\nHost: n.example\r\n\r\n",
            )),
        ),
        (
            "get-then-propfind",
            tcp80(&concat_bytes(
                GET_A,
                b"PROPFIND / HTTP/1.1\r\nHost: n.example\r\n\r\n",
            )),
        ),
        (
            "get-then-trace",
            tcp80(&concat_bytes(
                GET_A,
                b"TRACE / HTTP/1.1\r\nHost: n.example\r\n\r\n",
            )),
        ),
        (
            "options-then-notify",
            tcp80(b"OPTIONS * HTTP/1.1\r\nHost: a.example\r\n\r\nNOTIFY / HTTP/1.1\r\nHost: n.example\r\n\r\n"),
        ),
        (
            "post-cl0-then-notify",
            tcp80(b"POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 0\r\n\r\nNOTIFY / HTTP/1.1\r\nHost: n.example\r\n\r\n"),
        ),
        (
            "get-then-no-colon",
            tcp80(&concat_bytes(
                GET_A,
                b"GET / HTTP/1.1\r\nHost: b.example\r\nnot-a-header\r\n\r\n",
            )),
        ),
        (
            "get-then-204-cl0",
            tcp80(&concat_bytes(
                GET_A,
                b"HTTP/1.1 204 No Content\r\nHost: b.example\r\nContent-Length: 0\r\n\r\n",
            )),
        ),
        (
            "get-then-304-cl0",
            tcp80(&concat_bytes(
                GET_A,
                b"HTTP/1.1 304 Not Modified\r\nHost: b.example\r\nContent-Length: 0\r\n\r\n",
            )),
        ),
        (
            "get-then-100-cl0",
            tcp80(&concat_bytes(
                GET_A,
                b"HTTP/1.1 100 Continue\r\nHost: b.example\r\nContent-Length: 0\r\n\r\n",
            )),
        ),
        (
            "get-then-204-cl4-body",
            tcp80(&concat_bytes(
                GET_A,
                b"HTTP/1.1 204 No Content\r\nHost: b.example\r\nContent-Length: 4\r\n\r\nxxxx",
            )),
        ),
        (
            "get-then-unreadable-cl-then-get",
            tcp80(&concat_bytes(
                GET_A,
                b"POST / HTTP/1.1\r\nHost: cl.example\r\nContent-Length: 4\x0b\r\n\r\nGET / HTTP/1.1\r\nHost: inner.example\r\n\r\n",
            )),
        ),
        (
            "get-then-rpc-in-data",
            tcp80(&concat_bytes(
                GET_A,
                b"RPC_IN_DATA / HTTP/1.1\r\nHost: rpc.example\r\n\r\n",
            )),
        ),
        (
            "get-then-rpc-out-data",
            tcp80(&concat_bytes(
                GET_A,
                b"RPC_OUT_DATA / HTTP/1.1\r\nHost: rpc.example\r\n\r\n",
            )),
        ),
        (
            "get-then-rpc-connect",
            tcp80(&concat_bytes(
                GET_A,
                b"RPC_CONNECT / HTTP/1.1\r\nHost: rpc.example\r\n\r\n",
            )),
        ),
        (
            "two-gets-then-rpc-in-data",
            tcp80(&concat_bytes(
                GET_A,
                b"GET / HTTP/1.1\r\nHost: b.example\r\n\r\nRPC_IN_DATA / HTTP/1.1\r\nHost: rpc.example\r\n\r\n",
            )),
        ),
        (
            "get-then-rpc-then-get",
            tcp80(&concat_bytes(
                GET_A,
                b"RPC_IN_DATA / HTTP/1.1\r\nHost: rpc.example\r\n\r\nGET / HTTP/1.1\r\nHost: inner.example\r\n\r\n",
            )),
        ),
        (
            "204-no-cl-then-rpc-in-data",
            tcp80(
                b"HTTP/1.1 204 No Content\r\nHost: a.example\r\n\r\nRPC_IN_DATA / HTTP/1.1\r\nHost: rpc.example\r\n\r\n",
            ),
        ),
        (
            "get-no-host-then-rpc-in-data",
            tcp80(
                b"GET / HTTP/1.1\r\nUser-Agent: x\r\n\r\nRPC_IN_DATA / HTTP/1.1\r\nHost: rpc.example\r\n\r\n",
            ),
        ),
        (
            "get-then-mid-header-get",
            tcp80(&concat_bytes(
                GET_A,
                b"GET / HTTP/1.1\r\nHost: b.example\r\nGET / HTTP/1.1\r\nHost: inner.example\r\n\r\n",
            )),
        ),
        (
            "get-then-mid-header-post",
            tcp80(&concat_bytes(
                GET_A,
                b"GET / HTTP/1.1\r\nHost: b.example\r\nPOST / HTTP/1.1\r\nHost: inner.example\r\n\r\n",
            )),
        ),
        (
            "get-then-mid-header-200",
            tcp80(&concat_bytes(
                GET_A,
                b"GET / HTTP/1.1\r\nHost: b.example\r\nHTTP/1.1 200 OK\r\nHost: inner.example\r\n\r\n",
            )),
        ),
        (
            "get-then-mid-header-icy",
            tcp80(&concat_bytes(
                GET_A,
                b"GET / HTTP/1.1\r\nHost: b.example\r\nICY 200\r\nHost: inner.example\r\n\r\n",
            )),
        ),
        (
            "options-then-mid-header-get",
            tcp80(b"OPTIONS * HTTP/1.1\r\nHost: a.example\r\n\r\nGET / HTTP/1.1\r\nHost: b.example\r\nGET / HTTP/1.1\r\nHost: inner.example\r\n\r\n"),
        ),
        (
            "post-cl0-then-mid-header-get",
            tcp80(b"POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 0\r\n\r\nGET / HTTP/1.1\r\nHost: b.example\r\nGET / HTTP/1.1\r\nHost: inner.example\r\n\r\n"),
        ),
        (
            "get-no-host-then-mid-header-get",
            tcp80(
                b"GET / HTTP/1.1\r\nUser-Agent: x\r\n\r\nGET / HTTP/1.1\r\nHost: b.example\r\nGET / HTTP/1.1\r\nHost: inner.example\r\n\r\n",
            ),
        ),
        (
            "get-then-short-post",
            tcp80(&concat_bytes(
                GET_A,
                b"POST / HTTP/1.1\r\nHost: b.example\r\nContent-Length: 100\r\n\r\nno",
            )),
        ),
        (
            "head-then-200-get",
            tcp80(&concat_bytes(
                b"HEAD / HTTP/1.1\r\nHost: h.example\r\n\r\n",
                b"HTTP/1.1 200 OK\r\nHost: r.example\r\n\r\nGET / HTTP/1.1\r\nHost: inner.example\r\n\r\n",
            )),
        ),
        (
            "head-then-200-cl100-no",
            tcp80(&concat_bytes(
                b"HEAD / HTTP/1.1\r\nHost: h.example\r\n\r\n",
                b"HTTP/1.1 200 OK\r\nHost: r.example\r\nContent-Length: 100\r\n\r\nno",
            )),
        ),
        (
            "head-then-200-cl100-get",
            tcp80(&concat_bytes(
                b"HEAD / HTTP/1.1\r\nHost: h.example\r\n\r\n",
                b"HTTP/1.1 200 OK\r\nHost: r.example\r\nContent-Length: 100\r\n\r\nGET / HTTP/1.1\r\nHost: inner.example\r\n\r\n",
            )),
        ),
        (
            "get-then-head-then-200",
            tcp80(&concat_bytes(
                GET_A,
                b"HEAD / HTTP/1.1\r\nHost: h.example\r\n\r\nHTTP/1.1 200 OK\r\nHost: r.example\r\n\r\nGET / HTTP/1.1\r\nHost: inner.example\r\n\r\n",
            )),
        ),
        (
            "head-no-host-then-200",
            tcp80(
                b"HEAD / HTTP/1.1\r\nUser-Agent: x\r\n\r\nHTTP/1.1 200 OK\r\nHost: r.example\r\n\r\nGET / HTTP/1.1\r\nHost: inner.example\r\n\r\n",
            ),
        ),
        (
            "head-then-200-cl0-get",
            tcp80(&concat_bytes(
                b"HEAD / HTTP/1.1\r\nHost: h.example\r\n\r\n",
                b"HTTP/1.1 200 OK\r\nHost: r.example\r\nContent-Length: 0\r\n\r\nGET / HTTP/1.1\r\nHost: inner.example\r\n\r\n",
            )),
        ),
        (
            "get-then-leftover-host",
            tcp80(&concat_bytes(GET_A, b"Host: n.example\r\n\r\n")),
        ),
        (
            "get-then-leftover-x-foo-host",
            tcp80(&concat_bytes(
                GET_A,
                b"X-Foo: bar\r\nHost: n.example\r\n\r\n",
            )),
        ),
        (
            "get-then-leftover-foo-bar-host",
            tcp80(&concat_bytes(
                GET_A,
                b"FOO:BAR / HTTP/1.1\r\nHost: n.example\r\n\r\n",
            )),
        ),
        (
            "options-then-leftover-host",
            tcp80(b"OPTIONS * HTTP/1.1\r\nHost: a.example\r\n\r\nHost: n.example\r\n\r\n"),
        ),
        (
            "post-cl0-then-leftover-host",
            tcp80(b"POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 0\r\n\r\nHost: n.example\r\n\r\n"),
        ),
        (
            "204-no-cl-then-leftover-host",
            tcp80(
                b"HTTP/1.1 204 No Content\r\nHost: a.example\r\n\r\nHost: n.example\r\n\r\n",
            ),
        ),
        (
            "get-then-compact-leftover-host",
            tcp80(&concat_bytes(GET_A, b"Host:n.example\r\n\r\n")),
        ),
        (
            "get-then-leftover-host-tab",
            tcp80(&concat_bytes(GET_A, b"Host:\tn.example\r\n\r\n")),
        ),
        (
            "get-then-compact-x-foo-host",
            tcp80(&concat_bytes(
                GET_A,
                b"X-Foo:bar\r\nHost: n.example\r\n\r\n",
            )),
        ),
        (
            "get-then-compact-foo-bar-host",
            tcp80(&concat_bytes(GET_A, b"FOO:BAR\r\nHost: n.example\r\n\r\n")),
        ),
        (
            "get-then-compact-cl4-get",
            tcp80(&concat_bytes(
                GET_A,
                b"Content-Length:4\r\n\r\nxxxxGET / HTTP/1.1\r\nHost: n.example\r\n\r\n",
            )),
        ),
        (
            "options-then-compact-leftover-host",
            tcp80(b"OPTIONS * HTTP/1.1\r\nHost: a.example\r\n\r\nHost:n.example\r\n\r\n"),
        ),
        (
            "post-cl0-then-compact-leftover-host",
            tcp80(b"POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 0\r\n\r\nHost:n.example\r\n\r\n"),
        ),
        (
            "204-no-cl-then-compact-leftover-host",
            tcp80(
                b"HTTP/1.1 204 No Content\r\nHost: a.example\r\n\r\nHost:n.example\r\n\r\n",
            ),
        ),
        (
            "head-then-compact-leftover-host",
            tcp80(&concat_bytes(
                b"HEAD / HTTP/1.1\r\nHost: h.example\r\n\r\n",
                b"Host:n.example\r\n\r\n",
            )),
        ),
        (
            "get-no-host-then-compact-leftover-host",
            tcp80(b"GET / HTTP/1.1\r\nUser-Agent: x\r\n\r\nHost:n.example\r\n\r\n"),
        ),
        (
            "get-then-not-a-header-then-host",
            tcp80(&concat_bytes(
                GET_A,
                b"not-a-header\r\nHost: n.example\r\n\r\n",
            )),
        ),
    ];
    for (suffix, file) in tcp_http_ports(&concat_bytes(
        GET_A,
        b"NOTIFY / HTTP/1.1\r\nHost: n.example\r\n\r\n",
    )) {
        out.push((
            match suffix {
                "8080" => "get-then-notify-8080",
                "3128" => "get-then-notify-3128",
                "src80" => "get-then-notify-src80",
                _ => "get-then-notify-ipv6",
            },
            file,
        ));
    }
    for (suffix, file) in tcp_http_ports(&concat_bytes(
        GET_A,
        b"GET / HTTP/1.1\r\nHost: b.example\r\nnot-a-header\r\n\r\n",
    )) {
        out.push((
            match suffix {
                "8080" => "get-then-no-colon-8080",
                "3128" => "get-then-no-colon-3128",
                "src80" => "get-then-no-colon-src80",
                _ => "get-then-no-colon-ipv6",
            },
            file,
        ));
    }
    for (suffix, file) in tcp_http_ports(&concat_bytes(
        GET_A,
        b"HTTP/1.1 204 No Content\r\nHost: b.example\r\nContent-Length: 0\r\n\r\n",
    )) {
        out.push((
            match suffix {
                "8080" => "get-then-204-cl0-8080",
                "3128" => "get-then-204-cl0-3128",
                "src80" => "get-then-204-cl0-src80",
                _ => "get-then-204-cl0-ipv6",
            },
            file,
        ));
    }
    for (suffix, file) in tcp_http_ports(&concat_bytes(
        GET_A,
        b"RPC_IN_DATA / HTTP/1.1\r\nHost: rpc.example\r\n\r\n",
    )) {
        out.push((
            match suffix {
                "8080" => "get-then-rpc-in-data-8080",
                "3128" => "get-then-rpc-in-data-3128",
                "src80" => "get-then-rpc-in-data-src80",
                _ => "get-then-rpc-in-data-ipv6",
            },
            file,
        ));
    }
    for (suffix, file) in tcp_http_ports(&concat_bytes(
        GET_A,
        b"GET / HTTP/1.1\r\nHost: b.example\r\nGET / HTTP/1.1\r\nHost: inner.example\r\n\r\n",
    )) {
        out.push((
            match suffix {
                "8080" => "get-then-mid-header-get-8080",
                "3128" => "get-then-mid-header-get-3128",
                "src80" => "get-then-mid-header-get-src80",
                _ => "get-then-mid-header-get-ipv6",
            },
            file,
        ));
    }
    for (suffix, file) in tcp_http_ports(&concat_bytes(
        b"HEAD / HTTP/1.1\r\nHost: h.example\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nHost: r.example\r\n\r\nGET / HTTP/1.1\r\nHost: inner.example\r\n\r\n",
    )) {
        out.push((
            match suffix {
                "8080" => "head-then-200-get-8080",
                "3128" => "head-then-200-get-3128",
                "src80" => "head-then-200-get-src80",
                _ => "head-then-200-get-ipv6",
            },
            file,
        ));
    }
    for (suffix, file) in tcp_http_ports(&concat_bytes(GET_A, b"Host: n.example\r\n\r\n")) {
        out.push((
            match suffix {
                "8080" => "get-then-leftover-host-8080",
                "3128" => "get-then-leftover-host-3128",
                "src80" => "get-then-leftover-host-src80",
                _ => "get-then-leftover-host-ipv6",
            },
            file,
        ));
    }
    for (suffix, file) in tcp_http_ports(&concat_bytes(GET_A, b"Host:n.example\r\n\r\n")) {
        out.push((
            match suffix {
                "8080" => "get-then-compact-leftover-host-8080",
                "3128" => "get-then-compact-leftover-host-3128",
                "src80" => "get-then-compact-leftover-host-src80",
                _ => "get-then-compact-leftover-host-ipv6",
            },
            file,
        ));
    }
    out.extend(on_disk());
    out.into_iter()
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
        [
            "-n",
            "-T",
            "fields",
            "-e",
            FIELD,
            "-o",
            "tcp.reassemble_out_of_order:TRUE",
        ]
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
