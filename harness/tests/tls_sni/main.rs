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
    ]
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
