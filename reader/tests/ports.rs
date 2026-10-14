//! Live tshark 4.6.9 dump matches the checked-in port snapshot.

use std::env;
use std::io;
use std::path::PathBuf;
use std::process::Command;

use reader::ports::{checked_in_decodes, checked_in_heuristics};

#[test]
fn decodes_dump_matches_tshark_469() {
    let Some(tshark) = tshark_path() else {
        eprintln!("skip: tshark 4.6.9 is not installed");
        return;
    };
    if !version_ok(&tshark) {
        eprintln!("skip: tshark version is not 4.6.9");
        return;
    }
    let live = port_rows(&dump(&tshark, "decodes"));
    assert_eq!(normalize(&live), normalize(checked_in_decodes()));
}

#[test]
fn heuristic_dump_matches_tshark_469() {
    let Some(tshark) = tshark_path() else {
        eprintln!("skip: tshark 4.6.9 is not installed");
        return;
    };
    if !version_ok(&tshark) {
        eprintln!("skip: tshark version is not 4.6.9");
        return;
    }
    let live = udp_tcp_heuristics(&dump(&tshark, "heuristic-decodes"));
    assert_eq!(normalize(&live), normalize(checked_in_heuristics()));
}

fn dump(tshark: &PathBuf, report: &str) -> String {
    let output = Command::new(tshark)
        .args(["-G", report])
        .output()
        .unwrap_or_else(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                panic!("skip should have caught a missing tshark");
            }
            panic!("{error}");
        });
    assert!(output.status.success());
    String::from_utf8(output.stdout).expect("utf-8")
}

fn version_ok(tshark: &PathBuf) -> bool {
    let output = Command::new(tshark).arg("--version").output();
    match output {
        Ok(output) => String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .any(|token| token == "4.6.9"),
        Err(_) => false,
    }
}

fn port_rows(text: &str) -> String {
    text.lines()
        .filter(|line| line.starts_with("udp.port\t") || line.starts_with("tcp.port\t"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn udp_tcp_heuristics(text: &str) -> String {
    text.lines()
        .filter(|line| line.starts_with("udp\t") || line.starts_with("tcp\t"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn normalize(text: &str) -> String {
    let mut out = text.replace("\r\n", "\n").replace('\r', "\n");
    while out.ends_with('\n') {
        out.pop();
    }
    out.push('\n');
    out
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
