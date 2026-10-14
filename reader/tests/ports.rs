//! Live tshark 4.6.9 dump matches the checked-in port snapshot.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use reader::ports::{checked_in_decodes, checked_in_heuristics, is_pinned_name};

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
    let live = first_wins(&port_rows(&dump(&tshark, "decodes")));
    let pinned = first_wins(checked_in_decodes());
    let mut mismatches = Vec::new();
    for (key, name) in live.iter().chain(pinned.iter()) {
        if !is_pinned_name(name) {
            continue;
        }
        if live.get(key) != pinned.get(key) {
            mismatches.push(format!(
                "{}.port {} live={:?} dump={:?}",
                key.0,
                key.1,
                live.get(key),
                pinned.get(key)
            ));
        }
    }
    mismatches.sort();
    mismatches.dedup();
    assert!(
        mismatches.is_empty(),
        "pinned port names differ from tshark 4.6.9:\n{}",
        mismatches.join("\n")
    );
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
        .env("WIRESHARK_CONFIG_DIR", empty_config_dir())
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
    let output = Command::new(tshark)
        .arg("--version")
        .env("WIRESHARK_CONFIG_DIR", empty_config_dir())
        .output();
    match output {
        Ok(output) => String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .any(|token| token == "4.6.9"),
        Err(_) => false,
    }
}

fn empty_config_dir() -> PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let path = env::temp_dir().join(format!("fin-tshark-ports-{}", std::process::id()));
        fs::create_dir_all(&path).expect("empty tshark config dir");
        path
    })
    .clone()
}

fn first_wins(text: &str) -> BTreeMap<(String, u16), String> {
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let mut cols = line.split('\t');
        let Some(table) = cols.next() else { continue };
        let Some(key) = cols.next() else { continue };
        let Some(name) = cols.next() else { continue };
        let proto = match table {
            "udp.port" => "udp",
            "tcp.port" => "tcp",
            _ => continue,
        };
        let Ok(port) = key.parse::<u16>() else {
            continue;
        };
        map.entry((proto.to_string(), port))
            .or_insert_with(|| name.to_string());
    }
    map
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
