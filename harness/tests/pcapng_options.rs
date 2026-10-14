//! Differential check: malformed IDB/SHB/EPB options, fin vs tshark 4.6.9.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use harness::{RunError, TsharkSession};
use reader::read_capture;

const CASES: u32 = 512;

#[test]
fn malformed_idb_options_match_tshark_469() {
    let Some(tshark) = tshark_path() else {
        eprintln!("skip: tshark 4.6.9 is not installed");
        return;
    };
    let session = match TsharkSession::open(&tshark) {
        Ok(session) => session,
        Err(RunError::Version { found }) => {
            eprintln!("skip: tshark version is {found}");
            return;
        }
        Err(RunError::Spawn { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            eprintln!("skip: tshark 4.6.9 is not installed");
            return;
        }
        Err(error) => panic!("{error}"),
    };
    let dir = env::temp_dir().join(format!("fin-opt-fuzz-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();

    let mut mismatches = Vec::new();
    for (index, file) in cases().into_iter().enumerate() {
        if let Some(mismatch) = diff_one(&session, &dir, index, &file) {
            mismatches.push(mismatch);
            if mismatches.len() >= 8 {
                break;
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "tshark 4.6.9 mismatches:\n{}",
        mismatches.join("\n")
    );
}

fn cases() -> Vec<Vec<u8>> {
    let mut files = systematic();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..CASES {
        files.push(random_file(&mut rng));
    }
    files
}

fn systematic() -> Vec<Vec<u8>> {
    let mut files = Vec::new();
    files.push(capture(false, &[opt(9, &[9, 0])], true));
    files.push(capture(
        false,
        &[opt(
            14,
            &[0x10, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        )],
        true,
    ));
    let mut sixteen = Vec::from([0x0e, 0x00, 0x10, 0x00]);
    sixteen.extend_from_slice(&3600i64.to_le_bytes());
    sixteen.extend_from_slice(&7200i64.to_le_bytes());
    files.push(capture(false, &[sixteen], true));
    files.push(capture(
        true,
        &[Vec::from([0x09, 0x00, 0x64, 0x00, 0x09, 0x00, 0x00, 0x00])],
        true,
    ));
    files.push(capture(
        false,
        &[Vec::from([0x09, 0x00, 0x64, 0x00, 0x09, 0x00, 0x00, 0x00])],
        true,
    ));
    files.push(capture(true, &[opt(11, &[])], true));
    files.push(capture(false, &[opt(11, &[])], true));
    files.push(capture(
        false,
        &[opt(14, &(i64::MAX - 9).to_le_bytes())],
        true,
    ));
    files.push(capture(true, &[opt(9, &[20])], true));
    files.push(later_shb(false));
    files.push(later_shb(true));
    files.push(opening_shb_lengths());
    files.push(capture(false, &[opt(0, &[]), opt(9, &[9])], true));
    files.push(capture(false, &[opt(2988, &[])], true));
    files.push(capture(false, &[opt(2989, &[0, 0])], true));
    files.push(capture(false, &[opt(19372, &[0])], true));
    files.push(capture(true, &[opt(19373, &[0, 0, 0, 0])], true));
    files.push(epb_option(2, &[0, 0]));
    files.push(epb_option(3, &[]));
    files.push(epb_option(4, &[0, 0]));
    files.push(epb_option(7, &[1]));
    files.push(epb_option(8, &[0, 0]));
    files.push(extra_after_packet(9, &[]));
    files.push(extra_only(9, &[]));
    files.push(extra_after_packet(9, b"__REALTIME_TIMESTAMP=0\n\x00"));
    files.push(extra_solo(9, b"__REALTIME_TIMESTAMP=0\n\x00"));
    files.push(extra_after_packet(
        9,
        b"__REALTIME_TIMESTAMP=18446744073709551616\n",
    ));
    files.push(extra_after_packet(9, b"__REALTIME_TIMESTAMP= 1\nxxxx"));
    files.push(extra_after_packet(9, b"__REALTIME_TIMESTAMP=+1\nxxxx"));
    files.push(extra_after_packet(9, b"__REALTIME_TIMESTAMP=-1\nxxxx"));
    files.push(extra_after_packet(9, b"__REALTIME_TIMESTAMP= +1\nxxxx"));
    files.push(extra_after_packet(9, b"__REALTIME_TIMESTAMP= -1\nxxxx"));
    files.push(extra_after_packet(9, b"__REALTIME_TIMESTAMP= +1\nxx"));
    files.push(extra_after_packet(9, b"__REALTIME_TIMESTAMP= -1\nxx"));
    for space in [b' ', b'\t', b'\n', 0x0b, b'\x0c', b'\r'] {
        files.push(extra_after_packet(
            9,
            &journal_stamp(&[space, b'8', b'\n', b'x', b'x', b'x', b'x']),
        ));
        files.push(extra_after_packet(
            9,
            &journal_stamp(&[space, b'+', b'1', b'\n']),
        ));
        files.push(extra_after_packet(
            9,
            &journal_stamp(&[space, b'-', b'1', b'\n']),
        ));
    }
    files.push(extra_solo(9, &journal_stamp(b"\x0b8\nxxxx")));
    files.push(extra_after_packet(9, b"__REALTIME_TIMESTAMP=   +2\n"));
    files.push(extra_solo(9, b"FOO=bar\x00__REALTIME_TIMESTAMP=8\nxxxx"));
    files.push(extra_after_packet(
        9,
        b"FOO=bar\x00__REALTIME_TIMESTAMP=8\nxxxx",
    ));
    files.push(extra_solo(9, b"__REALTIME_TIMESTAMP=8\nxxxx\x00FOO=bar"));
    files.push(extra_solo(9, b"x__REALTIME_TIMESTAMP=8\nxxxx"));
    files.push(extra_solo(9, b"xx__REALTIME_TIMESTAMP="));
    files.push(extra_solo(9, b"__REALTIME_TIMESTAMP=0x10\nxxxx"));
    files.push(extra_after_packet(9, b"__REALTIME_TIMESTAMP=0"));
    files.push(epb_journal_custom(
        1_500_000,
        b"FOO=bar\x00__REALTIME_TIMESTAMP=8\nxxxx",
    ));
    files.push(extra_after_packet(0x0000_0BAD, &1u32.to_le_bytes()));
    files.push(extra_after_packet(0x0000_0BAD, &[]));
    files.push(extra_only(0x0000_0BAD, &[]));
    files.push(extra_solo(0x0000_0BAD, &1u32.to_le_bytes()));
    files.push(extra_after_packet(0x4000_0BAD, &1u32.to_le_bytes()));
    files.push(extra_after_packet(0x4000_0BAD, &[]));
    files.push(extra_after_packet(10, &[]));
    files.push(extra_after_packet(7, &[]));
    files.push(extra_after_packet(11, &[]));
    let mut isb = Vec::from([0u8; 12]);
    isb.extend_from_slice(&opt(2988, &[]));
    files.push(extra_after_packet(5, &isb));
    files.push(extra_only(5, &isb));
    let mut nrb = Vec::from([0u8; 4]);
    nrb.extend_from_slice(&opt(2988, &[]));
    files.push(extra_after_packet(4, &nrb));
    files.push(extra_after_packet(
        4,
        &[1, 0, 2, 0, 0xaa, 0xbb, 0x00, 0x00, 0, 0, 0, 0],
    ));
    files.push(epb_trailer(36, 35));
    files.push(epb_trailer(36, 33));
    files.push(epb_trailer(36, 32));
    files.push(later_epb_trailer(36, 35));
    files.push(later_unaligned_trailer());
    files.push(huge_later());
    files.push(opening_shb_totals(27, 27));
    files.push(opening_shb_totals(28, 27));
    files.push(opening_shb_padded(29, 32, 4));
    files.push(later_shb_totals(27, 27));
    for length in [0u16, 1, 2, 4, 8, 9, 16] {
        files.push(capture(false, &[raw_opt(9, length, &[9])], true));
        files.push(capture(
            false,
            &[raw_opt(14, length, &3600i64.to_le_bytes())],
            true,
        ));
        files.push(capture(true, &[raw_opt(11, length, &[0])], true));
    }
    files
}

fn random_file(rng: &mut Rng) -> Vec<u8> {
    if rng.bounded(3) == 0 {
        return random_extra(rng);
    }
    let prior = rng.bit();
    let mut options = Vec::new();
    let count = rng.bounded(4) + 1;
    for _ in 0..count {
        options.push(random_option(rng));
    }
    capture(prior, &options, rng.bit())
}

fn random_option(rng: &mut Rng) -> Vec<u8> {
    let code = if rng.bounded(8) == 0 {
        [2988, 2989, 19372, 19373][rng.bounded(4) as usize]
    } else {
        rng.bounded(20)
    };
    let length = if rng.bounded(10) == 0 {
        100
    } else {
        rng.bounded(17)
    };
    let mut value = vec![0u8; usize::from(length.min(24))];
    for byte in &mut value {
        *byte = rng.bounded(256) as u8;
    }
    raw_opt(code, length, &value)
}

fn random_extra(rng: &mut Rng) -> Vec<u8> {
    let types = [4u32, 5, 7, 9, 10, 11, 0x0000_0BAD, 0x4000_0BAD, 100];
    let block_type = types[rng.bounded(types.len() as u16) as usize];
    extra(rng.bit(), block_type, &random_extra_body(rng, block_type))
}

fn random_extra_body(rng: &mut Rng, block_type: u32) -> Vec<u8> {
    match block_type {
        9 => match rng.bounded(11) {
            0 => b"__REALTIME_TIMESTAMP=0\n".to_vec(),
            1 => b"__REALTIME_TIMESTAMP=18446744073709551616\n".to_vec(),
            2 => b"__REALTIME_TIMESTAMP= 1\nxxxx".to_vec(),
            3 => b"__REALTIME_TIMESTAMP=+1\nxxxx".to_vec(),
            4 => b"__REALTIME_TIMESTAMP=-1\nxxxx".to_vec(),
            5 => b"__REALTIME_TIMESTAMP= +1\nxxxx".to_vec(),
            6 => b"__REALTIME_TIMESTAMP= -1\nxxxx".to_vec(),
            7 => {
                let spaces = [b' ', b'\t', b'\n', b'\r', 0x0b, 0x0c];
                journal_stamp(&[
                    spaces[rng.bounded(6) as usize],
                    if rng.bit() { b'+' } else { b'-' },
                    b'1',
                    b'\n',
                ])
            }
            8 => b"FOO=bar\x00__REALTIME_TIMESTAMP=8\nxxxx".to_vec(),
            9 => b"x__REALTIME_TIMESTAMP=8\nxxxx".to_vec(),
            _ => vec![0; rng.bounded(8) as usize],
        },
        0x0000_0BAD | 0x4000_0BAD if rng.bit() => 1u32.to_le_bytes().to_vec(),
        5 => {
            let mut body = vec![0u8; 12];
            if rng.bit() {
                body.extend_from_slice(&random_option(rng));
            }
            body
        }
        4 => {
            let mut body = vec![0, 0, 0, 0];
            if rng.bit() {
                body.extend_from_slice(&random_option(rng));
            }
            body
        }
        10 if rng.bit() => vec![0u8; 8],
        _ => vec![0; rng.bounded(8) as usize],
    }
}

fn capture(prior_packet: bool, idb_options: &[Vec<u8>], trailing_packet: bool) -> Vec<u8> {
    let mut file = shb(1, 0);
    if prior_packet {
        file.extend_from_slice(&idb(&[]));
        file.extend_from_slice(&epb(0, 0, &[0x01], &[]));
    }
    let mut options = Vec::new();
    for option in idb_options {
        options.extend_from_slice(option);
    }
    file.extend_from_slice(&idb(&options));
    if trailing_packet {
        let iface = if prior_packet { 1 } else { 0 };
        file.extend_from_slice(&epb(iface, 20_000_000, &[0x02], &[]));
    }
    file
}

fn later_shb(prior_packet: bool) -> Vec<u8> {
    let mut file = shb(1, 0);
    file.extend_from_slice(&idb(&[]));
    if prior_packet {
        file.extend_from_slice(&epb(0, 0, &[0x01], &[]));
    }
    file.extend_from_slice(&shb(1, 1));
    file.extend_from_slice(&idb(&[]));
    file.extend_from_slice(&epb(0, 0, &[0xaa], &[]));
    file
}

fn opening_shb_lengths() -> Vec<u8> {
    let mut header = shb(1, 0);
    header[24..28].copy_from_slice(&32u32.to_le_bytes());
    header
}

fn epb_option(code: u16, value: &[u8]) -> Vec<u8> {
    let mut file = shb(1, 0);
    file.extend_from_slice(&idb(&[]));
    file.extend_from_slice(&epb(0, 0, &[0xaa], &opt(code, value)));
    file
}

fn journal_stamp(after_eq: &[u8]) -> Vec<u8> {
    let mut entry = b"__REALTIME_TIMESTAMP=".to_vec();
    entry.extend_from_slice(after_eq);
    entry
}

fn extra_after_packet(block_type: u32, body: &[u8]) -> Vec<u8> {
    extra(true, block_type, body)
}

fn extra_only(block_type: u32, body: &[u8]) -> Vec<u8> {
    extra(false, block_type, body)
}

fn extra_solo(block_type: u32, body: &[u8]) -> Vec<u8> {
    let mut file = shb(1, 0);
    file.extend_from_slice(&block(block_type, body));
    file
}

fn extra(prior_packet: bool, block_type: u32, body: &[u8]) -> Vec<u8> {
    let mut file = shb(1, 0);
    file.extend_from_slice(&idb(&[]));
    if prior_packet {
        file.extend_from_slice(&epb(0, 0, &[0x01], &[]));
    }
    file.extend_from_slice(&block(block_type, body));
    file.extend_from_slice(&epb(0, 0, &[0x02], &[]));
    file
}

fn epb_journal_custom(ticks: u64, entry: &[u8]) -> Vec<u8> {
    let mut file = shb(1, 0);
    file.extend_from_slice(&idb(&[]));
    file.extend_from_slice(&epb(0, ticks, &[0x01], &[]));
    file.extend_from_slice(&block(9, entry));
    file.extend_from_slice(&block(0x0000_0BAD, &1u32.to_le_bytes()));
    file
}

fn epb_trailer(first: u32, second: u32) -> Vec<u8> {
    epb_trailer_file(false, first, second)
}

fn later_epb_trailer(first: u32, second: u32) -> Vec<u8> {
    epb_trailer_file(true, first, second)
}

fn epb_trailer_file(prior_packet: bool, first: u32, second: u32) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&1u32.to_le_bytes());
    body.extend_from_slice(&1u32.to_le_bytes());
    body.extend_from_slice(&[0xaa, 0, 0, 0]);
    let mut file = shb(1, 0);
    file.extend_from_slice(&idb(&[]));
    if prior_packet {
        file.extend_from_slice(&epb(0, 0, &[0x01], &[]));
    }
    file.extend_from_slice(&block_with_totals(6, &body, first, second));
    file
}

fn opening_shb_totals(first: u32, second: u32) -> Vec<u8> {
    opening_shb_padded(first, second, 0)
}

fn opening_shb_padded(first: u32, second: u32, pad: usize) -> Vec<u8> {
    let mut file = shb_padded(first, second, pad);
    file.extend_from_slice(&idb(&[]));
    file.extend_from_slice(&epb(0, 0, &[0xaa], &[]));
    file
}

fn later_shb_totals(first: u32, second: u32) -> Vec<u8> {
    let mut file = shb(1, 0);
    file.extend_from_slice(&idb(&[]));
    file.extend_from_slice(&epb(0, 0, &[0x01], &[]));
    file.extend_from_slice(&shb_padded(first, second, 0));
    file.extend_from_slice(&idb(&[]));
    file.extend_from_slice(&epb(0, 0, &[0xaa], &[]));
    file
}

fn shb_padded(first: u32, second: u32, pad: usize) -> Vec<u8> {
    let mut header = shb(1, 0);
    let trailer = header.split_off(header.len() - 4);
    header.extend_from_slice(&vec![0u8; pad]);
    header.extend_from_slice(&trailer);
    header[4..8].copy_from_slice(&first.to_le_bytes());
    let end = header.len();
    header[end - 4..end].copy_from_slice(&second.to_le_bytes());
    header
}

fn later_unaligned_trailer() -> Vec<u8> {
    let mut file = shb(1, 0);
    file.extend_from_slice(&idb(&[]));
    file.extend_from_slice(&epb(0, 0, &[0x01], &[]));
    file.extend_from_slice(&block_with_totals(100, &[0, 0, 0, 0], 13, 16));
    file
}

fn huge_later() -> Vec<u8> {
    let mut file = shb(1, 0);
    file.extend_from_slice(&idb(&[]));
    file.extend_from_slice(&epb(0, 0, &[0x01], &[]));
    file.extend_from_slice(&100u32.to_le_bytes());
    file.extend_from_slice(&200_000_000u32.to_le_bytes());
    file
}

fn block_with_totals(block_type: u32, body: &[u8], first: u32, second: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&block_type.to_le_bytes());
    out.extend_from_slice(&first.to_le_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(&second.to_le_bytes());
    out
}

fn diff_one(session: &TsharkSession, dir: &Path, index: usize, bytes: &[u8]) -> Option<String> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let path = dir.join(format!(
        "c{}-{}.pcapng",
        index,
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&path, bytes).unwrap();
    let args = [
        OsString::from("-n"),
        OsString::from("-r"),
        path.as_os_str().to_os_string(),
        OsString::from("-T"),
        OsString::from("fields"),
        OsString::from("-e"),
        OsString::from("frame.number"),
        OsString::from("-e"),
        OsString::from("frame.cap_len"),
    ];
    let tshark = session.run(&args).unwrap();
    let capture = read_capture(bytes);
    let fin_stdout = fin_rows(&capture);
    let fin_exit = capture.exit_code();
    let mut problems = Vec::new();
    let tshark_stdout = tshark.stdout.replace('\r', "");
    if tshark_stdout != fin_stdout {
        problems.push(format!(
            "stdout tshark={:?} fin={:?}",
            tshark.stdout, fin_stdout
        ));
    }
    if tshark.exit_code != fin_exit {
        problems.push(format!("exit tshark={} fin={}", tshark.exit_code, fin_exit));
    }
    match &capture.fault {
        Some(fault) => {
            let phrase = fault.phrase();
            if !tshark.stderr.contains(&phrase) {
                problems.push(format!(
                    "phrase {:?} missing from tshark stderr {:?}",
                    phrase, tshark.stderr
                ));
            }
        }
        None => {
            if tshark.exit_code != 0 {
                problems.push(format!(
                    "fin had no fault, tshark exit {} stderr {:?}",
                    tshark.exit_code, tshark.stderr
                ));
            }
        }
    }
    if problems.is_empty() {
        None
    } else {
        Some(format!(
            "case {index} ({} bytes): {}",
            bytes.len(),
            problems.join("; ")
        ))
    }
}

fn fin_rows(capture: &reader::Capture<'_>) -> String {
    let mut out = String::new();
    for (index, frame) in capture.frames.iter().enumerate() {
        out.push_str(&format!("{}\t{}\n", index + 1, frame.captured.len()));
    }
    out
}

fn shb(major: u16, minor: u16) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x1A2B3C4Du32.to_le_bytes());
    body.extend_from_slice(&major.to_le_bytes());
    body.extend_from_slice(&minor.to_le_bytes());
    body.extend_from_slice(&(-1i64).to_le_bytes());
    block_raw(0x0A0D0D0A, &body)
}

fn idb(options: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&65535u32.to_le_bytes());
    body.extend_from_slice(options);
    block(1, &body)
}

fn epb(iface: u32, ticks: u64, packet: &[u8], options: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&iface.to_le_bytes());
    body.extend_from_slice(&(ticks >> 32).to_le_bytes()[..4]);
    body.extend_from_slice(&(ticks as u32).to_le_bytes());
    body.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    body.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    body.extend_from_slice(&pad4(packet));
    body.extend_from_slice(options);
    block(6, &body)
}

fn block(block_type: u32, body: &[u8]) -> Vec<u8> {
    block_raw(block_type, &pad4(body))
}

fn block_raw(block_type: u32, body: &[u8]) -> Vec<u8> {
    let total = (12 + body.len()) as u32;
    let mut out = Vec::new();
    out.extend_from_slice(&block_type.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(&total.to_le_bytes());
    out
}

fn opt(code: u16, value: &[u8]) -> Vec<u8> {
    raw_opt(code, value.len() as u16, value)
}

fn raw_opt(code: u16, length: u16, value: &[u8]) -> Vec<u8> {
    let mut raw = Vec::new();
    raw.extend_from_slice(&code.to_le_bytes());
    raw.extend_from_slice(&length.to_le_bytes());
    let take = usize::from(length).min(value.len());
    raw.extend_from_slice(&value[..take]);
    while raw.len() - 4 < usize::from(length) {
        raw.push(0);
    }
    pad4(&raw)
}

fn pad4(bytes: &[u8]) -> Vec<u8> {
    let mut padded = bytes.to_vec();
    while padded.len() % 4 != 0 {
        padded.push(0);
    }
    padded
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
