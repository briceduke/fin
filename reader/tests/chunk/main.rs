//! Chunked reader equals [`reader::read_capture`] on frames and faults.

use std::fs;
use std::path::PathBuf;

use reader::{read_capture, read_capture_chunked, read_capture_seams, Capture};

mod build;
use build::*;

const THREADS: &[usize] = &[1, 2, 8];

fn is_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    let start = haystack.as_ptr() as usize;
    let needle_start = needle.as_ptr() as usize;
    needle_start >= start && needle_start + needle.len() <= start + haystack.len()
}

fn assert_same(bytes: &[u8], left: &Capture<'_>, right: &Capture<'_>, label: &str) {
    assert_eq!(left.fault, right.fault, "{label} fault");
    assert_eq!(left.exit_code(), right.exit_code(), "{label} exit");
    assert_eq!(left.frames.len(), right.frames.len(), "{label} frames");
    for (index, (a, b)) in left.frames.iter().zip(&right.frames).enumerate() {
        assert_eq!(a.link_type, b.link_type, "{label} frame {index} link");
        assert_eq!(a.captured, b.captured, "{label} frame {index} bytes");
        assert!(
            is_subslice(bytes, a.captured),
            "{label} frame {index} not a subslice"
        );
    }
}

fn assert_chunked_matches(bytes: &[u8], label: &str) {
    let sequential = read_capture(bytes);
    for &threads in THREADS {
        let chunked = read_capture_chunked(bytes, threads);
        assert_same(
            bytes,
            &sequential,
            &chunked,
            &format!("{label} threads={threads}"),
        );
    }
}

fn corpus() -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    for (name, magic) in [
        ("le-usec", LE_USEC),
        ("be-usec", BE_USEC),
        ("le-nsec", LE_NSEC),
        ("be-nsec", BE_NSEC),
    ] {
        files.push((format!("{name}-0"), pcap_file(magic, &[])));
        files.push((format!("{name}-2"), pcap_file(magic, &[&[0x11], &[0x22]])));
        files.push((format!("{name}-32"), many_pcap_with(magic, 32)));
    }
    files.push(("pcapng-le-2".into(), many_pcapng(Endian::Little, 2)));
    files.push(("pcapng-le-32".into(), many_pcapng(Endian::Little, 32)));
    files.push(("pcapng-be-8".into(), many_pcapng(Endian::Big, 8)));
    if let Some(on_disk) = on_disk_corpus() {
        files.extend(on_disk);
    }
    files
}

fn on_disk_corpus() -> Option<Vec<(String, Vec<u8>)>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../study/corpus");
    let named = [
        ("corpus-eth-100", root.join("eth-ipv4-udp-100.pcap")),
        ("corpus-qinq-100", root.join("eth-qinq-ipv4-udp-100.pcap")),
        ("corpus-mixed-100", root.join("mixed-100.pcap")),
        (
            "challenge01",
            root.join("real/challenge01_ooo_stream.pcapng"),
        ),
        ("vxlan-public", root.join("real/vxlan.pcap")),
    ];
    let mut out = Vec::new();
    for (name, path) in named {
        if let Ok(bytes) = fs::read(&path) {
            out.push((name.to_string(), bytes));
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

#[test]
fn chunked_frames_match_sequential_on_corpus() {
    for (name, bytes) in corpus() {
        assert_chunked_matches(&bytes, &name);
    }
}

#[test]
fn awkward_pcap_seams_match_sequential() {
    let pcap = many_pcap(12);
    let packet = eth_ipv4_udp([10, 0, 0, 1], 1);
    let rec = 24 + 16 + packet.len();
    let seams = [
        vec![10],
        vec![24],
        vec![32],
        vec![24 + 8],
        vec![24 + 16 + 10],
        vec![rec],
        vec![rec + 3],
        vec![rec + 16 + 4],
        vec![10, 32, rec, rec + 20],
    ];
    for seams in &seams {
        let sequential = read_capture(&pcap);
        let (chunked, _) = read_capture_seams(&pcap, seams);
        assert_same(
            &pcap,
            &sequential,
            &chunked,
            &format!("pcap seams {seams:?}"),
        );
    }
}

fn fake_pcap_records(count: usize) -> Vec<u8> {
    let mut body = Vec::new();
    for i in 0..count {
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&1u32.to_le_bytes());
        body.push(0xA0 + i as u8);
    }
    body
}

#[test]
fn adversarial_pcap_payload_falls_back_and_keeps_frames() {
    let fake = fake_pcap_records(8);
    let mut real = Vec::from([0u8; 14]);
    real[12] = 0x08;
    real[13] = 0x00;
    real.extend_from_slice(&fake);
    let bytes = pcap_file(LE_USEC, &[&real, &[0x99]]);
    let fake_at = 24 + 16 + 14;
    let sequential = read_capture(&bytes);
    let (chunked, fallback) = read_capture_seams(&bytes, &[fake_at]);
    assert_same(&bytes, &sequential, &chunked, "adversarial pcap");
    assert!(
        fallback,
        "fake pcap records in payload must not prove a seam"
    );
    assert_eq!(sequential.frames.len(), 2);
    assert_ne!(
        sequential.frames[0].captured,
        &fake[..1],
        "must not emit the inner fake packet"
    );
}

#[test]
fn pcap_faults_match_sequential() {
    let mut truncated = pcap_header(LE_USEC, 1);
    truncated.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 0x11, 0x22]);
    let mut too_big = pcap_header(LE_USEC, 1);
    too_big.extend_from_slice(&1u32.to_le_bytes());
    too_big.extend_from_slice(&0u32.to_le_bytes());
    too_big.extend_from_slice(&262_145u32.to_le_bytes());
    too_big.extend_from_slice(&262_145u32.to_le_bytes());
    let mut later_too_big = pcap_file(LE_USEC, &[&[0xee]]);
    later_too_big.extend_from_slice(&1u32.to_le_bytes());
    later_too_big.extend_from_slice(&0u32.to_le_bytes());
    later_too_big.extend_from_slice(&262_145u32.to_le_bytes());
    later_too_big.extend_from_slice(&262_145u32.to_le_bytes());
    let mut short_header = pcap_header(LE_USEC, 1);
    short_header.pop();
    let files = [
        ("empty", Vec::new()),
        ("not-capture", b"abc".to_vec()),
        ("short-header", short_header),
        ("cut-body", truncated),
        ("too-big", too_big),
        ("later-too-big", later_too_big),
        ("link-type", pcap_header(LE_USEC, 104)),
    ];
    for (name, bytes) in files {
        assert_chunked_matches(&bytes, name);
        let sequential = read_capture(&bytes);
        let (forced, _) =
            read_capture_seams(&bytes, &[bytes.len() / 2, bytes.len().saturating_sub(1)]);
        assert_same(&bytes, &sequential, &forced, &format!("{name} forced"));
    }
}

#[test]
fn record_boundary_seam_proves() {
    let bytes = many_pcap(32);
    let sequential = read_capture(&bytes);
    let (one, fallback) = read_capture_seams(&bytes, &[]);
    assert!(!fallback, "one chunk is sequential");
    assert_same(&bytes, &sequential, &one, "one");
    let rec = 16 + eth_ipv4_udp([10, 0, 0, 1], 0).len();
    let seam = 24 + 16 * rec;
    let (split, fallback) = read_capture_seams(&bytes, &[seam]);
    assert!(!fallback, "a seam on a record boundary must prove");
    assert_same(&bytes, &sequential, &split, "boundary");
}
