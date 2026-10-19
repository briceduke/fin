//! Chunked reader equals [`reader::read_capture`] on frames, faults, and ip.src.

use std::fs;
use std::path::PathBuf;

use reader::{
    read_capture, read_capture_chunked, read_capture_seams, Capture, Frame, IpSrc,
};

mod build;
use build::*;

const THREADS: &[usize] = &[1, 2, 3, 5, 8, 64];

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

fn ip_src_view(frames: &[Frame<'_>]) -> (Vec<String>, Vec<(u64, &'static str)>) {
    let mut walk = IpSrc::new();
    let mut rows = Vec::new();
    let mut counted = Vec::new();
    for (index, frame) in frames.iter().enumerate() {
        let cell = walk.walk(frame);
        rows.push(cell.values.join(","));
        if let Some(reason) = cell.counted {
            counted.push((index as u64 + 1, reason));
        }
    }
    (rows, counted)
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
        let (seq_rows, seq_counted) = ip_src_view(&sequential.frames);
        let (chunk_rows, chunk_counted) = ip_src_view(&chunked.frames);
        assert_eq!(seq_rows, chunk_rows, "{label} threads={threads} ip.src");
        assert_eq!(
            seq_counted, chunk_counted,
            "{label} threads={threads} counted"
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
        files.push((format!("{name}-1"), pcap_file(magic, &[&[0x11]])));
        files.push((format!("{name}-2"), pcap_file(magic, &[&[0x11], &[0x22]])));
        files.push((format!("{name}-9"), many_pcap(9)));
        files.push((format!("{name}-32"), many_pcap(32)));
    }
    files.push(("pcapng-le-0".into(), {
        concat(&[&section_header(Endian::Little), &interface_block(Endian::Little, 1)])
    }));
    files.push(("pcapng-le-1".into(), many_pcapng(Endian::Little, 1)));
    files.push(("pcapng-le-2".into(), many_pcapng(Endian::Little, 2)));
    files.push(("pcapng-le-9".into(), many_pcapng(Endian::Little, 9)));
    files.push(("pcapng-le-32".into(), many_pcapng(Endian::Little, 32)));
    files.push(("pcapng-be-8".into(), many_pcapng(Endian::Big, 8)));
    files.push(("pcapng-two-section".into(), two_section_pcapng()));
    files.push(("pcapng-two-iface".into(), two_interface_pcapng()));
    files.push((
        "pcapng-mixed-blocks".into(),
        concat(&[
            &section_header(Endian::Little),
            &interface_block(Endian::Little, 1),
            &enhanced_packet(Endian::Little, 0, &[0x01]),
            &simple_packet(Endian::Little, &[0x02, 0x03]),
            &obsolete_packet(Endian::Little, &[0x04]),
            &block(Endian::Little, 7, &[]),
            &enhanced_packet(Endian::Little, 0, &[0x05]),
        ]),
    ));
    files.push((
        "pcapng-isb-between".into(),
        concat(&[
            &section_header(Endian::Little),
            &interface_block(Endian::Little, 1),
            &enhanced_packet(Endian::Little, 0, &[0x10]),
            &block(Endian::Little, 5, &[0u8; 12]),
            &enhanced_packet(Endian::Little, 0, &[0x11]),
        ]),
    ));
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
fn awkward_seams_match_sequential() {
    let pcap = many_pcap(12);
    let packet = eth_ipv4_udp([10, 0, 0, 1], 1);
    let rec = 24 + 16 + packet.len();
    let pcap_seams = [
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
    for seams in &pcap_seams {
        let sequential = read_capture(&pcap);
        let chunked = read_capture_seams(&pcap, seams);
        assert_same(
            &pcap,
            &sequential,
            &chunked.capture,
            &format!("pcap seams {seams:?}"),
        );
    }

    let ng = many_pcapng(Endian::Little, 12);
    let shb = 28;
    let idb = shb + 20;
    let epb = enhanced_packet(Endian::Little, 0, &packet).len();
    let ng_seams = [
        vec![8],
        vec![shb],
        vec![shb + 4],
        vec![idb],
        vec![idb + 8],
        vec![idb + epb / 2],
        vec![idb + epb],
        vec![idb + epb + 4],
        vec![8, shb, idb + 8, idb + epb + 12],
    ];
    for seams in &ng_seams {
        let sequential = read_capture(&ng);
        let chunked = read_capture_seams(&ng, seams);
        assert_same(
            &ng,
            &sequential,
            &chunked.capture,
            &format!("pcapng seams {seams:?}"),
        );
    }

    let two = two_section_pcapng();
    let sequential = read_capture(&two);
    for seams in [vec![28], vec![48], vec![two.len() / 2], vec![28, two.len() / 2]] {
        let chunked = read_capture_seams(&two, &seams);
        assert_same(
            &two,
            &sequential,
            &chunked.capture,
            &format!("two-section {seams:?}"),
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
    let chunked = read_capture_seams(&bytes, &[fake_at]);
    assert_same(&bytes, &sequential, &chunked.capture, "adversarial pcap");
    assert!(
        chunked.report.fallback,
        "fake pcap records in payload must not prove a seam"
    );
    assert_eq!(sequential.frames.len(), 2);
    assert_ne!(
        sequential.frames[0].captured,
        &fake[..1],
        "must not emit the inner fake packet"
    );
}

fn fake_epb(endian: Endian, packet: &[u8]) -> Vec<u8> {
    enhanced_packet(endian, 0, packet)
}

#[test]
fn adversarial_pcapng_payload_falls_back_and_keeps_frames() {
    let inner = fake_epb(Endian::Little, &[0xE0]);
    let mut payload = Vec::from([0u8; 14]);
    payload[12] = 0x08;
    payload[13] = 0x00;
    payload.extend_from_slice(&inner);
    for i in 1..8 {
        payload.extend_from_slice(&fake_epb(Endian::Little, &[0xE0 + i]));
    }
    let prefix = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1),
    ]);
    let outer = enhanced_packet(Endian::Little, 0, &payload);
    let bytes = concat(&[&prefix, &outer, &enhanced_packet(Endian::Little, 0, &[0x99])]);
    let packet_at = prefix.len() + 8 + 20;
    let fake_at = packet_at + 14;
    assert_eq!(&bytes[fake_at..fake_at + inner.len()], inner.as_slice());
    let sequential = read_capture(&bytes);
    let chunked = read_capture_seams(&bytes, &[fake_at]);
    assert_same(&bytes, &sequential, &chunked.capture, "adversarial pcapng");
    assert!(
        chunked.report.fallback,
        "fake pcapng blocks in payload must not prove a seam"
    );
    assert_eq!(sequential.frames.len(), 2);
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
        let forced = read_capture_seams(&bytes, &[bytes.len() / 2, bytes.len().saturating_sub(1)]);
        assert_same(&bytes, &sequential, &forced.capture, &format!("{name} forced"));
    }
}

#[test]
fn pcapng_faults_match_sequential() {
    let mut cut = many_pcapng(Endian::Little, 1);
    cut.truncate(cut.len() - 5);
    let mismatch = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1),
        &{
            let mut epb = enhanced_packet(Endian::Little, 0, &[0x01]);
            let n = epb.len();
            epb[n - 4..].copy_from_slice(&20u32.to_le_bytes());
            epb
        },
    ]);
    let bad_iface = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1),
        &enhanced_packet(Endian::Little, 3, &[0x01]),
    ]);
    let files = [
        ("cut", cut),
        ("len-mismatch", mismatch),
        ("bad-iface", bad_iface),
        ("tiny", vec![0x0a, 0x0d, 0x0d, 0x0a, 0, 0, 0]),
    ];
    for (name, bytes) in files {
        assert_chunked_matches(&bytes, name);
    }
}

#[test]
fn well_formed_equal_splits_usually_prove() {
    let bytes = many_pcap(32);
    let chunked = read_capture_seams(&bytes, &[]);
    assert!(!chunked.report.fallback, "one chunk is sequential-equivalent");
    let two = read_capture_chunked(&bytes, 2);
    let _ = two;
    let report = reader::read_capture_seams(&bytes, &[bytes.len() / 2]);
    assert_same(&bytes, &read_capture(&bytes), &report.capture, "half");
}

#[test]
fn fallback_rate_on_corpus_is_reported() {
    let mut files = 0u32;
    let mut forced_fallback = 0u32;
    let mut even_fallback = 0u32;
    let mut even_runs = 0u32;
    let mut long_even_fallback = 0u32;
    let mut long_even_runs = 0u32;
    let mut seams = 0u32;
    let mut proved = 0u32;
    for (name, bytes) in corpus() {
        if bytes.len() < 40 {
            continue;
        }
        files += 1;
        let mid = bytes.len() / 2;
        let extra = bytes.len() / 3;
        let report = read_capture_seams(&bytes, &[mid, extra]);
        assert_same(
            &bytes,
            &read_capture(&bytes),
            &report.capture,
            &format!("rate {name}"),
        );
        seams += report.report.seams as u32;
        proved += report.report.proved as u32;
        if report.report.fallback {
            forced_fallback += 1;
        }
        for &threads in &[2usize, 3, 5, 8] {
            even_runs += 1;
            let chunked = read_capture_seams(
                &bytes,
                &(1..threads)
                    .map(|i| i * bytes.len() / threads)
                    .collect::<Vec<_>>(),
            );
            assert_same(
                &bytes,
                &read_capture(&bytes),
                &chunked.capture,
                &format!("even {name} {threads}"),
            );
            if chunked.report.fallback {
                even_fallback += 1;
            }
            if read_capture(&bytes).frames.len() >= 9 {
                long_even_runs += 1;
                if chunked.report.fallback {
                    long_even_fallback += 1;
                }
            }
        }
    }
    eprintln!(
        "corpus files={files} forced_fallback={forced_fallback}/{files} even_fallback={even_fallback}/{even_runs} long_even_fallback={long_even_fallback}/{long_even_runs} forced_seams={seams} forced_proved={proved}"
    );
    assert!(files > 0);
}
