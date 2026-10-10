use reader::{read_capture, CaptureKind, Fault, TimeUnit, Timestamp};

fn header(link_type: u32) -> Vec<u8> {
    let mut bytes = vec![
        0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    bytes.extend_from_slice(&65_535u32.to_le_bytes());
    bytes.extend_from_slice(&link_type.to_le_bytes());
    bytes
}

fn record(seconds: u32, fraction: u32, included: u32, original: u32, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in [seconds, fraction, included, original] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(body);
    bytes
}

#[test]
fn empty_file_is_not_a_capture() {
    let capture = read_capture(b"");
    assert_eq!(capture.frames.len(), 0);
    let fault = capture.fault.unwrap();
    assert_eq!(fault, Fault::NotACaptureFile);
    assert_eq!(fault.exit_code(), 3);
    assert_eq!(fault.phrase(), "isn't a capture file");
}

#[test]
fn unrecognized_bytes_are_not_a_capture() {
    let capture = read_capture(b"abc");
    assert_eq!(capture.frames.len(), 0);
    let fault = capture.fault.unwrap();
    assert_eq!(fault, Fault::NotACaptureFile);
    assert_eq!(fault.exit_code(), 3);
    assert_eq!(fault.phrase(), "isn't a capture file");
}

#[test]
fn truncated_magic_tail() {
    let capture = read_capture(&[0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00]);
    assert_eq!(capture.frames.len(), 0);
    let fault = capture.fault.unwrap();
    assert_eq!(fault, Fault::TruncatedHeader);
    assert_eq!(fault.exit_code(), 3);
    assert!(fault.phrase().contains("or other data"));
}

#[test]
fn truncated_global_header() {
    let mut bytes = header(1);
    bytes.pop();
    assert_eq!(bytes.len(), 23);
    let capture = read_capture(&bytes);
    assert_eq!(capture.frames.len(), 0);
    let fault = capture.fault.unwrap();
    assert_eq!(fault, Fault::TruncatedHeader);
    assert_eq!(fault.exit_code(), 3);
    assert!(fault.phrase().contains("or other data"));
}

#[test]
fn a_body_cut_off_mid_packet_returns_no_frame() {
    let mut bytes = header(1);
    bytes.extend(record(1, 2, 4, 4, &[0x11, 0x22]));
    let capture = read_capture(&bytes);
    assert_eq!(capture.frames.len(), 0);
    let fault = capture.fault.unwrap();
    assert_eq!(fault, Fault::CutShort);
    assert_eq!(fault.exit_code(), 14);
    assert_eq!(
        fault.phrase(),
        "appears to have been cut short in the middle of a packet"
    );
}

#[test]
fn an_earlier_frame_survives_a_cut_short_header() {
    let mut bytes = header(1);
    bytes.extend(record(1, 2, 4, 4, &[0x11, 0x22, 0x33, 0x44]));
    bytes.extend_from_slice(&3u32.to_le_bytes());
    bytes.extend_from_slice(&4u32.to_le_bytes());
    let capture = read_capture(&bytes);
    assert_eq!(capture.frames.len(), 1);
    let frame = &capture.frames[0];
    assert_eq!(frame.captured, &[0x11, 0x22, 0x33, 0x44]);
    assert_eq!(frame.original_length, 4);
    assert_eq!(
        frame.timestamp,
        Some(Timestamp {
            seconds: 1,
            fraction: 2,
            unit: TimeUnit::Microsecond,
        })
    );
    let fault = capture.fault.unwrap();
    assert_eq!(fault, Fault::CutShort);
    assert_eq!(fault.exit_code(), 14);
    assert!(!fault.phrase().contains("or other data"));
}

#[test]
fn first_packet_bigger_than_262144_is_not_read() {
    let mut bytes = header(1);
    bytes.extend(record(1, 0, 262_145, 262_145, &[]));
    let capture = read_capture(&bytes);
    assert_eq!(capture.frames.len(), 0);
    let fault = capture.fault.unwrap();
    assert_eq!(
        fault,
        Fault::CapturedLengthTooBig {
            length: 262_145,
            kind: CaptureKind::Pcap,
        }
    );
    assert!(fault.phrase().contains("bigger than maximum of 262144"));
    assert_eq!(fault.exit_code(), 14);
}

#[test]
fn a_later_packet_bigger_than_262144_keeps_the_earlier_frame() {
    let mut bytes = header(1);
    bytes.extend(record(1, 2, 1, 1, &[0xee]));
    bytes.extend(record(3, 4, 262_145, 262_145, &[]));
    let capture = read_capture(&bytes);
    assert_eq!(capture.frames.len(), 1);
    assert_eq!(capture.frames[0].captured, &[0xee]);
    let fault = capture.fault.unwrap();
    assert_eq!(
        fault,
        Fault::CapturedLengthTooBig {
            length: 262_145,
            kind: CaptureKind::Pcap,
        }
    );
    assert_eq!(fault.exit_code(), 14);
}

#[test]
fn unclaimed_link_type_fails_before_any_frame() {
    let mut bytes = header(104);
    bytes.extend(record(1, 2, 1, 1, &[0xab]));
    let capture = read_capture(&bytes);
    assert_eq!(capture.frames.len(), 0);
    let fault = capture.fault.unwrap();
    assert_eq!(fault, Fault::UnsupportedLinkType { link_type: 104 });
    assert_eq!(fault.phrase(), "unsupported link type 104");
    assert_eq!(fault.exit_code(), 1);
}
