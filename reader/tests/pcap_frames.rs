use reader::{read_capture, Capture, Fault, Frame, TimeUnit, Timestamp};

const LE_USEC: [u8; 4] = [0xd4, 0xc3, 0xb2, 0xa1];
const BE_USEC: [u8; 4] = [0xa1, 0xb2, 0xc3, 0xd4];
const LE_NSEC: [u8; 4] = [0x4d, 0x3c, 0xb2, 0xa1];
const BE_NSEC: [u8; 4] = [0xa1, 0xb2, 0x3c, 0x4d];

fn is_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    let start = haystack.as_ptr() as usize;
    let needle_start = needle.as_ptr() as usize;
    needle_start >= start && needle_start + needle.len() <= start + haystack.len()
}

fn u16_bytes(value: u16, big: bool) -> [u8; 2] {
    if big {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    }
}

fn u32_bytes(value: u32, big: bool) -> [u8; 4] {
    if big {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    }
}

fn i32_bytes(value: i32, big: bool) -> [u8; 4] {
    if big {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    }
}

fn header(magic: [u8; 4], snaplen: u32, link_type: u32) -> Vec<u8> {
    let big = magic[0] == 0xa1;
    let mut file = magic.to_vec();
    file.extend_from_slice(&u16_bytes(2, big));
    file.extend_from_slice(&u16_bytes(4, big));
    file.extend_from_slice(&i32_bytes(0, big));
    file.extend_from_slice(&u32_bytes(0, big));
    file.extend_from_slice(&u32_bytes(snaplen, big));
    file.extend_from_slice(&u32_bytes(link_type, big));
    file
}

fn push_packet(file: &mut Vec<u8>, seconds: u32, fraction: u32, original_length: u32, body: &[u8]) {
    let big = file[0] == 0xa1;
    file.extend_from_slice(&u32_bytes(seconds, big));
    file.extend_from_slice(&u32_bytes(fraction, big));
    file.extend_from_slice(&u32_bytes(body.len() as u32, big));
    file.extend_from_slice(&u32_bytes(original_length, big));
    file.extend_from_slice(body);
}

fn stamp(seconds: u64, fraction: u32, unit: TimeUnit) -> Timestamp {
    Timestamp {
        seconds,
        fraction,
        unit,
    }
}

fn assert_clean(capture: &Capture<'_>) {
    assert_eq!(capture.fault, None::<Fault>);
}

fn assert_frame(
    frame: &Frame<'_>,
    bytes: &[u8],
    link_type: u32,
    timestamp: Timestamp,
    original_length: u32,
    captured: &[u8],
) {
    assert_eq!(frame.link_type, link_type);
    assert_eq!(frame.timestamp, Some(timestamp));
    assert_eq!(frame.original_length, original_length);
    assert_eq!(frame.captured, captured);
    assert!(is_subslice(bytes, frame.captured));
}

#[test]
fn little_endian_microseconds_yield_one_frame() {
    let mut bytes = header(LE_USEC, 65535, 1);
    push_packet(&mut bytes, 5, 6, 2, &[0x09, 0x08, 0x07, 0x06]);
    let capture = read_capture(&bytes);
    assert_clean(&capture);
    assert_eq!(capture.frames.len(), 1);
    assert_frame(
        &capture.frames[0],
        &bytes,
        1,
        stamp(5, 6, TimeUnit::Microsecond),
        2,
        &[0x09, 0x08, 0x07, 0x06],
    );
}

#[test]
fn big_endian_microseconds_yield_one_frame() {
    let mut bytes = header(BE_USEC, 65535, 1);
    push_packet(&mut bytes, 11, 12, 2, &[0xde, 0xad]);
    let capture = read_capture(&bytes);
    assert_clean(&capture);
    assert_eq!(capture.frames.len(), 1);
    assert_frame(
        &capture.frames[0],
        &bytes,
        1,
        stamp(11, 12, TimeUnit::Microsecond),
        2,
        &[0xde, 0xad],
    );
}

#[test]
fn little_endian_nanoseconds_keep_the_fraction() {
    let mut bytes = header(LE_NSEC, 65535, 1);
    push_packet(&mut bytes, 9, 1000, 1, &[0x01]);
    let capture = read_capture(&bytes);
    assert_clean(&capture);
    assert_eq!(capture.frames.len(), 1);
    assert_eq!(
        capture.frames[0].timestamp,
        Some(stamp(9, 1000, TimeUnit::Nanosecond))
    );
}

#[test]
fn big_endian_nanoseconds_keep_a_short_fraction() {
    let mut bytes = header(BE_NSEC, 65535, 1);
    push_packet(&mut bytes, 3, 250, 9, &[0xff]);
    let capture = read_capture(&bytes);
    assert_clean(&capture);
    assert_eq!(capture.frames.len(), 1);
    let frame = &capture.frames[0];
    assert_eq!(frame.original_length, 9);
    assert_eq!(frame.captured.len(), 1);
    assert_eq!(frame.timestamp, Some(stamp(3, 250, TimeUnit::Nanosecond)));
}

#[test]
fn two_packets_stay_in_file_order() {
    let mut bytes = header(LE_USEC, 65535, 1);
    push_packet(&mut bytes, 1, 2, 1, &[0x11]);
    push_packet(&mut bytes, 3, 4, 1, &[0x22]);
    let capture = read_capture(&bytes);
    assert_clean(&capture);
    assert_eq!(capture.frames.len(), 2);
    assert_frame(
        &capture.frames[0],
        &bytes,
        1,
        stamp(1, 2, TimeUnit::Microsecond),
        1,
        &[0x11],
    );
    assert_frame(
        &capture.frames[1],
        &bytes,
        1,
        stamp(3, 4, TimeUnit::Microsecond),
        1,
        &[0x22],
    );
}

#[test]
fn captured_length_steps_past_snaplen_and_original_length() {
    let mut bytes = header(LE_USEC, 1, 1);
    push_packet(&mut bytes, 5, 6, 2, &[0x09, 0x08, 0x07, 0x06]);
    push_packet(&mut bytes, 7, 8, 1, &[0xab]);
    let capture = read_capture(&bytes);
    assert_clean(&capture);
    assert_eq!(capture.frames.len(), 2);
    assert_frame(
        &capture.frames[0],
        &bytes,
        1,
        stamp(5, 6, TimeUnit::Microsecond),
        2,
        &[0x09, 0x08, 0x07, 0x06],
    );
    assert_frame(
        &capture.frames[1],
        &bytes,
        1,
        stamp(7, 8, TimeUnit::Microsecond),
        1,
        &[0xab],
    );
}

#[test]
fn header_only_file_has_no_frames() {
    let bytes = header(LE_USEC, 65535, 1);
    let capture = read_capture(&bytes);
    assert_eq!(capture.frames.len(), 0);
    assert_eq!(capture.fault, None::<Fault>);
}

#[test]
fn captured_length_262144_is_a_frame() {
    let body = vec![0u8; 262144];
    let mut bytes = header(LE_USEC, 65535, 1);
    push_packet(&mut bytes, 1, 0, 262144, &body);
    let capture = read_capture(&bytes);
    assert_clean(&capture);
    assert_eq!(capture.frames.len(), 1);
    assert_eq!(capture.frames[0].captured.len(), 262144);
    assert_eq!(
        capture.frames[0].timestamp,
        Some(stamp(1, 0, TimeUnit::Microsecond))
    );
    assert!(is_subslice(&bytes, capture.frames[0].captured));
}

#[test]
fn linux_cooked_capture_opens() {
    let mut bytes = header(LE_USEC, 65535, 113);
    push_packet(&mut bytes, 1, 0, 1, &[0x01]);
    let capture = read_capture(&bytes);
    assert_clean(&capture);
    assert_eq!(capture.frames.len(), 1);
    assert_eq!(capture.frames[0].link_type, 113);
}

#[test]
fn linux_cooked_capture_v2_opens() {
    let mut bytes = header(LE_USEC, 65535, 276);
    push_packet(&mut bytes, 1, 0, 1, &[0x01]);
    let capture = read_capture(&bytes);
    assert_clean(&capture);
    assert_eq!(capture.frames.len(), 1);
    assert_eq!(capture.frames[0].link_type, 276);
}

#[test]
fn zero_length_packet_is_an_empty_slice() {
    let mut bytes = header(LE_USEC, 65535, 1);
    push_packet(&mut bytes, 1, 0, 0, &[]);
    push_packet(&mut bytes, 2, 0, 1, &[0xab]);
    let capture = read_capture(&bytes);
    assert_clean(&capture);
    assert_eq!(capture.frames.len(), 2);
    assert_eq!(capture.frames[0].captured, &[] as &[u8]);
    assert!(is_subslice(&bytes, capture.frames[0].captured));
    assert_eq!(capture.frames[1].captured, &[0xab]);
}
