use reader::{read_capture, Capture, Fault, Frame};

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

fn header(magic: [u8; 4], snaplen: u32, link_type: u32) -> Vec<u8> {
    let big = magic[0] == 0xa1;
    let mut file = magic.to_vec();
    file.extend_from_slice(&u16_bytes(2, big));
    file.extend_from_slice(&u16_bytes(4, big));
    file.extend_from_slice(&u32_bytes(0, big));
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

fn assert_clean(capture: &Capture<'_>) {
    assert_eq!(capture.fault, None::<Fault>);
}

fn assert_frame(frame: &Frame<'_>, link_type: u32, captured: &[u8]) {
    assert_eq!(frame.link_type, link_type);
    assert_eq!(frame.captured, captured);
}

#[test]
fn four_magics_yield_one_frame() {
    for (magic, seconds, fraction, original, body) in [
        (LE_USEC, 5, 6, 2, &[0x09, 0x08, 0x07, 0x06][..]),
        (BE_USEC, 11, 12, 2, &[0xde, 0xad][..]),
        (LE_NSEC, 9, 1000, 1, &[0x01][..]),
        (BE_NSEC, 3, 250, 9, &[0xff][..]),
    ] {
        let mut bytes = header(magic, 65535, 1);
        push_packet(&mut bytes, seconds, fraction, original, body);
        let capture = read_capture(&bytes);
        assert_clean(&capture);
        assert_eq!(capture.frames.len(), 1);
        assert_frame(&capture.frames[0], 1, body);
        assert!(is_subslice(&bytes, capture.frames[0].captured));
    }
}

#[test]
fn two_packets_stay_in_file_order() {
    let mut bytes = header(LE_USEC, 65535, 1);
    push_packet(&mut bytes, 1, 2, 1, &[0x11]);
    push_packet(&mut bytes, 3, 4, 1, &[0x22]);
    let capture = read_capture(&bytes);
    assert_clean(&capture);
    assert_eq!(capture.frames.len(), 2);
    assert_frame(&capture.frames[0], 1, &[0x11]);
    assert_frame(&capture.frames[1], 1, &[0x22]);
}

#[test]
fn captured_length_steps_past_snaplen_and_original_length() {
    let mut bytes = header(LE_USEC, 1, 1);
    push_packet(&mut bytes, 5, 6, 2, &[0x09, 0x08, 0x07, 0x06]);
    push_packet(&mut bytes, 7, 8, 1, &[0xab]);
    let capture = read_capture(&bytes);
    assert_clean(&capture);
    assert_eq!(capture.frames.len(), 2);
    assert_frame(&capture.frames[0], 1, &[0x09, 0x08, 0x07, 0x06]);
    assert_frame(&capture.frames[1], 1, &[0xab]);
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
    assert!(is_subslice(&bytes, capture.frames[0].captured));
}

#[test]
fn linux_cooked_link_types_open() {
    for link_type in [113, 276] {
        let mut bytes = header(LE_USEC, 65535, link_type);
        push_packet(&mut bytes, 1, 0, 1, &[0x01]);
        let capture = read_capture(&bytes);
        assert_clean(&capture);
        assert_eq!(capture.frames.len(), 1);
        assert_eq!(capture.frames[0].link_type, link_type);
    }
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
