use reader::{read_capture, CaptureKind, Fault, TimeUnit, Timestamp};

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

fn pack_u16(value: u16, endian: Endian) -> [u8; 2] {
    match endian {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    }
}

fn pack_u32(value: u32, endian: Endian) -> [u8; 4] {
    match endian {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    }
}

fn pack_i64(value: i64, endian: Endian) -> [u8; 8] {
    match endian {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    }
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

fn pad_four(bytes: &[u8]) -> Vec<u8> {
    let mut padded = bytes.to_vec();
    while padded.len() % 4 != 0 {
        padded.push(0);
    }
    padded
}

fn is_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    let start = haystack.as_ptr() as usize;
    let end = start + haystack.len();
    let needle_start = needle.as_ptr() as usize;
    needle_start >= start && needle_start + needle.len() <= end
}

fn section_header(endian: Endian) -> Vec<u8> {
    let block_type = [0x0a, 0x0d, 0x0d, 0x0a];
    let total = pack_u32(28, endian);
    let order = pack_u32(0x1A2B3C4D, endian);
    let major = pack_u16(1, endian);
    let minor = pack_u16(0, endian);
    let section_length = pack_i64(-1, endian);
    concat(&[
        &block_type,
        &total,
        &order,
        &major,
        &minor,
        &section_length,
        &total,
    ])
}

fn block_with_lengths(
    endian: Endian,
    block_type: u32,
    body: &[u8],
    first: u32,
    second: u32,
) -> Vec<u8> {
    concat(&[
        &pack_u32(block_type, endian),
        &pack_u32(first, endian),
        body,
        &pack_u32(second, endian),
    ])
}

fn block(endian: Endian, block_type: u32, body: &[u8]) -> Vec<u8> {
    let total = (12 + body.len()) as u32;
    block_with_lengths(endian, block_type, body, total, total)
}

fn option(endian: Endian, code: u16, value: &[u8]) -> Vec<u8> {
    let raw = concat(&[
        &pack_u16(code, endian),
        &pack_u16(value.len() as u16, endian),
        value,
    ]);
    pad_four(&raw)
}

fn interface_block(endian: Endian, link_type: u16, snaplen: u32, options: &[u8]) -> Vec<u8> {
    let body = concat(&[
        &pack_u16(link_type, endian),
        &pack_u16(0, endian),
        &pack_u32(snaplen, endian),
        options,
    ]);
    block(endian, 1, &pad_four(&body))
}

fn enhanced_packet(
    endian: Endian,
    interface_id: u32,
    ticks: u64,
    captured_length: u32,
    original_length: u32,
    packet: &[u8],
    options: &[u8],
) -> Vec<u8> {
    let body = concat(&[
        &pack_u32(interface_id, endian),
        &pack_u32((ticks >> 32) as u32, endian),
        &pack_u32(ticks as u32, endian),
        &pack_u32(captured_length, endian),
        &pack_u32(original_length, endian),
        &pad_four(packet),
        options,
    ]);
    block(endian, 6, &pad_four(&body))
}

fn simple_packet(endian: Endian, original_length: u32, packet: &[u8]) -> Vec<u8> {
    let body = concat(&[&pack_u32(original_length, endian), &pad_four(packet)]);
    block(endian, 3, &pad_four(&body))
}

fn obsolete_packet(
    endian: Endian,
    interface_id: u16,
    ticks: u64,
    packet: &[u8],
    original_length: u32,
) -> Vec<u8> {
    let body = concat(&[
        &pack_u16(interface_id, endian),
        &pack_u16(0, endian),
        &pack_u32((ticks >> 32) as u32, endian),
        &pack_u32(ticks as u32, endian),
        &pack_u32(packet.len() as u32, endian),
        &pack_u32(original_length, endian),
        &pad_four(packet),
    ]);
    block(endian, 2, &pad_four(&body))
}

fn unknown_block(endian: Endian, block_type: u32) -> Vec<u8> {
    block(endian, block_type, &[])
}

#[test]
fn one_enhanced_packet_and_the_packet_after_padding() {
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &[]),
        &enhanced_packet(
            Endian::Little,
            0,
            1_500_000,
            3,
            60,
            &[0x10, 0x20, 0x30],
            &[],
        ),
        &enhanced_packet(Endian::Little, 0, 2, 1, 1, &[0x99], &[]),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(capture.frames.len(), 2);
    assert_eq!(capture.frames[0].link_type, 1);
    assert_eq!(capture.frames[0].original_length, 60);
    assert_eq!(
        capture.frames[0].timestamp,
        Some(Timestamp {
            seconds: 1,
            fraction: 500_000,
            unit: TimeUnit::Microsecond,
        })
    );
    assert_eq!(capture.frames[0].captured, &[0x10, 0x20, 0x30]);
    assert_eq!(is_subslice(&bytes, capture.frames[0].captured), true);
    assert_eq!(capture.frames[1].captured, &[0x99]);
    assert_eq!(is_subslice(&bytes, capture.frames[1].captured), true);
    assert_eq!(
        capture.frames[1].timestamp,
        Some(Timestamp {
            seconds: 0,
            fraction: 2,
            unit: TimeUnit::Microsecond,
        })
    );
}

#[test]
fn big_endian_section_reads_one_packet() {
    let bytes = concat(&[
        &section_header(Endian::Big),
        &interface_block(Endian::Big, 1, 65535, &[]),
        &enhanced_packet(Endian::Big, 0, 2_000_000, 2, 2, &[0x07, 0x08], &[]),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(capture.frames.len(), 1);
    assert_eq!(capture.frames[0].link_type, 1);
    assert_eq!(
        capture.frames[0].timestamp,
        Some(Timestamp {
            seconds: 2,
            fraction: 0,
            unit: TimeUnit::Microsecond,
        })
    );
    assert_eq!(capture.frames[0].captured, &[0x07, 0x08]);
    assert_eq!(is_subslice(&bytes, capture.frames[0].captured), true);
}

#[test]
fn snaplen_does_not_clip_an_enhanced_packet() {
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 1, &[]),
        &enhanced_packet(Endian::Little, 0, 0, 4, 4, &[0x01, 0x02, 0x03, 0x04], &[]),
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0xab], &[]),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(capture.frames.len(), 2);
    assert_eq!(capture.frames[0].captured, &[0x01, 0x02, 0x03, 0x04]);
    assert_eq!(is_subslice(&bytes, capture.frames[0].captured), true);
    assert_eq!(capture.frames[1].captured, &[0xab]);
    assert_eq!(is_subslice(&bytes, capture.frames[1].captured), true);
}

#[test]
fn second_interface_supplies_its_link_type() {
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &[]),
        &interface_block(Endian::Little, 113, 65535, &[]),
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0xaa], &[]),
        &enhanced_packet(Endian::Little, 1, 0, 2, 2, &[0xbb, 0xcc], &[]),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(capture.frames.len(), 2);
    assert_eq!(capture.frames[0].link_type, 1);
    assert_eq!(capture.frames[0].captured, &[0xaa]);
    assert_eq!(is_subslice(&bytes, capture.frames[0].captured), true);
    assert_eq!(capture.frames[1].link_type, 113);
    assert_eq!(capture.frames[1].captured, &[0xbb, 0xcc]);
    assert_eq!(is_subslice(&bytes, capture.frames[1].captured), true);
}

#[test]
fn a_new_section_resets_interface_ids() {
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &[]),
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0x01], &[]),
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 276, 65535, &[]),
        &enhanced_packet(Endian::Little, 0, 0, 2, 2, &[0x02, 0x03], &[]),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(capture.frames.len(), 2);
    assert_eq!(capture.frames[1].link_type, 276);
    assert_eq!(capture.frames[1].captured, &[2, 3]);
    assert_eq!(is_subslice(&bytes, capture.frames[1].captured), true);
}

#[test]
fn an_unknown_block_between_packets_is_skipped() {
    let skipped = unknown_block(Endian::Little, 9);
    assert_eq!(skipped.len(), 12);
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &[]),
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0x01], &[]),
        &skipped,
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0x02], &[]),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(capture.frames.len(), 2);
    assert_eq!(capture.frames[0].captured, &[0x01]);
    assert_eq!(is_subslice(&bytes, capture.frames[0].captured), true);
    assert_eq!(capture.frames[1].captured, &[0x02]);
    assert_eq!(is_subslice(&bytes, capture.frames[1].captured), true);
}

#[test]
fn simple_packet_has_no_timestamp() {
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 4, &[]),
        &simple_packet(Endian::Little, 8, &[0x01, 0x02, 0x03, 0x04]),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(capture.frames.len(), 1);
    assert_eq!(capture.frames[0].timestamp, None);
    assert_eq!(capture.frames[0].original_length, 8);
    assert_eq!(capture.frames[0].link_type, 1);
    assert_eq!(capture.frames[0].captured, &[0x01, 0x02, 0x03, 0x04]);
    assert_eq!(is_subslice(&bytes, capture.frames[0].captured), true);
}

#[test]
fn simple_packet_snaplen_zero_keeps_the_original_length() {
    let packet = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 0, &[]),
        &simple_packet(Endian::Little, 8, &packet),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(capture.frames.len(), 1);
    assert_eq!(capture.frames[0].timestamp, None);
    assert_eq!(capture.frames[0].original_length, 8);
    assert_eq!(capture.frames[0].link_type, 1);
    assert_eq!(capture.frames[0].captured, &packet);
    assert_eq!(is_subslice(&bytes, capture.frames[0].captured), true);
}

#[test]
fn simple_packet_snaplen_zero_above_the_maximum_is_not_a_frame() {
    let spb = simple_packet(Endian::Little, 262145, &[]);
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 0, &[]),
        &spb,
    ]);
    let capture = read_capture(&bytes);
    let fault = capture.fault.unwrap();

    assert_eq!(capture.frames.len(), 0);
    assert_eq!(
        fault,
        Fault::CapturedLengthTooBig {
            length: 262145,
            kind: CaptureKind::Pcapng,
        }
    );
    assert_eq!(fault.exit_code(), 14);
    assert_eq!(
        fault
            .phrase()
            .contains("larger than maximum supported length 262144"),
        true
    );
}

#[test]
fn nanosecond_interface_resolution() {
    let resol = option(Endian::Little, 9, &[9]);
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &resol),
        &enhanced_packet(Endian::Little, 0, 1_000_000_005, 1, 1, &[0x01], &[]),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(capture.frames.len(), 1);
    assert_eq!(
        capture.frames[0].timestamp,
        Some(Timestamp {
            seconds: 1,
            fraction: 5,
            unit: TimeUnit::Nanosecond,
        })
    );
    assert_eq!(capture.frames[0].captured, &[0x01]);
    assert_eq!(is_subslice(&bytes, capture.frames[0].captured), true);
}

#[test]
fn power_of_two_interface_resolution() {
    let resol = option(Endian::Little, 9, &[0x83]);
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &resol),
        &enhanced_packet(Endian::Little, 0, 1, 1, 1, &[0x01], &[]),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(capture.frames.len(), 1);
    assert_eq!(
        capture.frames[0].timestamp,
        Some(Timestamp {
            seconds: 0,
            fraction: 125_000_000,
            unit: TimeUnit::Nanosecond,
        })
    );
    assert_eq!(capture.frames[0].captured, &[0x01]);
    assert_eq!(is_subslice(&bytes, capture.frames[0].captured), true);
}

#[test]
fn millisecond_resolution_reports_microseconds() {
    let resol = option(Endian::Little, 9, &[3]);
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &resol),
        &enhanced_packet(Endian::Little, 0, 1, 1, 1, &[0x01], &[]),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(
        capture.frames[0].timestamp,
        Some(Timestamp {
            seconds: 0,
            fraction: 1000,
            unit: TimeUnit::Microsecond,
        })
    );
}

#[test]
fn ten_nanosecond_resolution_reports_nanoseconds() {
    let resol = option(Endian::Little, 9, &[8]);
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &resol),
        &enhanced_packet(Endian::Little, 0, 1, 1, 1, &[0x01], &[]),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(
        capture.frames[0].timestamp,
        Some(Timestamp {
            seconds: 0,
            fraction: 10,
            unit: TimeUnit::Nanosecond,
        })
    );
}

#[test]
fn sub_nanosecond_resolution_truncates_to_nanoseconds() {
    let resol = option(Endian::Little, 9, &[10]);
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &resol),
        &enhanced_packet(Endian::Little, 0, 10, 1, 1, &[0x01], &[]),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(
        capture.frames[0].timestamp,
        Some(Timestamp {
            seconds: 0,
            fraction: 1,
            unit: TimeUnit::Nanosecond,
        })
    );
}

#[test]
fn a_packet_option_does_not_swallow_the_next_packet() {
    let comment = option(Endian::Little, 1, b"abc");
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &[]),
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0x11], &comment),
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0x22], &[]),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(capture.frames.len(), 2);
    assert_eq!(capture.frames[0].captured, &[0x11]);
    assert_eq!(is_subslice(&bytes, capture.frames[0].captured), true);
    assert_eq!(capture.frames[1].captured, &[0x22]);
    assert_eq!(is_subslice(&bytes, capture.frames[1].captured), true);
}

#[test]
fn obsolete_packet_block_is_a_frame() {
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &[]),
        &obsolete_packet(Endian::Little, 0, 2_500_000, &[0x0a, 0x0b], 9),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(capture.frames.len(), 1);
    assert_eq!(capture.frames[0].link_type, 1);
    assert_eq!(capture.frames[0].original_length, 9);
    assert_eq!(
        capture.frames[0].timestamp,
        Some(Timestamp {
            seconds: 2,
            fraction: 500_000,
            unit: TimeUnit::Microsecond,
        })
    );
    assert_eq!(capture.frames[0].captured, &[0x0a, 0x0b]);
    assert_eq!(is_subslice(&bytes, capture.frames[0].captured), true);
}

#[test]
fn an_unclaimed_pcapng_link_type_still_yields_the_frame() {
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 127, 65535, &[]),
        &enhanced_packet(Endian::Little, 0, 0, 1, 4, &[0x22], &[]),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(capture.frames.len(), 1);
    assert_eq!(capture.frames[0].link_type, 127);
    assert_eq!(capture.frames[0].original_length, 4);
    assert_eq!(capture.frames[0].captured, &[0x22]);
    assert_eq!(is_subslice(&bytes, capture.frames[0].captured), true);
}

#[test]
fn header_only_section_has_no_frames() {
    let bytes = section_header(Endian::Little);
    assert_eq!(bytes.len(), 28);
    let capture = read_capture(&bytes);

    assert_eq!(capture.frames.len(), 0);
    assert_eq!(capture.fault, None);
}

#[test]
fn a_short_preamble_is_not_a_capture() {
    let bytes = [0x0a, 0x0d, 0x0d, 0x0a, 0x1c, 0x00, 0x00, 0x00];
    let capture = read_capture(&bytes);
    let fault = capture.fault.unwrap();

    assert_eq!(capture.frames.len(), 0);
    assert_eq!(fault, Fault::NotACaptureFile);
    assert_eq!(fault.exit_code(), 3);
    assert_eq!(fault.phrase(), "isn't a capture file");
}

#[test]
fn a_truncated_block_keeps_the_earlier_frame() {
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &[]),
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0x01], &[]),
        &[0x06, 0x00, 0x00, 0x00],
    ]);
    let capture = read_capture(&bytes);
    let fault = capture.fault.unwrap();
    let phrase = fault.phrase();

    assert_eq!(capture.frames.len(), 1);
    assert_eq!(fault, Fault::CutShort);
    assert_eq!(fault.exit_code(), 14);
    assert_eq!(
        phrase,
        "appears to have been cut short in the middle of a packet"
    );
    assert_eq!(phrase.contains("or other data"), false);
}

#[test]
fn captured_length_above_the_maximum_is_not_a_frame() {
    let epb = enhanced_packet(Endian::Little, 0, 0, 262145, 262145, &[], &[]);
    assert_eq!(epb.len(), 32);
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &[]),
        &epb,
    ]);
    let capture = read_capture(&bytes);
    let fault = capture.fault.unwrap();

    assert_eq!(capture.frames.len(), 0);
    assert_eq!(
        fault,
        Fault::CapturedLengthTooBig {
            length: 262145,
            kind: CaptureKind::Pcapng,
        }
    );
    assert_eq!(fault.exit_code(), 14);
    assert_eq!(
        fault
            .phrase()
            .contains("larger than maximum supported length 262144"),
        true
    );
}

#[test]
fn a_bad_interface_keeps_the_earlier_frame() {
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &[]),
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0x01], &[]),
        &enhanced_packet(Endian::Little, 2, 0, 1, 1, &[0x02], &[]),
    ]);
    let capture = read_capture(&bytes);
    let fault = capture.fault.unwrap();

    assert_eq!(capture.frames.len(), 1);
    assert_eq!(capture.frames[0].captured, &[1]);
    assert_eq!(
        fault,
        Fault::BadInterface {
            index: 2,
            interfaces: 1,
        }
    );
    assert_eq!(fault.exit_code(), 14);
    assert_eq!(
        fault
            .phrase()
            .contains("interface index 2 is not less than section interface count 1"),
        true
    );
}

#[test]
fn a_packet_before_any_interface_is_a_bad_interface() {
    let bytes = concat(&[
        &section_header(Endian::Little),
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0x01], &[]),
    ]);
    let capture = read_capture(&bytes);
    let fault = capture.fault.unwrap();

    assert_eq!(capture.frames.len(), 0);
    assert_eq!(
        fault,
        Fault::BadInterface {
            index: 0,
            interfaces: 0,
        }
    );
    assert_eq!(fault.exit_code(), 14);
}

#[test]
fn mismatched_block_lengths_stop() {
    let body = concat(&[
        &pack_u32(0, Endian::Little),
        &pack_u32(0, Endian::Little),
        &pack_u32(1, Endian::Little),
        &pack_u32(1, Endian::Little),
        &pack_u32(1, Endian::Little),
        &[0x11, 0x00, 0x00, 0x00],
    ]);
    assert_eq!(body.len(), 24);
    let epb = block_with_lengths(Endian::Little, 6, &body, 36, 40);
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &[]),
        &epb,
    ]);
    let capture = read_capture(&bytes);
    let fault = capture.fault.unwrap();

    assert_eq!(capture.frames.len(), 0);
    assert_eq!(
        fault,
        Fault::BlockLengths {
            first: 36,
            second: 40
        }
    );
    assert_eq!(fault.exit_code(), 14);
    assert_eq!(fault.phrase().contains("first 36 and second 40"), true);
}
