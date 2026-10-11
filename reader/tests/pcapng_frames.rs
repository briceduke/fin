use reader::{read_capture, BlockKind, CaptureKind, Fault, TimeUnit, Timestamp};

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
    section_header_version(endian, 1, 0)
}

fn section_header_totals(endian: Endian, first: u32, second: u32) -> Vec<u8> {
    let mut header = section_header(endian);
    header[4..8].copy_from_slice(&pack_u32(first, endian));
    let end = header.len();
    header[end - 4..end].copy_from_slice(&pack_u32(second, endian));
    header
}

fn section_header_version(endian: Endian, major: u16, minor: u16) -> Vec<u8> {
    let block_type = [0x0a, 0x0d, 0x0d, 0x0a];
    let total = pack_u32(28, endian);
    let order = pack_u32(0x1A2B3C4D, endian);
    let major = pack_u16(major, endian);
    let minor = pack_u16(minor, endian);
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
    let skipped = unknown_block(Endian::Little, 7);
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
    assert_eq!(capture.exit_code(), 14);
    assert_eq!(
        fault
            .phrase()
            .contains("larger than maximum supported length 262144"),
        true
    );
}

#[test]
fn if_tsoffset_is_added_to_the_packet_timestamp() {
    let offset = option(Endian::Little, 14, &pack_i64(3600, Endian::Little));
    assert_eq!(
        offset,
        [0x0e, 0x00, 0x08, 0x00, 0x10, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    );
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &offset),
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0xaa], &[]),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(capture.frames.len(), 1);
    assert_eq!(capture.frames[0].captured, &[0xaa]);
    assert_eq!(is_subslice(&bytes, capture.frames[0].captured), true);
    assert_eq!(
        capture.frames[0].timestamp,
        Some(Timestamp {
            seconds: 3600,
            fraction: 0,
            unit: TimeUnit::Microsecond,
        })
    );
}

#[test]
fn a_negative_if_tsoffset_is_a_negative_epoch() {
    let offset = option(Endian::Little, 14, &pack_i64(-3600, Endian::Little));
    assert_eq!(
        offset,
        [0x0e, 0x00, 0x08, 0x00, 0xf0, 0xf1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    );
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &offset),
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0xaa], &[]),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(capture.frames.len(), 1);
    assert_eq!(
        capture.frames[0].timestamp,
        Some(Timestamp {
            seconds: -3600,
            fraction: 0,
            unit: TimeUnit::Microsecond,
        })
    );
}

#[test]
fn a_negative_if_tsoffset_adds_to_the_whole_seconds() {
    let offset = option(Endian::Little, 14, &pack_i64(-3600, Endian::Little));
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &offset),
        &enhanced_packet(Endian::Little, 0, 1_500_000, 1, 1, &[0xaa], &[]),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(
        capture.frames[0].timestamp,
        Some(Timestamp {
            seconds: -3599,
            fraction: 500_000,
            unit: TimeUnit::Microsecond,
        })
    );
}

#[test]
fn options_after_endofopt_are_ignored() {
    let options = concat(&[
        &option(Endian::Little, 0, &[]),
        &option(Endian::Little, 9, &[9]),
    ]);
    assert_eq!(
        options,
        [0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x01, 0x00, 0x09, 0x00, 0x00, 0x00]
    );
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &options),
        &enhanced_packet(Endian::Little, 0, 1_000_000_005, 1, 1, &[0xaa], &[]),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(capture.frames.len(), 1);
    assert_eq!(
        capture.frames[0].timestamp,
        Some(Timestamp {
            seconds: 1000,
            fraction: 5,
            unit: TimeUnit::Microsecond,
        })
    );
}

#[test]
fn tsoffset_after_endofopt_is_ignored() {
    let options = concat(&[
        &option(Endian::Little, 0, &[]),
        &option(Endian::Little, 14, &pack_i64(3600, Endian::Little)),
    ]);
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &options),
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0xaa], &[]),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(
        capture.frames[0].timestamp,
        Some(Timestamp {
            seconds: 0,
            fraction: 0,
            unit: TimeUnit::Microsecond,
        })
    );
}

#[test]
fn power_of_ten_tsresol_above_19_is_unsupported() {
    let resol = option(Endian::Little, 9, &[20]);
    assert_eq!(resol, [0x09, 0x00, 0x01, 0x00, 0x14, 0x00, 0x00, 0x00]);
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &resol),
        &enhanced_packet(Endian::Little, 0, 10, 1, 1, &[0xaa], &[]),
    ]);
    let capture = read_capture(&bytes);
    let fault = capture.fault.unwrap();

    assert_eq!(capture.frames.len(), 0);
    assert_eq!(
        fault,
        Fault::UnsupportedTsresol {
            binary: false,
            exponent: 20,
        }
    );
    assert_eq!(capture.exit_code(), 3);
    assert_eq!(
        fault.phrase(),
        "pcapng: IDB power-of-10 time stamp resolution 20 > 19"
    );
}

#[test]
fn power_of_two_tsresol_above_63_is_unsupported() {
    let resol = option(Endian::Little, 9, &[0xc0]);
    assert_eq!(resol, [0x09, 0x00, 0x01, 0x00, 0xc0, 0x00, 0x00, 0x00]);
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &resol),
        &enhanced_packet(Endian::Little, 0, 10, 1, 1, &[0xaa], &[]),
    ]);
    let capture = read_capture(&bytes);
    let fault = capture.fault.unwrap();

    assert_eq!(capture.frames.len(), 0);
    assert_eq!(
        fault,
        Fault::UnsupportedTsresol {
            binary: true,
            exponent: 64,
        }
    );
    assert_eq!(capture.exit_code(), 3);
    assert_eq!(
        fault.phrase(),
        "pcapng: IDB power-of-2 time stamp resolution 64 > 63"
    );
}

#[test]
fn shb_version_1_1_is_unsupported() {
    let header = section_header_version(Endian::Little, 1, 1);
    assert_eq!(
        &header[8..16],
        [0x4d, 0x3c, 0x2b, 0x1a, 0x01, 0x00, 0x01, 0x00]
    );
    let bytes = concat(&[
        &header,
        &interface_block(Endian::Little, 1, 65535, &[]),
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0xaa], &[]),
    ]);
    let capture = read_capture(&bytes);
    let fault = capture.fault.unwrap();

    assert_eq!(capture.frames.len(), 0);
    assert_eq!(
        fault,
        Fault::UnsupportedPcapngVersion { major: 1, minor: 1 }
    );
    assert_eq!(capture.exit_code(), 3);
    assert_eq!(fault.phrase(), "pcapng: unknown SHB version 1.1");
}

#[test]
fn a_later_shb_1_1_keeps_the_earlier_frame() {
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &[]),
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0x01], &[]),
        &section_header_version(Endian::Little, 1, 1),
        &interface_block(Endian::Little, 1, 65535, &[]),
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0x02], &[]),
    ]);
    let capture = read_capture(&bytes);
    let fault = capture.fault.unwrap();

    assert_eq!(capture.frames.len(), 1);
    assert_eq!(capture.frames[0].captured, &[0x01]);
    assert_eq!(
        fault,
        Fault::UnsupportedPcapngVersion { major: 1, minor: 1 }
    );
    assert_eq!(capture.exit_code(), 14);
    assert_eq!(fault.phrase(), "pcapng: unknown SHB version 1.1");
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
    assert_eq!(capture.exit_code(), 3);
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
    assert_eq!(capture.exit_code(), 14);
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
    assert_eq!(capture.exit_code(), 14);
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
    assert_eq!(capture.exit_code(), 14);
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
    assert_eq!(capture.exit_code(), 14);
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
    assert_eq!(capture.exit_code(), 14);
    assert_eq!(fault.phrase().contains("first 36 and second 40"), true);
}

#[test]
fn if_tsresol_is_used_only_when_the_length_is_one() {
    let resol = option(Endian::Little, 9, &[9, 0]);
    assert_eq!(resol, [0x09, 0x00, 0x02, 0x00, 0x09, 0x00, 0x00, 0x00]);
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &resol),
        &enhanced_packet(Endian::Little, 0, 1_000_000_005, 1, 1, &[0xaa], &[]),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(
        capture.frames[0].timestamp,
        Some(Timestamp {
            seconds: 1000,
            fraction: 5,
            unit: TimeUnit::Microsecond,
        })
    );
}

#[test]
fn if_tsoffset_is_used_only_when_the_length_is_eight() {
    let offset_nine = option(
        Endian::Little,
        14,
        &[0x10, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    );
    assert_eq!(
        &offset_nine[..13],
        [0x0e, 0x00, 0x09, 0x00, 0x10, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    );
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &offset_nine),
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0xaa], &[]),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(
        capture.frames[0].timestamp,
        Some(Timestamp {
            seconds: 0,
            fraction: 0,
            unit: TimeUnit::Microsecond,
        })
    );

    let mut offset_sixteen =
        concat(&[&pack_u16(14, Endian::Little), &pack_u16(16, Endian::Little)]);
    offset_sixteen.extend_from_slice(&pack_i64(3600, Endian::Little));
    offset_sixteen.extend_from_slice(&pack_i64(7200, Endian::Little));
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &offset_sixteen),
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0xaa], &[]),
    ]);
    let capture = read_capture(&bytes);
    assert_eq!(
        capture.frames[0].timestamp,
        Some(Timestamp {
            seconds: 0,
            fraction: 0,
            unit: TimeUnit::Microsecond,
        })
    );
}

#[test]
fn an_option_overrun_fails_the_idb() {
    let overrun = [0x09, 0x00, 0x64, 0x00, 0x09, 0x00, 0x00, 0x00];
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &[]),
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0x01], &[]),
        &interface_block(Endian::Little, 1, 65535, &overrun),
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0x02], &[]),
    ]);
    let capture = read_capture(&bytes);
    let fault = capture.fault.unwrap();

    assert_eq!(capture.frames.len(), 1);
    assert_eq!(capture.frames[0].captured, &[0x01]);
    assert_eq!(fault, Fault::OptionOverrun { length: 100 });
    assert_eq!(capture.exit_code(), 14);
    assert_eq!(
        fault.phrase(),
        "pcapng: Not enough data to handle option of length 100"
    );

    let opening = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &overrun),
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0x02], &[]),
    ]);
    let capture = read_capture(&opening);
    let fault = capture.fault.unwrap();
    assert_eq!(capture.frames.len(), 0);
    assert_eq!(fault, Fault::OptionOverrun { length: 100 });
    assert_eq!(capture.exit_code(), 3);
}

#[test]
fn if_filter_length_zero_fails_the_idb() {
    let filter = option(Endian::Little, 11, &[]);
    assert_eq!(filter, [0x0b, 0x00, 0x00, 0x00]);
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &[]),
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0x01], &[]),
        &interface_block(Endian::Little, 1, 65535, &filter),
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0x02], &[]),
    ]);
    let capture = read_capture(&bytes);
    let fault = capture.fault.unwrap();

    assert_eq!(capture.frames.len(), 1);
    assert_eq!(fault, Fault::IdbFilter { length: 0 });
    assert_eq!(capture.exit_code(), 14);
    assert_eq!(
        fault.phrase(),
        "pcapng: IDB interface filter option length 0 is < 1"
    );

    let opening = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &filter),
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0x02], &[]),
    ]);
    let capture = read_capture(&opening);
    assert_eq!(capture.frames.len(), 0);
    assert_eq!(capture.fault, Some(Fault::IdbFilter { length: 0 }));
    assert_eq!(capture.exit_code(), 3);
}

#[test]
fn if_tsoffset_wraps_like_a_signed_time_t() {
    let offset = option(Endian::Little, 14, &pack_i64(i64::MAX - 9, Endian::Little));
    assert_eq!(
        offset,
        [0x0e, 0x00, 0x08, 0x00, 0xf6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]
    );
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &offset),
        &enhanced_packet(Endian::Little, 0, 20_000_000, 1, 1, &[0xaa], &[]),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(
        capture.frames[0].timestamp,
        Some(Timestamp {
            seconds: -9223372036854775798,
            fraction: 0,
            unit: TimeUnit::Microsecond,
        })
    );
}

#[test]
fn a_fault_after_a_frame_exits_14() {
    let resol = option(Endian::Little, 9, &[20]);
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &[]),
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0x01], &[]),
        &interface_block(Endian::Little, 1, 65535, &resol),
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0x02], &[]),
    ]);
    let capture = read_capture(&bytes);
    let fault = capture.fault.unwrap();

    assert_eq!(capture.frames.len(), 1);
    assert_eq!(
        fault,
        Fault::UnsupportedTsresol {
            binary: false,
            exponent: 20,
        }
    );
    assert_eq!(capture.exit_code(), 14);
    assert_eq!(
        fault.phrase(),
        "pcapng: IDB power-of-10 time stamp resolution 20 > 19"
    );
}

#[test]
fn a_later_shb_1_1_before_any_frame_exits_3() {
    let bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &[]),
        &section_header_version(Endian::Little, 1, 1),
        &interface_block(Endian::Little, 1, 65535, &[]),
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0xaa], &[]),
    ]);
    let capture = read_capture(&bytes);
    let fault = capture.fault.unwrap();

    assert_eq!(capture.frames.len(), 0);
    assert_eq!(
        fault,
        Fault::UnsupportedPcapngVersion { major: 1, minor: 1 }
    );
    assert_eq!(capture.exit_code(), 3);
    assert_eq!(fault.phrase(), "pcapng: unknown SHB version 1.1");
}

#[test]
fn opening_shb_mismatched_lengths_exit_3() {
    let mut header = section_header(Endian::Little);
    header[24..28].copy_from_slice(&32u32.to_le_bytes());
    let capture = read_capture(&header);
    let fault = capture.fault.unwrap();

    assert_eq!(capture.frames.len(), 0);
    assert_eq!(
        fault,
        Fault::BlockLengths {
            first: 28,
            second: 32,
        }
    );
    assert_eq!(capture.exit_code(), 3);
    assert_eq!(
        fault.phrase(),
        "pcapng: total block lengths (first 28 and second 32) don't match"
    );
}

fn prefix(packet: Option<u8>) -> Vec<u8> {
    let mut bytes = concat(&[
        &section_header(Endian::Little),
        &interface_block(Endian::Little, 1, 65535, &[]),
    ]);
    if let Some(byte) = packet {
        bytes.extend_from_slice(&enhanced_packet(Endian::Little, 0, 0, 1, 1, &[byte], &[]));
    }
    bytes
}

fn epb_lengths(first: u32, second: u32) -> Vec<u8> {
    let body = concat(&[
        &pack_u32(0, Endian::Little),
        &pack_u32(0, Endian::Little),
        &pack_u32(0, Endian::Little),
        &pack_u32(1, Endian::Little),
        &pack_u32(1, Endian::Little),
        &[0xaa, 0x00, 0x00, 0x00],
    ]);
    block_with_lengths(Endian::Little, 6, &body, first, second)
}

#[test]
fn a_trailer_three_below_the_first_length_is_accepted() {
    let bytes = concat(&[&prefix(None), &epb_lengths(36, 35)]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(capture.frames.len(), 1);
    assert_eq!(capture.frames[0].captured, &[0xaa]);
    assert_eq!(capture.exit_code(), 0);
}

#[test]
fn a_trailer_that_rounds_up_to_the_first_length_is_accepted() {
    let bytes = concat(&[&prefix(None), &epb_lengths(36, 33)]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(capture.frames.len(), 1);
    assert_eq!(capture.frames[0].captured, &[0xaa]);
    assert_eq!(capture.exit_code(), 0);
}

#[test]
fn a_later_unaligned_epb_trailer_keeps_both_frames() {
    let bytes = concat(&[&prefix(Some(1)), &epb_lengths(36, 35)]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(capture.frames.len(), 2);
    assert_eq!(capture.frames[0].captured, &[1]);
    assert_eq!(capture.frames[1].captured, &[0xaa]);
    assert_eq!(capture.exit_code(), 0);
}

#[test]
fn opening_shb_first_length_27_still_opens() {
    let bytes = concat(&[
        &section_header_totals(Endian::Little, 27, 27),
        &interface_block(Endian::Little, 1, 65535, &[]),
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0xaa], &[]),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(capture.frames.len(), 1);
    assert_eq!(capture.frames[0].captured, &[0xaa]);
    assert_eq!(capture.exit_code(), 0);
}

#[test]
fn opening_shb_trailer_27_still_opens() {
    let bytes = concat(&[
        &section_header_totals(Endian::Little, 28, 27),
        &interface_block(Endian::Little, 1, 65535, &[]),
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0xaa], &[]),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(capture.frames.len(), 1);
    assert_eq!(capture.frames[0].captured, &[0xaa]);
    assert_eq!(capture.exit_code(), 0);
}

#[test]
fn a_trailer_that_does_not_round_to_the_first_length_fails() {
    let bytes = concat(&[&prefix(None), &epb_lengths(36, 32)]);
    let capture = read_capture(&bytes);
    let fault = capture.fault.unwrap();

    assert_eq!(capture.frames.len(), 0);
    assert_eq!(
        fault,
        Fault::BlockLengths {
            first: 36,
            second: 32
        }
    );
    assert_eq!(capture.exit_code(), 14);
}

#[test]
fn a_later_block_first_length_rounds_up_before_the_trailer() {
    let later = block_with_lengths(Endian::Little, 100, &[0, 0, 0, 0], 13, 16);
    let bytes = concat(&[&prefix(Some(1)), &later]);
    let capture = read_capture(&bytes);
    let fault = capture.fault.unwrap();

    assert_eq!(capture.frames.len(), 1);
    assert_eq!(
        fault,
        Fault::BlockLengths {
            first: 13,
            second: 16
        }
    );
    assert_eq!(capture.exit_code(), 14);
    assert_eq!(
        fault.phrase(),
        "pcapng: total block lengths (first 13 and second 16) don't match"
    );
}

#[test]
fn a_block_above_max_size_fails_after_a_frame() {
    let mut later = pack_u32(100, Endian::Little).to_vec();
    later.extend_from_slice(&200_000_000u32.to_le_bytes());
    let bytes = concat(&[&prefix(Some(1)), &later]);
    let capture = read_capture(&bytes);
    let fault = capture.fault.unwrap();

    assert_eq!(capture.frames.len(), 1);
    assert_eq!(
        fault,
        Fault::BlockTooLarge {
            length: 200_000_000
        }
    );
    assert_eq!(capture.exit_code(), 14);
    assert_eq!(
        fault.phrase(),
        "pcapng: total block length 200000000 is too large (> 134348832)"
    );
}

#[test]
fn a_journal_export_between_packets_is_a_frame() {
    let entry = b"__REALTIME_TIMESTAMP=0\n";
    let journal = block(Endian::Little, 9, &[entry.as_slice(), &[0]].concat());
    let bytes = concat(&[
        &prefix(Some(1)),
        &journal,
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0x02], &[]),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(capture.frames.len(), 3);
    assert_eq!(capture.frames[1].captured, entry.as_slice());
    assert_eq!(capture.frames[1].original_length, 23);
    assert_eq!(
        capture.frames[1].timestamp,
        Some(Timestamp {
            seconds: 0,
            fraction: 0,
            unit: TimeUnit::Microsecond,
        })
    );
    assert_eq!(capture.frames[2].captured, &[0x02]);
    assert_eq!(capture.exit_code(), 0);
}

#[test]
fn an_empty_journal_export_stops_the_file() {
    let bytes = concat(&[&prefix(Some(1)), &unknown_block(Endian::Little, 9)]);
    let capture = read_capture(&bytes);
    let fault = capture.fault.unwrap();

    assert_eq!(capture.frames.len(), 1);
    assert_eq!(
        fault,
        Fault::BlockBody {
            kind: BlockKind::Journal,
            length: 0
        }
    );
    assert_eq!(capture.exit_code(), 14);
    assert_eq!(
        fault.phrase(),
        "pcapng: block content length 0 of a systemd journal export is less than the minimum systemd journal export content size 23"
    );
}

#[test]
fn an_opening_journal_export_fault_exits_14() {
    let bytes = concat(&[&prefix(None), &unknown_block(Endian::Little, 9)]);
    let capture = read_capture(&bytes);
    let fault = capture.fault.unwrap();

    assert_eq!(capture.frames.len(), 0);
    assert_eq!(capture.exit_code(), 14);
    assert_eq!(
        fault.phrase(),
        "pcapng: block content length 0 of a systemd journal export is less than the minimum systemd journal export content size 23"
    );
}

#[test]
fn a_journal_export_without_packets_is_a_frame() {
    let entry = b"__REALTIME_TIMESTAMP=0\n";
    let journal = block(Endian::Little, 9, &[entry.as_slice(), &[0]].concat());
    let bytes = concat(&[&section_header(Endian::Little), &journal]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(capture.frames.len(), 1);
    assert_eq!(capture.frames[0].captured, entry.as_slice());
    assert_eq!(capture.frames[0].original_length, 23);
    assert_eq!(capture.exit_code(), 0);
}

#[test]
fn a_custom_block_between_packets_is_a_frame() {
    let custom = block(Endian::Little, 0x0000_0BAD, &pack_u32(1, Endian::Little));
    let bytes = concat(&[
        &prefix(Some(1)),
        &custom,
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0x02], &[]),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(capture.frames.len(), 3);
    assert_eq!(capture.frames[1].captured, b"");
    assert_eq!(capture.frames[1].original_length, 0);
    assert_eq!(capture.frames[2].captured, &[0x02]);
    assert_eq!(capture.exit_code(), 0);
}

#[test]
fn a_custom_block_without_packets_is_a_frame() {
    let custom = block(Endian::Little, 0x0000_0BAD, &pack_u32(1, Endian::Little));
    let bytes = concat(&[&section_header(Endian::Little), &custom]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(capture.frames.len(), 1);
    assert_eq!(capture.frames[0].captured, b"");
    assert_eq!(capture.exit_code(), 0);
}

#[test]
fn a_nocopy_custom_block_between_packets_is_a_frame() {
    let custom = block(Endian::Little, 0x4000_0BAD, &pack_u32(1, Endian::Little));
    let bytes = concat(&[
        &prefix(Some(1)),
        &custom,
        &enhanced_packet(Endian::Little, 0, 0, 1, 1, &[0x02], &[]),
    ]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.fault, None);
    assert_eq!(capture.frames.len(), 3);
    assert_eq!(capture.frames[1].captured, b"");
    assert_eq!(capture.frames[2].captured, &[0x02]);
    assert_eq!(capture.exit_code(), 0);
}

#[test]
fn an_empty_custom_block_stops_the_file() {
    let bytes = concat(&[
        &prefix(Some(1)),
        &unknown_block(Endian::Little, 0x0000_0BAD),
    ]);
    let capture = read_capture(&bytes);
    let fault = capture.fault.unwrap();

    assert_eq!(capture.frames.len(), 1);
    assert_eq!(
        fault,
        Fault::BlockBody {
            kind: BlockKind::Custom,
            length: 0
        }
    );
    assert_eq!(capture.exit_code(), 14);
    assert_eq!(
        fault.phrase(),
        "pcapng: block content length 0 of a CB is less than the minimum CB content size 4"
    );
}

#[test]
fn an_isb_custom_option_stops_the_file() {
    let isb = block(
        Endian::Little,
        5,
        &concat(&[
            &pack_u32(0, Endian::Little),
            &pack_u32(0, Endian::Little),
            &pack_u32(0, Endian::Little),
            &option(Endian::Little, 2988, &[]),
        ]),
    );
    let bytes = concat(&[&prefix(Some(1)), &isb]);
    let capture = read_capture(&bytes);
    let fault = capture.fault.unwrap();

    assert_eq!(capture.frames.len(), 1);
    assert_eq!(fault, Fault::CustomOption { length: 0 });
    assert_eq!(capture.exit_code(), 14);
}

#[test]
fn an_opening_isb_custom_option_exits_3() {
    let isb = block(
        Endian::Little,
        5,
        &concat(&[
            &pack_u32(0, Endian::Little),
            &pack_u32(0, Endian::Little),
            &pack_u32(0, Endian::Little),
            &option(Endian::Little, 2988, &[]),
        ]),
    );
    let bytes = concat(&[&prefix(None), &isb]);
    let capture = read_capture(&bytes);

    assert_eq!(capture.frames.len(), 0);
    assert_eq!(capture.exit_code(), 3);
    assert_eq!(
        capture.fault.unwrap().phrase(),
        "pcapng: option length (0) too small for custom option"
    );
}

#[test]
fn an_empty_dsb_stops_the_file() {
    let bytes = concat(&[&prefix(Some(1)), &unknown_block(Endian::Little, 10)]);
    let capture = read_capture(&bytes);
    let fault = capture.fault.unwrap();

    assert_eq!(capture.frames.len(), 1);
    assert_eq!(
        fault,
        Fault::BlockBody {
            kind: BlockKind::Dsb,
            length: 0
        }
    );
    assert_eq!(capture.exit_code(), 14);
    assert_eq!(
        fault.phrase(),
        "pcapng: block content length 0 of an DSB is less than the minimum DSB content size 8"
    );
}

#[test]
fn an_nrb_custom_option_stops_the_file() {
    let nrb = block(
        Endian::Little,
        4,
        &concat(&[
            &pack_u16(0, Endian::Little),
            &pack_u16(0, Endian::Little),
            &option(Endian::Little, 2988, &[]),
        ]),
    );
    let bytes = concat(&[&prefix(Some(1)), &nrb]);
    let capture = read_capture(&bytes);
    let fault = capture.fault.unwrap();

    assert_eq!(capture.frames.len(), 1);
    assert_eq!(fault, Fault::CustomOption { length: 0 });
    assert_eq!(capture.exit_code(), 14);
}

#[test]
fn an_nrb_ipv4_record_length_two_stops_the_file() {
    let nrb = block(
        Endian::Little,
        4,
        &concat(&[
            &pack_u16(1, Endian::Little),
            &pack_u16(2, Endian::Little),
            &[0xaa, 0xbb, 0x00, 0x00],
            &pack_u16(0, Endian::Little),
            &pack_u16(0, Endian::Little),
        ]),
    );
    let bytes = concat(&[&prefix(Some(1)), &nrb]);
    let capture = read_capture(&bytes);
    let fault = capture.fault.unwrap();

    assert_eq!(capture.frames.len(), 1);
    assert_eq!(fault, Fault::NrbIpv4 { length: 2 });
    assert_eq!(capture.exit_code(), 14);
    assert_eq!(
        fault.phrase(),
        "pcapng: NRB IPv4 record length 2 < minimum length 4"
    );
}
