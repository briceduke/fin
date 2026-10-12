use crate::{Capture, CaptureKind, Fault, Frame, MAX_CAPTURED_LENGTH};

const HEADER_LEN: usize = 24;
const RECORD_LEN: usize = 16;

#[derive(Clone, Copy)]
enum Lengths {
    NotSwapped,
    Swapped,
    MaybeSwapped,
}

pub(crate) fn read<'a>(bytes: &'a [u8]) -> Capture<'a> {
    if bytes.len() < HEADER_LEN {
        return Capture::halt(Vec::new(), Fault::TruncatedHeader, false);
    }
    let big_endian = layout(bytes);
    let major = u16_at(bytes, 4, big_endian);
    if major < 2 {
        return Capture::halt(Vec::new(), Fault::UnsupportedPcapVersion { major }, false);
    }
    let minor = u16_at(bytes, 6, big_endian);
    let link_type = u32_at(bytes, 20, big_endian);
    if !matches!(link_type, 1 | 113 | 276) {
        return Capture::halt(Vec::new(), Fault::UnsupportedLinkType { link_type }, false);
    }
    records(bytes, big_endian, link_type, lengths(major, minor))
}

fn layout(bytes: &[u8]) -> bool {
    matches!(
        [bytes[0], bytes[1], bytes[2], bytes[3]],
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d]
    )
}

fn lengths(major: u16, minor: u16) -> Lengths {
    match (major, minor) {
        (2, 0..=2) => Lengths::Swapped,
        (2, 3) => Lengths::MaybeSwapped,
        (543, _) => Lengths::Swapped,
        _ => Lengths::NotSwapped,
    }
}

fn order(included: u32, original: u32, lengths: Lengths) -> (u32, u32) {
    match lengths {
        Lengths::NotSwapped => (included, original),
        Lengths::Swapped => (original, included),
        Lengths::MaybeSwapped if included <= original => (included, original),
        Lengths::MaybeSwapped => (original, included),
    }
}

fn records<'a>(
    bytes: &'a [u8],
    big_endian: bool,
    link_type: u32,
    lengths: Lengths,
) -> Capture<'a> {
    let mut frames = Vec::new();
    let mut offset = HEADER_LEN;
    while offset < bytes.len() {
        if bytes.len() - offset < RECORD_LEN {
            return Capture::halt(frames, Fault::CutShort, true);
        }
        let included = u32_at(bytes, offset + 8, big_endian);
        let original = u32_at(bytes, offset + 12, big_endian);
        let (included, _) = order(included, original, lengths);
        if included > MAX_CAPTURED_LENGTH {
            return Capture::halt(
                frames,
                Fault::CapturedLengthTooBig {
                    length: included,
                    kind: CaptureKind::Pcap,
                },
                true,
            );
        }
        let start = offset + RECORD_LEN;
        if bytes.len() - start < included as usize {
            return Capture::halt(frames, Fault::CutShort, true);
        }
        let end = start + included as usize;
        frames.push(Frame {
            link_type,
            captured: &bytes[start..end],
        });
        offset = end;
    }
    Capture::ok(frames)
}

fn u16_at(bytes: &[u8], offset: usize, big_endian: bool) -> u16 {
    let raw = [bytes[offset], bytes[offset + 1]];
    if big_endian {
        u16::from_be_bytes(raw)
    } else {
        u16::from_le_bytes(raw)
    }
}

fn u32_at(bytes: &[u8], offset: usize, big_endian: bool) -> u32 {
    let raw = [
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ];
    if big_endian {
        u32::from_be_bytes(raw)
    } else {
        u32::from_le_bytes(raw)
    }
}
