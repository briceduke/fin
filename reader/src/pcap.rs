use crate::{Capture, CaptureKind, Fault, Frame, MAX_CAPTURED_LENGTH};

pub(crate) const HEADER_LEN: usize = 24;
const RECORD_LEN: usize = 16;

#[derive(Clone, Copy)]
enum Lengths {
    NotSwapped,
    Swapped,
    MaybeSwapped,
}

#[derive(Clone, Copy)]
pub(crate) struct Layout {
    big_endian: bool,
    link_type: u32,
    lengths: Lengths,
}

pub(crate) fn read(bytes: &[u8]) -> Capture<'_> {
    let layout = match open(bytes) {
        Ok(layout) => layout,
        Err(fault) => return Capture::halt(Vec::new(), fault, false),
    };
    let mut frames = Vec::new();
    let mut offset = HEADER_LEN;
    while offset < bytes.len() {
        match record_at(bytes, offset, layout) {
            Ok((frame, next)) => {
                frames.push(frame);
                offset = next;
            }
            Err(fault) => return Capture::halt(frames, fault, true),
        }
    }
    Capture::ok(frames)
}

pub(crate) fn open(bytes: &[u8]) -> Result<Layout, Fault> {
    if bytes.len() < HEADER_LEN {
        return Err(Fault::TruncatedHeader);
    }
    let big_endian = layout(bytes);
    let major = u16_at(bytes, 4, big_endian);
    if major < 2 {
        return Err(Fault::UnsupportedPcapVersion { major });
    }
    let minor = u16_at(bytes, 6, big_endian);
    let link_type = u32_at(bytes, 20, big_endian);
    if !matches!(link_type, 1 | 113 | 276) {
        return Err(Fault::UnsupportedLinkType { link_type });
    }
    Ok(Layout {
        big_endian,
        link_type,
        lengths: lengths(major, minor),
    })
}

/// One complete record at `offset`, and the start of the next.
pub(crate) fn record_at(
    bytes: &[u8],
    offset: usize,
    layout: Layout,
) -> Result<(Frame<'_>, usize), Fault> {
    if bytes.len() - offset < RECORD_LEN {
        return Err(Fault::CutShort);
    }
    let included = u32_at(bytes, offset + 8, layout.big_endian);
    let original = u32_at(bytes, offset + 12, layout.big_endian);
    let (included, _) = order(included, original, layout.lengths);
    if included > MAX_CAPTURED_LENGTH {
        return Err(Fault::CapturedLengthTooBig {
            length: included,
            kind: CaptureKind::Pcap,
        });
    }
    let start = offset + RECORD_LEN;
    if bytes.len() - start < included as usize {
        return Err(Fault::CutShort);
    }
    let end = start + included as usize;
    Ok((
        Frame {
            link_type: layout.link_type,
            captured: &bytes[start..end],
        },
        end,
    ))
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
