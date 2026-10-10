use crate::{Capture, CaptureKind, Fault, Frame, TimeUnit, Timestamp, MAX_CAPTURED_LENGTH};

const HEADER_LEN: usize = 24;
const RECORD_LEN: usize = 16;

pub(crate) fn read<'a>(bytes: &'a [u8]) -> Capture<'a> {
    if bytes.len() < HEADER_LEN {
        return stopped(Vec::new(), Fault::TruncatedHeader);
    }
    let (big_endian, unit) = layout(bytes);
    let link_type = u32_at(bytes, 20, big_endian);
    if !matches!(link_type, 1 | 113 | 276) {
        return stopped(Vec::new(), Fault::UnsupportedLinkType { link_type });
    }
    records(bytes, big_endian, unit, link_type)
}

fn layout(bytes: &[u8]) -> (bool, TimeUnit) {
    match [bytes[0], bytes[1], bytes[2], bytes[3]] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (false, TimeUnit::Microsecond),
        [0xa1, 0xb2, 0xc3, 0xd4] => (true, TimeUnit::Microsecond),
        [0x4d, 0x3c, 0xb2, 0xa1] => (false, TimeUnit::Nanosecond),
        [0xa1, 0xb2, 0x3c, 0x4d] => (true, TimeUnit::Nanosecond),
        _ => unreachable!(),
    }
}

fn records<'a>(bytes: &'a [u8], big_endian: bool, unit: TimeUnit, link_type: u32) -> Capture<'a> {
    let mut frames = Vec::new();
    let mut offset = HEADER_LEN;
    while offset < bytes.len() {
        if bytes.len() - offset < RECORD_LEN {
            return stopped(frames, Fault::CutShort);
        }
        let [seconds, fraction, included, original] = header_words(bytes, offset, big_endian);
        if included > MAX_CAPTURED_LENGTH {
            return stopped(
                frames,
                Fault::CapturedLengthTooBig {
                    length: included,
                    kind: CaptureKind::Pcap,
                },
            );
        }
        let start = offset + RECORD_LEN;
        if bytes.len() - start < included as usize {
            return stopped(frames, Fault::CutShort);
        }
        let end = start + included as usize;
        frames.push(Frame {
            link_type,
            timestamp: Some(Timestamp {
                seconds: u64::from(seconds),
                fraction,
                unit,
            }),
            original_length: original,
            captured: &bytes[start..end],
        });
        offset = end;
    }
    Capture {
        frames,
        fault: None,
    }
}

fn header_words(bytes: &[u8], offset: usize, big_endian: bool) -> [u32; 4] {
    [
        u32_at(bytes, offset, big_endian),
        u32_at(bytes, offset + 4, big_endian),
        u32_at(bytes, offset + 8, big_endian),
        u32_at(bytes, offset + 12, big_endian),
    ]
}

fn stopped<'a>(frames: Vec<Frame<'a>>, fault: Fault) -> Capture<'a> {
    Capture {
        frames,
        fault: Some(fault),
    }
}

fn u32_at(bytes: &[u8], offset: usize, big_endian: bool) -> u32 {
    let raw = [bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]];
    if big_endian {
        u32::from_be_bytes(raw)
    } else {
        u32::from_le_bytes(raw)
    }
}
