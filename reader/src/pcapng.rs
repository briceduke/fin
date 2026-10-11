use crate::options::{self, IdOptions};
use crate::{
    BlockKind, Capture, CaptureKind, Fault, Frame, TimeUnit, Timestamp, MAX_BLOCK_SIZE,
    MAX_CAPTURED_LENGTH,
};

const SHB_MAGIC: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];
const SHB_TYPE: u32 = 0x0A0D0D0A;
const SHB_MIN: u32 = 28;
const BLOCK_MIN: u32 = 12;
const IDB_TYPE: u32 = 1;
const OPB_TYPE: u32 = 2;
const SPB_TYPE: u32 = 3;
const NRB_TYPE: u32 = 4;
const ISB_TYPE: u32 = 5;
const EPB_TYPE: u32 = 6;
const JOURNAL_TYPE: u32 = 9;
const DSB_TYPE: u32 = 10;
const CB_COPY: u32 = 0x0000_0BAD;
const CB_NO_COPY: u32 = 0x4000_0BAD;
const JOURNAL_MIN: usize = 23;
const JOURNAL_KEY: &[u8] = b"__REALTIME_TIMESTAMP=";
const LE_ORDER: [u8; 4] = [0x4d, 0x3c, 0x2b, 0x1a];
const BE_ORDER: [u8; 4] = [0x1a, 0x2b, 0x3c, 0x4d];

/// tshark 4.6.9 `register_pcapng_block_type_information`. `packet` is
/// `!handler->internal`: those blocks are rows, and a fault on them is
/// exit 14 even when no row was produced.
const BLOCKS: &[(u32, bool)] = &[
    (SHB_TYPE, false),
    (IDB_TYPE, false),
    (OPB_TYPE, true),
    (SPB_TYPE, true),
    (NRB_TYPE, false),
    (ISB_TYPE, false),
    (EPB_TYPE, true),
    (JOURNAL_TYPE, true),
    (DSB_TYPE, false),
    (CB_COPY, true),
    (CB_NO_COPY, true),
];

struct Interface {
    link_type: u32,
    snaplen: u32,
    resol: u8,
    tsoffset: i64,
}

struct Packet {
    interface_id: u32,
    ticks: Option<u64>,
    captured_len: u32,
    original_len: u32,
    packet_at: usize,
}

pub(crate) fn read<'a>(bytes: &'a [u8]) -> Capture<'a> {
    match open_section(bytes) {
        Ok((big_endian, offset)) => blocks(bytes, big_endian, offset),
        Err(fault) => Capture::halt(Vec::new(), fault, false),
    }
}

fn open_section(bytes: &[u8]) -> Result<(bool, usize), Fault> {
    if bytes.len() < SHB_MIN as usize || bytes[..4] != SHB_MAGIC {
        return Err(Fault::NotACaptureFile);
    }
    let big_endian = match endian_at(bytes, 8) {
        Some(big_endian) => big_endian,
        None => return Err(Fault::NotACaptureFile),
    };
    let total = block_total(bytes, 0, big_endian, SHB_MIN, Fault::NotACaptureFile, true)?;
    shb_version(bytes, 0, big_endian)?;
    options::walk_shb(bytes, 24, total - 4, big_endian)?;
    Ok((big_endian, total))
}

fn shb_version(bytes: &[u8], offset: usize, big_endian: bool) -> Result<(), Fault> {
    let major = u16_at(bytes, offset + 12, big_endian);
    let minor = u16_at(bytes, offset + 14, big_endian);
    if major == 1 && (minor == 0 || minor == 2) {
        Ok(())
    } else {
        Err(Fault::UnsupportedPcapngVersion { major, minor })
    }
}

fn blocks<'a>(bytes: &'a [u8], mut big_endian: bool, mut offset: usize) -> Capture<'a> {
    let mut frames = Vec::new();
    let mut interfaces = Vec::new();
    let mut after_packet = false;
    let mut last_ts = None;
    while offset < bytes.len() {
        let (block_type, total, endian) = match block_at(bytes, offset, big_endian) {
            Ok(found) => found,
            Err(fault) => {
                if packet_type_at(bytes, offset, big_endian) {
                    after_packet = true;
                }
                return Capture::halt(frames, fault, after_packet);
            }
        };
        big_endian = endian;
        if is_packet(block_type) {
            after_packet = true;
        }
        if let Err(fault) = consume(
            bytes,
            offset,
            total,
            block_type,
            big_endian,
            &mut interfaces,
            &mut frames,
            &mut last_ts,
        ) {
            return Capture::halt(frames, fault, after_packet);
        }
        offset += total;
    }
    Capture::ok(frames)
}

fn is_packet(block_type: u32) -> bool {
    BLOCKS
        .iter()
        .any(|&(id, packet)| id == block_type && packet)
}

fn packet_type_at(bytes: &[u8], offset: usize, big_endian: bool) -> bool {
    bytes.len() - offset >= 8 && is_packet(u32_at(bytes, offset, big_endian))
}

fn block_at(bytes: &[u8], offset: usize, big_endian: bool) -> Result<(u32, usize, bool), Fault> {
    let rest = bytes.len() - offset;
    if rest < 8 {
        return Err(Fault::CutShort);
    }
    let block_type = u32_at(bytes, offset, big_endian);
    if block_type != SHB_TYPE {
        let total = block_total(bytes, offset, big_endian, BLOCK_MIN, Fault::CutShort, false)?;
        return Ok((block_type, total, big_endian));
    }
    if rest < 12 {
        return Err(Fault::CutShort);
    }
    let endian = match endian_at(bytes, offset + 8) {
        Some(endian) => endian,
        None => return Err(Fault::CutShort),
    };
    let total = block_total(bytes, offset, endian, SHB_MIN, Fault::CutShort, true)?;
    Ok((block_type, total, endian))
}

fn block_total(
    bytes: &[u8],
    offset: usize,
    big_endian: bool,
    minimum: u32,
    short: Fault,
    round_first: bool,
) -> Result<usize, Fault> {
    let rest = bytes.len() - offset;
    if rest < 8 {
        return Err(short);
    }
    let first = u32_at(bytes, offset + 4, big_endian);
    let padded = roundup4_u32(first);
    let stored = if round_first { padded } else { first };
    if stored < minimum {
        return Err(short);
    }
    if padded < first || padded > MAX_BLOCK_SIZE {
        return Err(Fault::BlockTooLarge { length: first });
    }
    let total = padded as usize;
    if rest < total {
        return Err(short);
    }
    let second = u32_at(bytes, offset + total - 4, big_endian);
    let rounded_second = roundup4_u32(second);
    if rounded_second != stored {
        return Err(Fault::BlockLengths {
            first: stored,
            second: rounded_second,
        });
    }
    Ok(total)
}

fn consume<'a>(
    bytes: &'a [u8],
    offset: usize,
    total: usize,
    block_type: u32,
    big_endian: bool,
    interfaces: &mut Vec<Interface>,
    frames: &mut Vec<Frame<'a>>,
    last_ts: &mut Option<Timestamp>,
) -> Result<(), Fault> {
    // Same set as BLOCKS. Unknown types are skipped.
    match block_type {
        SHB_TYPE => {
            shb_version(bytes, offset, big_endian)?;
            options::walk_shb(bytes, offset + 24, offset + total - 4, big_endian)?;
            interfaces.clear();
        }
        IDB_TYPE => interfaces.push(interface(bytes, offset, total, big_endian)?),
        EPB_TYPE => push_stamp(
            frames,
            enhanced(bytes, offset, total, big_endian, interfaces)?,
            last_ts,
        ),
        SPB_TYPE => {
            frames.push(simple(bytes, offset, total, big_endian, interfaces)?);
            *last_ts = None;
        }
        OPB_TYPE => push_stamp(
            frames,
            obsolete(bytes, offset, total, big_endian, interfaces)?,
            last_ts,
        ),
        ISB_TYPE => isb(bytes, offset, total, big_endian)?,
        NRB_TYPE => nrb(bytes, offset, total, big_endian)?,
        DSB_TYPE => dsb(bytes, offset, total, big_endian)?,
        CB_COPY | CB_NO_COPY => {
            let mut frame = custom(bytes, offset, total)?;
            frame.timestamp = *last_ts;
            frames.push(frame);
        }
        JOURNAL_TYPE => {
            let frame = journal(bytes, offset, total)?;
            *last_ts = frame.timestamp;
            frames.push(frame);
        }
        _ => {}
    }
    Ok(())
}

fn push_stamp<'a>(frames: &mut Vec<Frame<'a>>, frame: Frame<'a>, last_ts: &mut Option<Timestamp>) {
    *last_ts = frame.timestamp;
    frames.push(frame);
}

fn interface(
    bytes: &[u8],
    offset: usize,
    total: usize,
    big_endian: bool,
) -> Result<Interface, Fault> {
    if total < 20 {
        return Err(Fault::CutShort);
    }
    let at = offset + 8;
    let IdOptions { resol, tsoffset } =
        options::walk_idb(bytes, at + 8, offset + total - 4, big_endian)?;
    Ok(Interface {
        link_type: u32::from(u16_at(bytes, at, big_endian)),
        snaplen: u32_at(bytes, at + 4, big_endian),
        resol,
        tsoffset,
    })
}

fn align4(len: usize) -> usize {
    len.saturating_add(3) & !3
}

fn roundup4_u32(n: u32) -> u32 {
    n.wrapping_add(3) & !3
}

fn content(bytes: &[u8], offset: usize, total: usize) -> &[u8] {
    &bytes[offset + 8..offset + total - 4]
}

fn too_small(kind: BlockKind, length: usize) -> Fault {
    Fault::BlockBody {
        kind,
        length: length as u32,
    }
}

fn isb(bytes: &[u8], offset: usize, total: usize, big_endian: bool) -> Result<(), Fault> {
    let body = content(bytes, offset, total);
    if body.len() < 12 {
        return Err(too_small(BlockKind::Isb, body.len()));
    }
    options::walk_common(bytes, offset + 20, offset + total - 4, big_endian)
}

fn nrb(bytes: &[u8], offset: usize, total: usize, big_endian: bool) -> Result<(), Fault> {
    let end = offset + total - 4;
    let mut cursor = offset + 8;
    if end - cursor < 4 {
        return Err(too_small(BlockKind::Nrb, end - cursor));
    }
    loop {
        let left = end - cursor;
        if left == 0 {
            return Ok(());
        }
        if left < 4 {
            return Err(Fault::NrbShort { left: left as u32 });
        }
        let rec_type = u16_at(bytes, cursor, big_endian);
        let rec_len = u16_at(bytes, cursor + 2, big_endian);
        cursor += 4;
        let need = align4(usize::from(rec_len));
        let remaining = end - cursor;
        if remaining < need {
            return Err(Fault::NrbPad {
                left: remaining as u32,
                need: need as u32,
            });
        }
        match rec_type {
            0 => return options::walk_common(bytes, cursor, end, big_endian),
            1 => {
                if rec_len < 4 {
                    return Err(Fault::NrbIpv4 {
                        length: u32::from(rec_len),
                    });
                }
                nrb_names(&bytes[cursor + 4..cursor + usize::from(rec_len)])?;
            }
            2 => {
                if rec_len < 16 {
                    return Err(Fault::NrbIpv6 {
                        length: u32::from(rec_len),
                    });
                }
                nrb_names(&bytes[cursor + 16..cursor + usize::from(rec_len)])?;
            }
            _ => {}
        }
        cursor += need;
    }
}

fn nrb_names(names: &[u8]) -> Result<(), Fault> {
    let mut rest = names;
    while !rest.is_empty() {
        match rest.iter().position(|&byte| byte == 0) {
            Some(end) => rest = &rest[end + 1..],
            None => return Err(Fault::NrbName),
        }
    }
    Ok(())
}

fn dsb(bytes: &[u8], offset: usize, total: usize, big_endian: bool) -> Result<(), Fault> {
    let body = content(bytes, offset, total);
    if body.len() < 8 {
        return Err(too_small(BlockKind::Dsb, body.len()));
    }
    let secrets_len = u32_at(bytes, offset + 12, big_endian);
    let needed = 8u32.saturating_add(secrets_len);
    if (body.len() as u32) < needed {
        return Err(Fault::DsbSecrets {
            length: body.len() as u32,
            needed,
        });
    }
    if secrets_len > 1024 * 1024 * 1024 {
        return Err(Fault::DsbHuge {
            length: secrets_len,
        });
    }
    Ok(())
}

fn custom(bytes: &[u8], offset: usize, total: usize) -> Result<Frame<'_>, Fault> {
    let body = content(bytes, offset, total);
    if body.len() < 4 {
        return Err(too_small(BlockKind::Custom, body.len()));
    }
    let captured = &body[4..];
    Ok(Frame {
        link_type: 0,
        timestamp: None,
        original_length: captured.len() as u32,
        captured,
    })
}

fn journal(bytes: &[u8], offset: usize, total: usize) -> Result<Frame<'_>, Fault> {
    let body = content(bytes, offset, total);
    if body.len() < JOURNAL_MIN {
        return Err(too_small(BlockKind::Journal, body.len()));
    }
    let mut length = body.len();
    while length > 0 && body[length - 1] == 0 {
        length -= 1;
    }
    if length < JOURNAL_MIN {
        return Err(Fault::JournalEntry {
            length: length as u32,
        });
    }
    let captured = &body[..length];
    Ok(Frame {
        link_type: 0,
        timestamp: journal_time(captured),
        original_length: captured.len() as u32,
        captured,
    })
}

fn journal_time(entry: &[u8]) -> Option<Timestamp> {
    let start = entry
        .windows(JOURNAL_KEY.len())
        .position(|window| window == JOURNAL_KEY)?;
    let ticks = ws_strtou64(&entry[start + JOURNAL_KEY.len()..])?;
    Some(Timestamp {
        seconds: (ticks / 1_000_000) as i64,
        fraction: (ticks % 1_000_000) as u32,
        unit: TimeUnit::Microsecond,
    })
}

/// tshark 4.6.9 `ws_strtou64` with `endptr` set (pcapng.c journal stamp).
fn ws_strtou64(bytes: &[u8]) -> Option<u64> {
    match bytes.first() {
        Some(b'+' | b'-') | None => return None,
        _ => {}
    }
    let mut rest = bytes;
    while let Some((&byte, tail)) = rest.split_first() {
        if !byte.is_ascii_whitespace() {
            break;
        }
        rest = tail;
    }
    let negative = match rest.split_first() {
        Some((b'+', tail)) => {
            rest = tail;
            false
        }
        Some((b'-', tail)) => {
            rest = tail;
            true
        }
        _ => false,
    };
    let mut ticks = 0u64;
    let mut seen = false;
    for &byte in rest {
        if !byte.is_ascii_digit() {
            break;
        }
        seen = true;
        ticks = ticks.checked_mul(10)?.checked_add(u64::from(byte - b'0'))?;
    }
    if !seen {
        return None;
    }
    Some(if negative {
        0u64.wrapping_sub(ticks)
    } else {
        ticks
    })
}

fn enhanced<'a>(
    bytes: &'a [u8],
    offset: usize,
    total: usize,
    big_endian: bool,
    interfaces: &[Interface],
) -> Result<Frame<'a>, Fault> {
    if total < 32 {
        return Err(Fault::CutShort);
    }
    let at = offset + 8;
    frame(
        bytes,
        Packet {
            interface_id: u32_at(bytes, at, big_endian),
            ticks: Some(ticks_at(bytes, at + 4, big_endian)),
            captured_len: u32_at(bytes, at + 12, big_endian),
            original_len: u32_at(bytes, at + 16, big_endian),
            packet_at: at + 20,
        },
        offset + total - 4,
        interfaces,
        Some(big_endian),
    )
}

fn simple<'a>(
    bytes: &'a [u8],
    offset: usize,
    total: usize,
    big_endian: bool,
    interfaces: &[Interface],
) -> Result<Frame<'a>, Fault> {
    if total < 16 {
        return Err(Fault::CutShort);
    }
    let Some(snaplen) = interfaces.first().map(|iface| iface.snaplen) else {
        return Err(Fault::BadInterface {
            index: 0,
            interfaces: 0,
        });
    };
    let original_len = u32_at(bytes, offset + 8, big_endian);
    frame(
        bytes,
        Packet {
            interface_id: 0,
            ticks: None,
            captured_len: captured_from_snaplen(original_len, snaplen),
            original_len,
            packet_at: offset + 12,
        },
        offset + total - 4,
        interfaces,
        None,
    )
}

fn captured_from_snaplen(original_len: u32, snaplen: u32) -> u32 {
    if snaplen == 0 {
        original_len
    } else {
        original_len.min(snaplen)
    }
}

fn obsolete<'a>(
    bytes: &'a [u8],
    offset: usize,
    total: usize,
    big_endian: bool,
    interfaces: &[Interface],
) -> Result<Frame<'a>, Fault> {
    if total < 32 {
        return Err(Fault::CutShort);
    }
    let at = offset + 8;
    frame(
        bytes,
        Packet {
            interface_id: u32::from(u16_at(bytes, at, big_endian)),
            ticks: Some(ticks_at(bytes, at + 4, big_endian)),
            captured_len: u32_at(bytes, at + 12, big_endian),
            original_len: u32_at(bytes, at + 16, big_endian),
            packet_at: at + 20,
        },
        offset + total - 4,
        interfaces,
        Some(big_endian),
    )
}

fn frame<'a>(
    bytes: &'a [u8],
    packet: Packet,
    data_end: usize,
    interfaces: &[Interface],
    packet_options: Option<bool>,
) -> Result<Frame<'a>, Fault> {
    if packet.captured_len > MAX_CAPTURED_LENGTH {
        return Err(Fault::CapturedLengthTooBig {
            length: packet.captured_len,
            kind: CaptureKind::Pcapng,
        });
    }
    let Some(iface) = interfaces.get(packet.interface_id as usize) else {
        return Err(Fault::BadInterface {
            index: packet.interface_id,
            interfaces: interfaces.len() as u32,
        });
    };
    let captured = packet_bytes(bytes, packet.packet_at, packet.captured_len, data_end)?;
    if let Some(big_endian) = packet_options {
        let packet_end = packet.packet_at + packet.captured_len as usize;
        let options_at = align4(packet_end);
        if options_at > data_end {
            return Err(Fault::CutShort);
        }
        options::walk_packet(bytes, options_at, data_end, big_endian)?;
    }
    Ok(Frame {
        link_type: iface.link_type,
        timestamp: packet
            .ticks
            .map(|ticks| with_offset(timestamp(ticks, iface.resol), iface.tsoffset)),
        original_length: packet.original_len,
        captured,
    })
}

fn with_offset(stamp: Timestamp, offset: i64) -> Timestamp {
    Timestamp {
        seconds: add_seconds(stamp.seconds, offset),
        fraction: stamp.fraction,
        unit: stamp.unit,
    }
}

fn add_seconds(seconds: i64, offset: i64) -> i64 {
    seconds.wrapping_add(offset)
}

fn packet_bytes<'a>(
    bytes: &'a [u8],
    packet_at: usize,
    captured_len: u32,
    data_end: usize,
) -> Result<&'a [u8], Fault> {
    let Some(end) = packet_at.checked_add(captured_len as usize) else {
        return Err(Fault::CutShort);
    };
    if end > data_end {
        return Err(Fault::CutShort);
    }
    Ok(&bytes[packet_at..end])
}

fn timestamp(ticks: u64, resol: u8) -> Timestamp {
    if resol & 0x80 != 0 {
        let nanos = (u128::from(ticks) * 1_000_000_000) >> (resol & 0x7f);
        return split(nanos, 1_000_000_000, TimeUnit::Nanosecond);
    }
    let resol = u32::from(resol);
    if resol <= 6 {
        let micros = u128::from(ticks) * pow10(6 - resol);
        return split(micros, 1_000_000, TimeUnit::Microsecond);
    }
    let nanos = if resol < 9 {
        u128::from(ticks) * pow10(9 - resol)
    } else if resol == 9 {
        u128::from(ticks)
    } else {
        div_pow10(u128::from(ticks), resol - 9)
    };
    split(nanos, 1_000_000_000, TimeUnit::Nanosecond)
}

fn split(ticks: u128, scale: u128, unit: TimeUnit) -> Timestamp {
    Timestamp {
        seconds: (ticks / scale) as i64,
        fraction: (ticks % scale) as u32,
        unit,
    }
}

fn pow10(exp: u32) -> u128 {
    let mut scale = 1u128;
    for _ in 0..exp {
        scale *= 10;
    }
    scale
}

fn div_pow10(value: u128, exp: u32) -> u128 {
    let mut out = value;
    for _ in 0..exp {
        out /= 10;
    }
    out
}

fn ticks_at(bytes: &[u8], offset: usize, big_endian: bool) -> u64 {
    let high = u64::from(u32_at(bytes, offset, big_endian));
    let low = u64::from(u32_at(bytes, offset + 4, big_endian));
    (high << 32) | low
}

fn endian_at(bytes: &[u8], offset: usize) -> Option<bool> {
    match [
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ] {
        LE_ORDER => Some(false),
        BE_ORDER => Some(true),
        _ => None,
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
