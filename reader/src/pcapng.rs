use crate::{Capture, CaptureKind, Fault, Frame, TimeUnit, Timestamp, MAX_CAPTURED_LENGTH};

const SHB_MAGIC: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];
const SHB_TYPE: u32 = 0x0A0D0D0A;
const SHB_MIN: u32 = 28;
const BLOCK_MIN: u32 = 12;
const IDB_TYPE: u32 = 1;
const OPB_TYPE: u32 = 2;
const SPB_TYPE: u32 = 3;
const EPB_TYPE: u32 = 6;
const IF_TSRESOL: u16 = 9;
const DEFAULT_RESOL: u8 = 6;
const LE_ORDER: [u8; 4] = [0x4d, 0x3c, 0x2b, 0x1a];
const BE_ORDER: [u8; 4] = [0x1a, 0x2b, 0x3c, 0x4d];

struct Interface {
    link_type: u32,
    snaplen: u32,
    resol: u8,
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
        Err(fault) => stopped(Vec::new(), fault),
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
    let total = block_total(bytes, 0, big_endian, SHB_MIN, Fault::NotACaptureFile)?;
    Ok((big_endian, total))
}

fn blocks<'a>(bytes: &'a [u8], mut big_endian: bool, mut offset: usize) -> Capture<'a> {
    let mut frames = Vec::new();
    let mut interfaces = Vec::new();
    while offset < bytes.len() {
        let (block_type, total, endian) = match block_at(bytes, offset, big_endian) {
            Ok(found) => found,
            Err(fault) => return stopped(frames, fault),
        };
        big_endian = endian;
        if let Err(fault) = consume(
            bytes,
            offset,
            total,
            block_type,
            big_endian,
            &mut interfaces,
            &mut frames,
        ) {
            return stopped(frames, fault);
        }
        offset += total;
    }
    Capture {
        frames,
        fault: None,
    }
}

fn block_at(bytes: &[u8], offset: usize, big_endian: bool) -> Result<(u32, usize, bool), Fault> {
    let rest = bytes.len() - offset;
    if rest < 8 {
        return Err(Fault::CutShort);
    }
    let block_type = u32_at(bytes, offset, big_endian);
    if block_type != SHB_TYPE {
        let total = block_total(bytes, offset, big_endian, BLOCK_MIN, Fault::CutShort)?;
        return Ok((block_type, total, big_endian));
    }
    if rest < 12 {
        return Err(Fault::CutShort);
    }
    let endian = match endian_at(bytes, offset + 8) {
        Some(endian) => endian,
        None => return Err(Fault::CutShort),
    };
    let total = block_total(bytes, offset, endian, SHB_MIN, Fault::CutShort)?;
    Ok((block_type, total, endian))
}

fn block_total(
    bytes: &[u8],
    offset: usize,
    big_endian: bool,
    minimum: u32,
    short: Fault,
) -> Result<usize, Fault> {
    let rest = bytes.len() - offset;
    if rest < 8 {
        return Err(short);
    }
    let first = u32_at(bytes, offset + 4, big_endian);
    if first < minimum || first % 4 != 0 {
        return Err(short);
    }
    let total = first as usize;
    if rest < total {
        return Err(short);
    }
    let second = u32_at(bytes, offset + total - 4, big_endian);
    if first != second {
        return Err(Fault::BlockLengths { first, second });
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
) -> Result<(), Fault> {
    match block_type {
        SHB_TYPE => interfaces.clear(),
        IDB_TYPE => interfaces.push(interface(bytes, offset, total, big_endian)?),
        EPB_TYPE => frames.push(enhanced(bytes, offset, total, big_endian, interfaces)?),
        SPB_TYPE => frames.push(simple(bytes, offset, total, big_endian, interfaces)?),
        OPB_TYPE => frames.push(obsolete(bytes, offset, total, big_endian, interfaces)?),
        _ => {}
    }
    Ok(())
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
    Ok(Interface {
        link_type: u32::from(u16_at(bytes, at, big_endian)),
        snaplen: u32_at(bytes, at + 4, big_endian),
        resol: resolution(bytes, at + 8, offset + total - 4, big_endian),
    })
}

fn resolution(bytes: &[u8], mut cursor: usize, end: usize, big_endian: bool) -> u8 {
    while cursor + 4 <= end {
        let code = u16_at(bytes, cursor, big_endian);
        let len = usize::from(u16_at(bytes, cursor + 2, big_endian));
        let value_at = cursor + 4;
        if value_at.saturating_add(len) > end {
            break;
        }
        if code == IF_TSRESOL && len >= 1 {
            return bytes[value_at];
        }
        let Some(next) = cursor.checked_add(4 + align4(len)) else {
            break;
        };
        if next > end {
            break;
        }
        cursor = next;
    }
    DEFAULT_RESOL
}

fn align4(len: usize) -> usize {
    len.saturating_add(3) & !3
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
    )
}

fn frame<'a>(
    bytes: &'a [u8],
    packet: Packet,
    data_end: usize,
    interfaces: &[Interface],
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
    Ok(Frame {
        link_type: iface.link_type,
        timestamp: packet.ticks.map(|ticks| timestamp(ticks, iface.resol)),
        original_length: packet.original_len,
        captured: packet_bytes(bytes, packet.packet_at, packet.captured_len, data_end)?,
    })
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
        seconds: (ticks / scale) as u64,
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

fn stopped<'a>(frames: Vec<Frame<'a>>, fault: Fault) -> Capture<'a> {
    Capture {
        frames,
        fault: Some(fault),
    }
}
