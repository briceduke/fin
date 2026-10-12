//! pcapng option walk, mirroring tshark 4.6.9 `wiretap/pcapng.c`.
//!
//! Common loop: `pcapng_process_options`.
//! - remaining < 4 → `Not enough data for option header`
//! - rounded length > remaining → `Not enough data to handle option of length N`
//!   (`N` is the unrounded length)
//! - code 0 `OPT_EOFOPT` → stop (`remaining = rounded`, then subtract)
//! - code 1 `OPT_COMMENT` → string, never fails
//! - codes 2988, 2989, 19372, 19373 → `pcapng_process_custom_option_common`; length < 4 fails
//!
//! SHB (`pcapng_process_section_header_block_option`): strings only, no length fail.
//!
//! IDB (`pcapng_process_if_descr_block_option`):
//! - 9 `if_tsresol` → reject iff length == 1 and the exponent is out of range
//! - 11 `if_filter` → fail if length < 1
//!
//! EPB/OPB (`pcapng_process_packet_block_option`):
//! - 2 flags length == 4 else fail
//! - 3 hash length >= 1 else fail
//! - 4 drop count length == 8 else fail
//! - 5 packet id length == 8 else fail
//! - 6 queue length == 4 else fail
//! - 7 verdict length >= 1 else fail; type 1/2 also need length == 9
//! - 8 process/thread id length == 8 else fail

use crate::{Fault, PacketOption};

const OPT_EOFOPT: u16 = 0;
const OPT_COMMENT: u16 = 1;
const CUSTOM_STR_COPY: u16 = 2988;
const CUSTOM_BIN_COPY: u16 = 2989;
const CUSTOM_STR_NO_COPY: u16 = 19372;
const CUSTOM_BIN_NO_COPY: u16 = 19373;

const IF_TSRESOL: u16 = 9;
const IF_FILTER: u16 = 11;

const PKT_FLAGS: u16 = 2;
const PKT_HASH: u16 = 3;
const PKT_DROPCOUNT: u16 = 4;
const PKT_PACKETID: u16 = 5;
const PKT_QUEUE: u16 = 6;
const PKT_VERDICT: u16 = 7;
const PKT_PROCID: u16 = 8;
const VERDICT_TC: u8 = 1;
const VERDICT_XDP: u8 = 2;

enum Role<'a> {
    Section,
    Interface(&'a mut Collected),
    Packet,
}

struct Collected {
    resol: Option<u8>,
}

pub(crate) fn walk_shb(
    bytes: &[u8],
    start: usize,
    end: usize,
    big_endian: bool,
) -> Result<(), Fault> {
    walk_common(bytes, start, end, big_endian)
}

pub(crate) fn walk_common(
    bytes: &[u8],
    start: usize,
    end: usize,
    big_endian: bool,
) -> Result<(), Fault> {
    walk(bytes, start, end, big_endian, Role::Section)
}

pub(crate) fn walk_idb(
    bytes: &[u8],
    start: usize,
    end: usize,
    big_endian: bool,
) -> Result<(), Fault> {
    let mut collected = Collected { resol: None };
    walk(
        bytes,
        start,
        end,
        big_endian,
        Role::Interface(&mut collected),
    )?;
    if let Some(value) = collected.resol {
        check_tsresol(value)?;
    }
    Ok(())
}

pub(crate) fn walk_packet(
    bytes: &[u8],
    start: usize,
    end: usize,
    big_endian: bool,
) -> Result<(), Fault> {
    walk(bytes, start, end, big_endian, Role::Packet)
}

fn walk(
    bytes: &[u8],
    start: usize,
    end: usize,
    big_endian: bool,
    mut role: Role<'_>,
) -> Result<(), Fault> {
    if start > end {
        return Err(Fault::CutShort);
    }
    let mut cursor = start;
    let mut remaining = end - start;
    while remaining != 0 {
        if remaining < 4 {
            return Err(Fault::OptionHeader);
        }
        let code = u16_at(bytes, cursor, big_endian);
        let length = u16_at(bytes, cursor + 2, big_endian);
        cursor += 4;
        remaining -= 4;
        let value_len = usize::from(length);
        let rounded = align4(value_len);
        if rounded > remaining {
            return Err(Fault::OptionOverrun {
                length: u32::from(length),
            });
        }
        match code {
            OPT_EOFOPT => remaining = rounded,
            OPT_COMMENT => {}
            CUSTOM_STR_COPY | CUSTOM_BIN_COPY | CUSTOM_STR_NO_COPY | CUSTOM_BIN_NO_COPY => {
                if length < 4 {
                    return Err(Fault::CustomOption {
                        length: u32::from(length),
                    });
                }
            }
            _ => role.apply(code, length, &bytes[cursor..cursor + value_len], big_endian)?,
        }
        cursor += rounded;
        remaining -= rounded;
    }
    Ok(())
}

impl Role<'_> {
    fn apply(
        &mut self,
        code: u16,
        length: u16,
        content: &[u8],
        _big_endian: bool,
    ) -> Result<(), Fault> {
        match self {
            Role::Section => Ok(()),
            Role::Interface(collected) => idb_option(code, length, content, collected),
            Role::Packet => packet_option(code, length, content),
        }
    }
}

fn idb_option(
    code: u16,
    length: u16,
    content: &[u8],
    collected: &mut Collected,
) -> Result<(), Fault> {
    match code {
        IF_TSRESOL if length == 1 && collected.resol.is_none() => {
            collected.resol = Some(content[0]);
        }
        IF_FILTER if length < 1 => {
            return Err(Fault::IdbFilter {
                length: u32::from(length),
            });
        }
        _ => {}
    }
    Ok(())
}

fn packet_option(code: u16, length: u16, content: &[u8]) -> Result<(), Fault> {
    match code {
        PKT_FLAGS if length != 4 => packet(PacketOption::Flags, length),
        PKT_HASH if length < 1 => packet(PacketOption::Hash, length),
        PKT_DROPCOUNT if length != 8 => packet(PacketOption::DropCount, length),
        PKT_PACKETID if length != 8 => packet(PacketOption::PacketId, length),
        PKT_QUEUE if length != 4 => packet(PacketOption::Queue, length),
        PKT_VERDICT => verdict(length, content),
        PKT_PROCID if length != 8 => packet(PacketOption::ProcThread, length),
        _ => Ok(()),
    }
}

fn verdict(length: u16, content: &[u8]) -> Result<(), Fault> {
    if length < 1 {
        return packet(PacketOption::Verdict, length);
    }
    match content[0] {
        VERDICT_TC if length != 9 => packet(PacketOption::VerdictTc, length),
        VERDICT_XDP if length != 9 => packet(PacketOption::VerdictXdp, length),
        _ => Ok(()),
    }
}

fn packet(kind: PacketOption, length: u16) -> Result<(), Fault> {
    Err(Fault::PacketOption {
        kind,
        length: u32::from(length),
    })
}

fn check_tsresol(value: u8) -> Result<(), Fault> {
    let exponent = value & 0x7f;
    if value & 0x80 != 0 {
        if exponent > 63 {
            return Err(Fault::UnsupportedTsresol {
                binary: true,
                exponent,
            });
        }
    } else if exponent > 19 {
        return Err(Fault::UnsupportedTsresol {
            binary: false,
            exponent,
        });
    }
    Ok(())
}

fn align4(len: usize) -> usize {
    len.saturating_add(3) & !3
}

fn u16_at(bytes: &[u8], offset: usize, big_endian: bool) -> u16 {
    let raw = [bytes[offset], bytes[offset + 1]];
    if big_endian {
        u16::from_be_bytes(raw)
    } else {
        u16::from_le_bytes(raw)
    }
}
