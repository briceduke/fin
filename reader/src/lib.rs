//! Capture reader.
//!
//! [`read_capture`] walks a file front to back on one core. [`read_capture_chunked`]
//! splits a classic pcap across cores and falls back to [`read_capture`] when a
//! seam does not prove. pcapng uses [`read_capture`].

mod chunk;
mod ip_src;
mod options;
mod pcap;
mod pcapng;
pub mod ports;
mod tls_sni;

pub use chunk::read_capture_chunked;
#[doc(hidden)]
pub use chunk::read_capture_seams;
pub use ip_src::{walk_ip_src, Cell, IpSrc};
pub use tls_sni::{parse_tcp_tls, TlsParse};

/// Largest captured length tshark 4.6.9 will read.
pub const MAX_CAPTURED_LENGTH: u32 = 262144;

/// Largest pcapng block tshark 4.6.9 will read (`MIN_EPB_SIZE` + D-Bus packet + 128 KiB).
pub const MAX_BLOCK_SIZE: u32 = 134348832;

const PCAP_MAGICS: [[u8; 4]; 4] = [
    [0xa1, 0xb2, 0xc3, 0xd4],
    [0xd4, 0xc3, 0xb2, 0xa1],
    [0xa1, 0xb2, 0x3c, 0x4d],
    [0x4d, 0x3c, 0xb2, 0xa1],
];

const PCAPNG_MAGIC: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];

/// One packet, borrowed from the capture bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame<'a> {
    pub link_type: u32,
    pub captured: &'a [u8],
}

/// Frames read before the reader stopped, and the fault that stopped it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capture<'a> {
    pub frames: Vec<Frame<'a>>,
    pub fault: Option<Fault>,
    after_packet: bool,
}

/// Why the reader stopped. Earlier complete frames stay in [`Capture::frames`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    NotACaptureFile,
    /// Classic pcap magic, but the 24-byte global header is incomplete.
    TruncatedHeader,
    CutShort,
    CapturedLengthTooBig {
        length: u32,
        kind: CaptureKind,
    },
    BadInterface {
        index: u32,
        interfaces: u32,
    },
    BlockLengths {
        first: u32,
        second: u32,
    },
    /// Classic pcap link type outside the v1 set. No frames are returned.
    UnsupportedLinkType {
        link_type: u32,
    },
    UnsupportedPcapVersion {
        major: u16,
    },
    UnsupportedPcapngVersion {
        major: u16,
        minor: u16,
    },
    UnsupportedTsresol {
        binary: bool,
        exponent: u8,
    },
    OptionHeader,
    OptionOverrun {
        length: u32,
    },
    IdbFilter {
        length: u32,
    },
    CustomOption {
        length: u32,
    },
    PacketOption {
        kind: PacketOption,
        length: u32,
    },
    BlockTooLarge {
        length: u32,
    },
    BlockBody {
        kind: BlockKind,
        length: u32,
    },
    DsbSecrets {
        length: u32,
        needed: u32,
    },
    DsbHuge {
        length: u32,
    },
    JournalEntry {
        length: u32,
    },
    NrbShort {
        left: u32,
    },
    NrbPad {
        left: u32,
        need: u32,
    },
    NrbIpv4 {
        length: u32,
    },
    NrbIpv6 {
        length: u32,
    },
    NrbName,
}

/// A pcapng block tshark 4.6.9 still reads besides SHB/IDB/packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockKind {
    Isb,
    Nrb,
    Dsb,
    Custom,
    Journal,
}

/// Which capture container produced a captured-length fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureKind {
    Pcap,
    Pcapng,
}

/// An EPB/OPB option tshark 4.6.9 rejects for a wrong length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketOption {
    Flags,
    Hash,
    DropCount,
    PacketId,
    Queue,
    Verdict,
    VerdictTc,
    VerdictXdp,
    ProcThread,
}

impl<'a> Capture<'a> {
    pub(crate) fn ok(frames: Vec<Frame<'a>>) -> Self {
        Self {
            frames,
            fault: None,
            after_packet: false,
        }
    }

    pub(crate) fn halt(frames: Vec<Frame<'a>>, fault: Fault, after_packet: bool) -> Self {
        Self {
            frames,
            fault: Some(fault),
            after_packet,
        }
    }

    /// Process status tshark 4.6.9 uses for this capture.
    ///
    /// [`Fault::UnsupportedLinkType`] is fin's own rejection. The status is 1.
    /// Any other fault is 3 before a packet-like block is reached, and 14 after.
    /// Packet-like blocks are EPB, SPB, OPB, custom, and systemd journal export.
    pub fn exit_code(&self) -> i32 {
        match self.fault {
            None => 0,
            Some(Fault::UnsupportedLinkType { .. }) => 1,
            Some(_) if self.frames.is_empty() && !self.after_packet => 3,
            Some(_) => 14,
        }
    }
}

impl Fault {
    /// The distinctive phrase, without a program name or a file path.
    pub fn phrase(self) -> String {
        match self {
            Fault::NotACaptureFile => "isn't a capture file".to_string(),
            Fault::TruncatedHeader => {
                "appears to have been cut short in the middle of a packet or other data".to_string()
            }
            Fault::CutShort => {
                "appears to have been cut short in the middle of a packet".to_string()
            }
            Fault::CapturedLengthTooBig {
                length,
                kind: CaptureKind::Pcap,
            } => format!(
                "pcap: File has {length}-byte packet, bigger than maximum of {MAX_CAPTURED_LENGTH}"
            ),
            Fault::CapturedLengthTooBig {
                length,
                kind: CaptureKind::Pcapng,
            } => format!(
                "pcapng: cap_len {length} is larger than maximum supported length {MAX_CAPTURED_LENGTH}"
            ),
            Fault::BadInterface { index, interfaces } => format!(
                "pcapng: interface index {index} is not less than section interface count {interfaces}"
            ),
            Fault::BlockLengths { first, second } => format!(
                "pcapng: total block lengths (first {first} and second {second}) don't match"
            ),
            Fault::UnsupportedLinkType { link_type } => {
                format!("unsupported link type {link_type}")
            }
            Fault::UnsupportedPcapVersion { major } => {
                format!("pcap: major version {major} unsupported")
            }
            Fault::UnsupportedPcapngVersion { major, minor } => {
                format!("pcapng: unknown SHB version {major}.{minor}")
            }
            Fault::UnsupportedTsresol {
                binary: true,
                exponent,
            } => format!("pcapng: IDB power-of-2 time stamp resolution {exponent} > 63"),
            Fault::UnsupportedTsresol {
                binary: false,
                exponent,
            } => format!("pcapng: IDB power-of-10 time stamp resolution {exponent} > 19"),
            Fault::OptionHeader => "pcapng: Not enough data for option header".to_string(),
            Fault::OptionOverrun { length } => {
                format!("pcapng: Not enough data to handle option of length {length}")
            }
            Fault::IdbFilter { length } => {
                format!("pcapng: IDB interface filter option length {length} is < 1")
            }
            Fault::CustomOption { length } => {
                format!("pcapng: option length ({length}) too small for custom option")
            }
            Fault::PacketOption { kind, length } => kind.phrase(length),
            Fault::BlockTooLarge { length } => {
                format!("pcapng: total block length {length} is too large (> {MAX_BLOCK_SIZE})")
            }
            Fault::BlockBody { kind, length } => kind.too_small(length),
            Fault::DsbSecrets { length, needed } => format!(
                "pcapng: block content length {length} of an DSB is less the size needed for the secrets in the DSB {needed}"
            ),
            Fault::DsbHuge { length } => format!("pcapng: secrets block is too large: {length}"),
            Fault::JournalEntry { length } => {
                format!("pcapng: entry length {length} is too small (< 23)")
            }
            Fault::NrbShort { left } => {
                format!("pcapng: {left} bytes left in the block < NRB record header size 4")
            }
            Fault::NrbPad { left, need } => {
                format!(
                    "pcapng: {left} bytes left in the block < NRB record length + padding {need}"
                )
            }
            Fault::NrbIpv4 { length } => {
                format!("pcapng: NRB IPv4 record length {length} < minimum length 4")
            }
            Fault::NrbIpv6 { length } => {
                format!("pcapng: NRB record length for IPv6 record {length} < minimum length 16")
            }
            Fault::NrbName => "pcapng: NRB record has non-null-terminated host name".to_string(),
        }
    }
}

impl BlockKind {
    fn too_small(self, length: u32) -> String {
        match self {
            BlockKind::Isb => format!(
                "pcapng: block content length {length} of an ISB is less than the minimum ISB content size 12"
            ),
            BlockKind::Nrb => format!(
                "pcapng: block content length {length} of an NRB is less than the minimum NRB content size 4"
            ),
            BlockKind::Dsb => format!(
                "pcapng: block content length {length} of an DSB is less than the minimum DSB content size 8"
            ),
            BlockKind::Custom => format!(
                "pcapng: block content length {length} of a CB is less than the minimum CB content size 4"
            ),
            BlockKind::Journal => format!(
                "pcapng: block content length {length} of a systemd journal export is less than the minimum systemd journal export content size 23"
            ),
        }
    }
}

impl PacketOption {
    fn phrase(self, length: u32) -> String {
        match self {
            PacketOption::Flags => {
                format!("pcapng: packet block flags option length {length} is not 4")
            }
            PacketOption::Hash => {
                format!("pcapng: packet block hash option length {length} is < 1")
            }
            PacketOption::DropCount => {
                format!("pcapng: packet block drop count option length {length} is not 8")
            }
            PacketOption::PacketId => {
                format!("pcapng: packet block packet id option length {length} is not 8")
            }
            PacketOption::Queue => {
                format!("pcapng: packet block queue option length {length} is not 4")
            }
            PacketOption::Verdict => {
                format!("pcapng: packet block verdict option length {length} is < 1")
            }
            PacketOption::VerdictTc => {
                format!("pcapng: packet block TC verdict option length {length} is != 9")
            }
            PacketOption::VerdictXdp => {
                format!("pcapng: packet block XDP verdict option length {length} is != 9")
            }
            PacketOption::ProcThread => {
                format!("pcapng: packet block process id thread id option length {length} is not 8")
            }
        }
    }
}

/// Read a classic pcap or pcapng file from the front.
///
/// `captured` on each frame is a subslice of `bytes`. A fault leaves every
/// complete frame in place and omits the packet that caused the stop.
pub fn read_capture(bytes: &[u8]) -> Capture<'_> {
    if bytes.len() >= 4 && bytes[..4] == PCAPNG_MAGIC {
        return pcapng::read(bytes);
    }
    if bytes.len() >= 4 && PCAP_MAGICS.iter().any(|magic| bytes.starts_with(magic)) {
        return pcap::read(bytes);
    }
    Capture::halt(Vec::new(), Fault::NotACaptureFile, false)
}
