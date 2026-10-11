//! Sequential capture reader.
//!
//! One core, front to back. Classic pcap and pcapng become frames. A later
//! chunked reader falls back to this when a seam does not prove.

mod pcap;
mod pcapng;

/// Largest captured length tshark 4.6.9 will read.
pub const MAX_CAPTURED_LENGTH: u32 = 262144;

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
    pub timestamp: Option<Timestamp>,
    pub original_length: u32,
    pub captured: &'a [u8],
}

/// A timestamp taken from the file, split into whole seconds and a fraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp {
    pub seconds: i64,
    pub fraction: u32,
    pub unit: TimeUnit,
}

/// The unit of [`Timestamp::fraction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeUnit {
    Microsecond,
    Nanosecond,
}

/// Frames read before the reader stopped, and the fault that stopped it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capture<'a> {
    pub frames: Vec<Frame<'a>>,
    pub fault: Option<Fault>,
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
        later: bool,
    },
    UnsupportedTsresol {
        binary: bool,
        exponent: u8,
    },
}

/// Which capture container produced a captured-length fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureKind {
    Pcap,
    Pcapng,
}

impl Fault {
    /// Process status tshark 4.6.9 uses for this fault.
    ///
    /// [`Fault::UnsupportedLinkType`] is fin's own rejection. tshark still
    /// opens that file. The status is 1.
    pub fn exit_code(self) -> i32 {
        match self {
            Fault::NotACaptureFile
            | Fault::TruncatedHeader
            | Fault::UnsupportedPcapVersion { .. }
            | Fault::UnsupportedPcapngVersion { later: false, .. }
            | Fault::UnsupportedTsresol { .. } => 3,
            Fault::UnsupportedLinkType { .. } => 1,
            Fault::CutShort
            | Fault::CapturedLengthTooBig { .. }
            | Fault::BadInterface { .. }
            | Fault::BlockLengths { .. }
            | Fault::UnsupportedPcapngVersion { later: true, .. } => 14,
        }
    }

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
            Fault::UnsupportedPcapngVersion { major, minor, .. } => {
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
    Capture {
        frames: Vec::new(),
        fault: Some(Fault::NotACaptureFile),
    }
}
