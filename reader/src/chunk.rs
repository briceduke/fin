//! Split a mapped capture across cores.
//!
//! Each core nominates a start with an 8-record (pcap) or 8-block (pcapng)
//! chain. A start is proved only when it is the byte where the previous
//! chunk stopped. A seam that does not prove is reread by [`read_capture`].

use std::thread;

use crate::pcap::{self, Layout};
use crate::pcapng::{self, Hop, NgState};
use crate::{read_capture, Capture, Fault, Frame, PCAPNG_MAGIC, PCAP_MAGICS};

/// Consecutive records or blocks a nominated start must hop.
pub const CHAIN: usize = 8;

/// How the split went. `fallback` means [`read_capture`] produced the frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkReport {
    pub chunks: usize,
    pub seams: usize,
    pub proved: usize,
    pub fallback: bool,
}

/// Frames plus whether every seam proved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunked<'a> {
    pub capture: Capture<'a>,
    pub report: ChunkReport,
}

/// Split `bytes` into `threads` ranges and read them in parallel.
pub fn read_capture_chunked(bytes: &[u8], threads: usize) -> Capture<'_> {
    read_chunks(bytes, &ranges(bytes.len(), threads.max(1))).capture
}

/// Split at explicit interior byte offsets. Used to force awkward seams.
pub fn read_capture_seams<'a>(bytes: &'a [u8], seams: &[usize]) -> Chunked<'a> {
    read_chunks(bytes, &ranges_from_seams(bytes.len(), seams))
}

pub(crate) fn read_chunks<'a>(bytes: &'a [u8], ranges: &[(usize, usize)]) -> Chunked<'a> {
    let ranges = if ranges.is_empty() {
        vec![(0, bytes.len())]
    } else {
        ranges.to_vec()
    };
    if bytes.len() >= 4 && bytes[..4] == PCAPNG_MAGIC {
        return match pcapng::open_section(bytes) {
            Ok((endian, first_end)) => pcapng_chunks(bytes, &ranges, endian, first_end),
            Err(_) => sequential(bytes, 1, 0),
        };
    }
    if bytes.len() >= 4 && PCAP_MAGICS.iter().any(|magic| bytes.starts_with(magic)) {
        return match pcap::open(bytes) {
            Ok(layout) => pcap_chunks(bytes, &ranges, layout),
            Err(_) => sequential(bytes, 1, 0),
        };
    }
    sequential(bytes, 1, 0)
}

fn sequential(bytes: &[u8], chunks: usize, seams: usize) -> Chunked<'_> {
    Chunked {
        capture: read_capture(bytes),
        report: ChunkReport {
            chunks,
            seams,
            proved: 0,
            fallback: false,
        },
    }
}

fn fallback(bytes: &[u8], chunks: usize, seams: usize, proved: usize) -> Chunked<'_> {
    Chunked {
        capture: read_capture(bytes),
        report: ChunkReport {
            chunks,
            seams,
            proved,
            fallback: true,
        },
    }
}

fn ranges(len: usize, threads: usize) -> Vec<(usize, usize)> {
    let n = threads.max(1);
    let mut out: Vec<(usize, usize)> = (0..n)
        .map(|i| (i * len / n, (i + 1) * len / n))
        .filter(|(start, end)| start < end)
        .collect();
    if out.is_empty() {
        out.push((0, len));
    }
    out
}

fn ranges_from_seams(len: usize, seams: &[usize]) -> Vec<(usize, usize)> {
    let mut cuts: Vec<usize> = seams
        .iter()
        .copied()
        .filter(|&seam| seam > 0 && seam < len)
        .collect();
    cuts.sort_unstable();
    cuts.dedup();
    let mut points = Vec::with_capacity(cuts.len() + 2);
    points.push(0);
    points.extend(cuts);
    points.push(len);
    points.windows(2).map(|w| (w[0], w[1])).collect()
}

struct PcapPiece<'a> {
    from: usize,
    start: Option<usize>,
    stop: usize,
    frames: Vec<Frame<'a>>,
    fault: Option<Fault>,
}

fn pcap_chunks<'a>(bytes: &'a [u8], ranges: &[(usize, usize)], layout: Layout) -> Chunked<'a> {
    let pieces: Vec<PcapPiece<'a>> = thread::scope(|scope| {
        let handles: Vec<_> = ranges
            .iter()
            .map(|&(from, end)| scope.spawn(move || pcap_piece(bytes, from, end, layout)))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    merge_pcap(bytes, pieces)
}

fn pcap_piece(bytes: &[u8], from: usize, end: usize, layout: Layout) -> PcapPiece<'_> {
    let body = pcap::HEADER_LEN;
    let start = if from <= body && end > body && bytes.len() > body {
        body
    } else {
        match scan_pcap(bytes, from.max(body), end, layout) {
            Some(start) if start < end => start,
            _ => {
                return PcapPiece {
                    from,
                    start: None,
                    stop: from.max(body),
                    frames: Vec::new(),
                    fault: None,
                }
            }
        }
    };
    let mut frames = Vec::new();
    let mut offset = start;
    let mut fault = None;
    while offset < end && offset < bytes.len() {
        match pcap::record_at(bytes, offset, layout) {
            Ok((frame, next)) => {
                frames.push(frame);
                offset = next;
            }
            Err(err) => {
                fault = Some(err);
                break;
            }
        }
    }
    PcapPiece {
        from,
        start: Some(start),
        stop: offset,
        frames,
        fault,
    }
}

fn scan_pcap(bytes: &[u8], from: usize, end: usize, layout: Layout) -> Option<usize> {
    let mut offset = from;
    while offset < end && offset < bytes.len() {
        if pcap_chain(bytes, offset, layout) {
            return Some(offset);
        }
        offset += 1;
    }
    None
}

fn pcap_chain(bytes: &[u8], mut offset: usize, layout: Layout) -> bool {
    let mut count = 0;
    while count < CHAIN && offset < bytes.len() {
        match pcap::record_at(bytes, offset, layout) {
            Ok((_, next)) if next > offset => {
                offset = next;
                count += 1;
            }
            _ => return false,
        }
    }
    count > 0 && (count == CHAIN || offset == bytes.len())
}

fn merge_pcap<'a>(bytes: &'a [u8], pieces: Vec<PcapPiece<'a>>) -> Chunked<'a> {
    let chunks = pieces.len();
    let seams = chunks.saturating_sub(1);
    let mut pos = pcap::HEADER_LEN;
    let mut frames = Vec::new();
    let mut proved = 0;
    let mut fault = None;
    let mut after_packet = false;
    for (index, mut piece) in pieces.into_iter().enumerate() {
        match piece.start {
            None => {
                if pos < piece.from && piece.from < bytes.len() && piece.from > pcap::HEADER_LEN {
                    return fallback(bytes, chunks, seams, proved);
                }
            }
            Some(start) => {
                if start != pos {
                    return fallback(bytes, chunks, seams, proved);
                }
                if index > 0 {
                    proved += 1;
                }
                frames.append(&mut piece.frames);
                pos = piece.stop;
                if piece.fault.is_some() {
                    after_packet = true;
                    fault = piece.fault;
                    break;
                }
            }
        }
    }
    if fault.is_none() && pos != bytes.len() {
        return fallback(bytes, chunks, seams, proved);
    }
    let capture = match fault {
        None => Capture::ok(frames),
        Some(err) => Capture::halt(frames, err, after_packet),
    };
    Chunked {
        capture,
        report: ChunkReport {
            chunks,
            seams,
            proved,
            fallback: false,
        },
    }
}

struct NgPiece {
    from: usize,
    start: Option<usize>,
    stop: usize,
    hops: Vec<(usize, Hop)>,
    fault: Option<Fault>,
    after_packet: bool,
}

fn pcapng_chunks<'a>(
    bytes: &'a [u8],
    ranges: &[(usize, usize)],
    endian: bool,
    first_end: usize,
) -> Chunked<'a> {
    let pieces: Vec<NgPiece> = thread::scope(|scope| {
        let handles: Vec<_> = ranges
            .iter()
            .map(|&(from, end)| {
                scope.spawn(move || ng_piece(bytes, from, end, endian, first_end))
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    merge_pcapng(bytes, pieces, endian)
}

fn ng_piece(
    bytes: &[u8],
    from: usize,
    end: usize,
    file_endian: bool,
    first_end: usize,
) -> NgPiece {
    let (start, mut endian) = if from == 0 {
        (0, file_endian)
    } else {
        match scan_pcapng(bytes, from, end, file_endian) {
            Some((start, endian)) if start < end => (start, endian),
            _ => {
                return NgPiece {
                    from,
                    start: None,
                    stop: from,
                    hops: Vec::new(),
                    fault: None,
                    after_packet: false,
                }
            }
        }
    };
    let mut hops = Vec::new();
    let mut offset = start;
    if start == 0 {
        hops.push((
            0,
            Hop {
                block_type: pcapng::SHB_TYPE,
                total: first_end,
                endian: file_endian,
            },
        ));
        offset = first_end;
        endian = file_endian;
    }
    let mut fault = None;
    let mut after_packet = false;
    while offset < end && offset < bytes.len() {
        match pcapng::hop(bytes, offset, endian) {
            Ok(hop) => {
                endian = hop.endian;
                offset += hop.total;
                hops.push((offset - hop.total, hop));
            }
            Err(err) => {
                after_packet = pcapng::packet_type_at(bytes, offset, endian);
                fault = Some(err);
                break;
            }
        }
    }
    NgPiece {
        from,
        start: Some(start),
        stop: offset,
        hops,
        fault,
        after_packet,
    }
}

fn scan_pcapng(bytes: &[u8], from: usize, end: usize, file_endian: bool) -> Option<(usize, bool)> {
    let mut offset = from;
    if offset % 4 != 0 {
        if let Some(endian) = ng_chain_endian(bytes, offset, file_endian) {
            return Some((offset, endian));
        }
        offset = offset.next_multiple_of(4);
    }
    while offset < end && offset < bytes.len() {
        if let Some(endian) = ng_chain_endian(bytes, offset, file_endian) {
            return Some((offset, endian));
        }
        offset += 4;
    }
    None
}

fn ng_chain_endian(bytes: &[u8], offset: usize, file_endian: bool) -> Option<bool> {
    if ng_chain(bytes, offset, file_endian) {
        Some(file_endian)
    } else if ng_chain(bytes, offset, !file_endian) {
        Some(!file_endian)
    } else {
        None
    }
}

fn ng_chain(bytes: &[u8], mut offset: usize, mut endian: bool) -> bool {
    let mut count = 0;
    while count < CHAIN && offset < bytes.len() {
        match pcapng::hop(bytes, offset, endian) {
            Ok(hop) if hop.total > 0 => {
                endian = hop.endian;
                offset += hop.total;
                count += 1;
            }
            _ => return false,
        }
    }
    count > 0 && (count == CHAIN || offset == bytes.len())
}

fn merge_pcapng(bytes: &[u8], pieces: Vec<NgPiece>, endian: bool) -> Chunked<'_> {
    let chunks = pieces.len();
    let seams = chunks.saturating_sub(1);
    let mut pos = 0;
    let mut hops = Vec::new();
    let mut proved = 0;
    let mut hop_fault = None;
    let mut hop_after = false;
    for (index, piece) in pieces.into_iter().enumerate() {
        match piece.start {
            None => {
                if pos < piece.from && piece.from < bytes.len() {
                    return fallback(bytes, chunks, seams, proved);
                }
            }
            Some(start) => {
                if start != pos {
                    return fallback(bytes, chunks, seams, proved);
                }
                if index > 0 {
                    proved += 1;
                }
                hops.extend(piece.hops);
                pos = piece.stop;
                if let Some(err) = piece.fault {
                    hop_fault = Some(err);
                    hop_after = piece.after_packet;
                    break;
                }
            }
        }
    }
    if hop_fault.is_none() && pos != bytes.len() {
        return fallback(bytes, chunks, seams, proved);
    }
    let capture = peel_pcapng(bytes, &hops, endian, hop_fault, hop_after);
    Chunked {
        capture,
        report: ChunkReport {
            chunks,
            seams,
            proved,
            fallback: false,
        },
    }
}

fn peel_pcapng<'a>(
    bytes: &'a [u8],
    hops: &[(usize, Hop)],
    endian: bool,
    hop_fault: Option<Fault>,
    hop_after: bool,
) -> Capture<'a> {
    let mut state = NgState::new(endian);
    let mut frames = Vec::new();
    for &(offset, hop) in hops {
        if let Err(fault) = state.apply(bytes, offset, hop, &mut frames) {
            return Capture::halt(frames, fault, state.after_packet);
        }
    }
    match hop_fault {
        None => Capture::ok(frames),
        Some(fault) => Capture::halt(frames, fault, state.after_packet || hop_after),
    }
}
