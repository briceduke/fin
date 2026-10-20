//! Split a mapped classic pcap across cores.
//!
//! Each core nominates a start with an 8-record chain. A start is proved only
//! when it is the byte where the previous chunk stopped. A seam that does not
//! prove is reread by [`read_capture`]. pcapng uses [`read_capture`].

use std::thread;

use crate::pcap::{self, Layout};
use crate::{read_capture, Capture, Fault, Frame, PCAP_MAGICS};

const CHAIN: usize = 8;
const MIN_CHUNK: usize = 1024 * 1024;

/// Split `bytes` into `threads` ranges and read them in parallel.
pub fn read_capture_chunked(bytes: &[u8], threads: usize) -> Capture<'_> {
    if bytes.len() < MIN_CHUNK {
        return read_capture(bytes);
    }
    read_chunks(
        bytes,
        &ranges(bytes.len(), chunk_count(bytes.len(), threads)),
    )
    .0
}

/// Split at explicit interior byte offsets. Used to force awkward seams.
/// The bool is whether [`read_capture`] produced the frames.
#[doc(hidden)]
pub fn read_capture_seams<'a>(bytes: &'a [u8], seams: &[usize]) -> (Capture<'a>, bool) {
    read_chunks(bytes, &ranges_from_seams(bytes.len(), seams))
}

fn chunk_count(len: usize, threads: usize) -> usize {
    match len / MIN_CHUNK {
        0 => 1,
        cap => threads.max(1).min(cap),
    }
}

fn read_chunks<'a>(bytes: &'a [u8], ranges: &[(usize, usize)]) -> (Capture<'a>, bool) {
    if ranges.len() <= 1 || !is_pcap(bytes) {
        return (read_capture(bytes), false);
    }
    match pcap::open(bytes) {
        Ok(layout) => pcap_chunks(bytes, ranges, layout),
        Err(_) => (read_capture(bytes), false),
    }
}

fn is_pcap(bytes: &[u8]) -> bool {
    PCAP_MAGICS.iter().any(|magic| bytes.starts_with(magic))
}

fn fallback(bytes: &[u8]) -> (Capture<'_>, bool) {
    (read_capture(bytes), true)
}

fn ranges(len: usize, threads: usize) -> Vec<(usize, usize)> {
    let mut out: Vec<(usize, usize)> = (0..threads)
        .map(|i| (i * len / threads, (i + 1) * len / threads))
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

struct Piece<'a> {
    from: usize,
    start: Option<usize>,
    stop: usize,
    frames: Vec<Frame<'a>>,
    fault: Option<Fault>,
}

fn pcap_chunks<'a>(
    bytes: &'a [u8],
    ranges: &[(usize, usize)],
    layout: Layout,
) -> (Capture<'a>, bool) {
    let pieces: Vec<Piece<'a>> = thread::scope(|scope| {
        let handles: Vec<_> = ranges
            .iter()
            .map(|&(from, end)| scope.spawn(move || piece(bytes, from, end, layout)))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    merge(bytes, pieces)
}

fn piece(bytes: &[u8], from: usize, end: usize, layout: Layout) -> Piece<'_> {
    let body = pcap::HEADER_LEN;
    let start = if from <= body && end > body {
        debug_assert!(bytes.len() > body);
        body
    } else {
        match scan(bytes, from.max(body), end, layout) {
            Some(start) if start < end => start,
            _ => {
                return Piece {
                    from,
                    start: None,
                    stop: 0,
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
    Piece {
        from,
        start: Some(start),
        stop: offset,
        frames,
        fault,
    }
}

fn scan(bytes: &[u8], from: usize, end: usize, layout: Layout) -> Option<usize> {
    let mut offset = from;
    while offset < end && offset < bytes.len() {
        if chain(bytes, offset, layout) {
            return Some(offset);
        }
        offset += 1;
    }
    None
}

fn chain(bytes: &[u8], mut offset: usize, layout: Layout) -> bool {
    let mut count = 0;
    // Empty records (caplen or origlen 0) chain on zero padding; abutment still decides.
    while count < CHAIN && offset < bytes.len() {
        match pcap::record_at(bytes, offset, layout) {
            Ok((_, next)) if next > offset && pcap::nonzero_lengths(bytes, offset, layout) => {
                offset = next;
                count += 1;
            }
            _ => return false,
        }
    }
    count > 0 && (count == CHAIN || offset == bytes.len())
}

fn merge<'a>(bytes: &'a [u8], pieces: Vec<Piece<'a>>) -> (Capture<'a>, bool) {
    let mut pos = pcap::HEADER_LEN;
    let mut frames = Vec::new();
    let mut fault = None;
    for mut piece in pieces {
        match piece.start {
            None => {
                if pos < piece.from {
                    return fallback(bytes);
                }
            }
            Some(start) => {
                if start != pos {
                    return fallback(bytes);
                }
                frames.append(&mut piece.frames);
                pos = piece.stop;
                if piece.fault.is_some() {
                    fault = piece.fault;
                    break;
                }
            }
        }
    }
    if fault.is_none() && pos != bytes.len() {
        return fallback(bytes);
    }
    let capture = match fault {
        None => Capture::ok(frames),
        Some(err) => Capture::halt(frames, err, true),
    };
    (capture, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiny_file_uses_sequential_path() {
        assert_eq!(chunk_count(0, 16), 1);
        assert_eq!(chunk_count(MIN_CHUNK - 1, 16), 1);
        assert_eq!(chunk_count(MIN_CHUNK, 16), 1);
        assert_eq!(chunk_count(MIN_CHUNK * 2, 16), 2);
        assert_eq!(chunk_count(MIN_CHUNK * 8, 4), 4);
        assert_eq!(chunk_count(MIN_CHUNK * 8, 0), 1);
        let bytes = [0u8; 64];
        assert_eq!(read_capture_chunked(&bytes, 16), read_capture(&bytes));
    }
}
