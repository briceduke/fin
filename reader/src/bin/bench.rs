//! Throwaway bench: one `read_capture` walk. `--in-process` times that walk alone.
//! `--chunked` prints sequential vs chunked medians on the same bytes.

use std::env;
use std::fs::File;
use std::hint::black_box;
use std::io::{Read, Seek, SeekFrom};
use std::process::ExitCode;
use std::thread;
use std::time::Instant;

use reader::{read_capture, read_capture_chunked};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let (passes, chunked, path) = match args.as_slice() {
        [path] => (1, false, path.as_str()),
        [flag, path] if flag == "--in-process" => (4, false, path.as_str()),
        [flag, path] if flag == "--chunked" => (4, true, path.as_str()),
        _ => {
            eprintln!("usage: bench [--in-process|--chunked] <pcap>");
            return ExitCode::from(2);
        }
    };
    let load_started = Instant::now();
    let Ok(bytes) = load_capture(path) else {
        eprintln!("read failed");
        return ExitCode::from(1);
    };
    if env::var_os("FIN_PHASES").is_some() {
        eprintln!("load {:.6}", load_started.elapsed().as_secs_f64());
    }
    if chunked {
        let threads = thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
        return bench_pair(&bytes, threads);
    }
    let mut timed = [0.0; 3];
    for index in 0..passes {
        let started = Instant::now();
        let capture = read_capture(&bytes);
        if let Some(fault) = capture.fault {
            eprintln!("fault: {}", fault.phrase());
            return ExitCode::from(1);
        }
        let sum: u64 = capture
            .frames
            .iter()
            .map(|frame| frame.captured.len() as u64)
            .sum();
        black_box(sum);
        let elapsed = started.elapsed().as_secs_f64();
        if capture.frames.len() != 1_000_000 {
            eprintln!("{}", capture.frames.len());
            return ExitCode::from(1);
        }
        if index == 0 {
            eprintln!("1000000");
            if env::var_os("FIN_PHASES").is_some() {
                eprintln!("walk {:.6}", elapsed);
            }
        } else {
            timed[index - 1] = elapsed;
        }
    }
    if passes == 4 {
        timed.sort_by(f64::total_cmp);
        eprintln!("median {:.6}", timed[1]);
    }
    ExitCode::SUCCESS
}

fn bench_pair(bytes: &[u8], threads: usize) -> ExitCode {
    let sequential = median_walk(bytes, false, threads);
    let chunked = median_walk(bytes, true, threads);
    match (sequential, chunked) {
        (Some((frames, seq)), Some((_, par))) => {
            eprintln!("frames {frames}");
            eprintln!("threads {threads}");
            eprintln!("sequential {:.6}", seq);
            eprintln!("chunked {:.6}", par);
            ExitCode::SUCCESS
        }
        _ => ExitCode::from(1),
    }
}

fn median_walk(bytes: &[u8], chunked: bool, threads: usize) -> Option<(usize, f64)> {
    let mut timed = [0.0; 3];
    let mut frames = 0;
    for index in 0..4 {
        let started = Instant::now();
        let capture = if chunked {
            read_capture_chunked(bytes, threads)
        } else {
            read_capture(bytes)
        };
        if let Some(fault) = capture.fault {
            eprintln!("fault: {}", fault.phrase());
            return None;
        }
        let sum: u64 = capture
            .frames
            .iter()
            .map(|frame| frame.captured.len() as u64)
            .sum();
        black_box(sum);
        let elapsed = started.elapsed().as_secs_f64();
        frames = capture.frames.len();
        if index == 0 {
            continue;
        }
        timed[index - 1] = elapsed;
    }
    timed.sort_by(f64::total_cmp);
    Some((frames, timed[1]))
}

/// Read the whole file on several threads. Each thread fills a disjoint range.
fn load_capture(path: &str) -> std::io::Result<Vec<u8>> {
    let len = usize::try_from(File::open(path)?.metadata()?.len()).unwrap_or(0);
    let mut bytes = Vec::<u8>::with_capacity(len);
    // 16 threads. 32 was no faster on the million-packet file.
    let threads = 16.min(len.max(1));
    let chunk = len.div_ceil(threads);
    let start = bytes.as_mut_ptr() as usize;
    thread::scope(|scope| {
        for index in 0..threads {
            let offset = index * chunk;
            if offset >= len {
                break;
            }
            let end = (offset + chunk).min(len);
            scope.spawn(move || {
                let mut file = File::open(path).expect("open");
                file.seek(SeekFrom::Start(offset as u64)).expect("seek");
                let slice = unsafe {
                    std::slice::from_raw_parts_mut((start + offset) as *mut u8, end - offset)
                };
                file.read_exact(slice).expect("read");
            });
        }
    });
    // Every range was written before this. A panic above leaves len at 0.
    unsafe { bytes.set_len(len) };
    Ok(bytes)
}
