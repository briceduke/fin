//! Throwaway bench: one `read_capture` walk. `--in-process` times that walk alone.

use std::env;
use std::fs;
use std::hint::black_box;
use std::process::ExitCode;
use std::time::Instant;

use reader::read_capture;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let (passes, path) = match args.as_slice() {
        [path] => (1, path.as_str()),
        [flag, path] if flag == "--in-process" => (4, path.as_str()),
        _ => {
            eprintln!("usage: bench [--in-process] <pcap>");
            return ExitCode::from(2);
        }
    };
    let load_started = Instant::now();
    let Ok(bytes) = fs::read(path) else {
        eprintln!("read failed");
        return ExitCode::from(1);
    };
    if env::var_os("FIN_PHASES").is_some() {
        eprintln!("load {:.6}", load_started.elapsed().as_secs_f64());
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
        if index == 0 {
            eprintln!("{}", capture.frames.len());
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
