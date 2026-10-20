//! `fin -r <file> [-n] -T fields -e ip.src`

use std::env;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;

use memmap2::Mmap;
use reader::{read_capture, read_capture_chunked, IpSrc};

fn main() -> ExitCode {
    match run(env::args_os().skip(1)) {
        Ok(code) => ExitCode::from(code as u8),
        Err(message) => {
            eprintln!("fin: {message}");
            ExitCode::from(1)
        }
    }
}

fn run(args: impl Iterator<Item = OsString>) -> Result<i32, String> {
    let args = parse(args)?;
    let path = args.file.ok_or_else(|| "missing -r".to_string())?;
    if path.as_os_str() == "-" {
        let mut bytes = Vec::new();
        io::stdin()
            .read_to_end(&mut bytes)
            .map_err(|error| format!("stdin: {error}"))?;
        return emit("stdin", read_capture(&bytes));
    }
    let file = File::open(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let is_file = file.metadata().map(|m| m.is_file()).unwrap_or(false);
    if !is_file {
        // Pipes, FIFOs, and devices cannot be mapped. Read the already-open
        // handle so a FIFO is not opened twice.
        let mut file = file;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        return emit(&path.display().to_string(), read_capture(&bytes));
    }
    // Regular files are mapped. They are not written while fin reads them; on
    // Linux a concurrent truncation can SIGBUS instead of reporting a fault.
    let mapped =
        unsafe { Mmap::map(&file) }.map_err(|error| format!("{}: {error}", path.display()))?;
    let threads = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    emit(
        &path.display().to_string(),
        read_capture_chunked(&mapped, threads),
    )
}

fn emit(name: &str, capture: reader::Capture<'_>) -> Result<i32, String> {
    let mut ip_src = IpSrc::new();
    let mut counted = Vec::new();
    for (index, frame) in capture.frames.iter().enumerate() {
        let cell = ip_src.walk(frame);
        println!("{}", cell.values.join(","));
        if let Some(reason) = cell.counted {
            counted.push((index as u64 + 1, reason));
        }
    }
    for (frame, reason) in &counted {
        eprintln!("counted {frame} {reason}");
    }
    eprintln!("total {}", counted.len());
    if let Some(fault) = capture.fault {
        eprintln!("fin: {name}: {}", fault.phrase());
        return Ok(capture.exit_code());
    }
    if counted.is_empty() {
        Ok(0)
    } else {
        Ok(1)
    }
}

struct Args {
    file: Option<PathBuf>,
}

fn parse(raw: impl Iterator<Item = OsString>) -> Result<Args, String> {
    let mut file = None;
    let mut fields = false;
    let mut ip_src = false;
    let mut args = raw.peekable();
    while let Some(arg) = args.next() {
        let Some(flag) = arg.to_str() else {
            return Err("unrecognized flag".to_string());
        };
        match flag {
            "-n" => {}
            "-r" => {
                let value = args.next().ok_or_else(|| "missing -r path".to_string())?;
                file = Some(PathBuf::from(value));
            }
            "-T" => {
                let value = next_str(&mut args, "-T")?;
                if value != "fields" {
                    return Err(format!("unsupported -T {value}"));
                }
                fields = true;
            }
            "-e" => {
                let value = next_str(&mut args, "-e")?;
                if value != "ip.src" {
                    return Err(format!("unsupported field {value}"));
                }
                ip_src = true;
            }
            "-o" => {
                let value = next_str(&mut args, "-o")?;
                if value != "tcp.reassemble_out_of_order:TRUE" {
                    return Err(format!("unsupported -o {value}"));
                }
            }
            _ => return Err(format!("unrecognized flag {flag}")),
        }
    }
    if !fields {
        return Err("missing -T fields".to_string());
    }
    if !ip_src {
        return Err("missing -e ip.src".to_string());
    }
    Ok(Args { file })
}

fn next_str(
    args: &mut std::iter::Peekable<impl Iterator<Item = OsString>>,
    flag: &str,
) -> Result<String, String> {
    let value = args.next().ok_or_else(|| format!("missing {flag} value"))?;
    value
        .into_string()
        .map_err(|_| format!("missing {flag} value"))
}
