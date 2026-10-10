use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use harness::{check_pair, run_pair};

fn main() -> ExitCode {
    match run(env::args_os().skip(1)) {
        Ok(report) if report.faults.is_empty() => ExitCode::SUCCESS,
        Ok(report) => {
            eprint!("{report}");
            ExitCode::from(1)
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(1)
        }
    }
}

fn run(args: impl Iterator<Item = OsString>) -> Result<harness::DiffReport, String> {
    let args = parse_args(args)?;
    let output =
        run_pair(&args.tshark, &args.fin, &args.tool_args).map_err(|error| error.to_string())?;
    check_pair(&output).map_err(|error| error.to_string())
}

struct Args {
    tshark: PathBuf,
    fin: PathBuf,
    tool_args: Vec<OsString>,
}

fn parse_args(mut raw: impl Iterator<Item = OsString>) -> Result<Args, String> {
    let mut tshark: Option<PathBuf> = None;
    let mut fin: Option<PathBuf> = None;
    let mut tool_args: Option<Vec<OsString>> = None;
    while let Some(arg) = raw.next() {
        if arg == "--" {
            tool_args = Some(raw.collect());
            break;
        }
        if arg == "--tshark" {
            tshark = Some(require_path("--tshark", raw.next())?);
            continue;
        }
        if arg == "--fin" {
            fin = Some(require_path("--fin", raw.next())?);
            continue;
        }
        return Err(usage());
    }
    let tool_args = tool_args.ok_or_else(usage)?;
    if tool_args.is_empty() {
        return Err(usage());
    }
    let fin = fin.ok_or_else(|| "missing --fin".to_string())?;
    let tshark = tshark.unwrap_or_else(default_tshark);
    Ok(Args {
        tshark,
        fin,
        tool_args,
    })
}

fn require_path(flag: &str, value: Option<OsString>) -> Result<PathBuf, String> {
    value
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing {flag} path"))
}

fn default_tshark() -> PathBuf {
    let installed = PathBuf::from(r"C:\Program Files\Wireshark\tshark.exe");
    if installed.is_file() {
        installed
    } else {
        PathBuf::from("tshark")
    }
}

fn usage() -> String {
    "fin-diff --fin <fin> [--tshark <tshark>] -- <args passed to both>".to_string()
}
