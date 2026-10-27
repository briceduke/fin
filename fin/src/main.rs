//! `fin -r <file> [-n] -T fields -e ip.src` / `-e tls.handshake.extensions_server_name`

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
        return emit("stdin", read_capture(&bytes), &args.fields);
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
        return emit(
            &path.display().to_string(),
            read_capture(&bytes),
            &args.fields,
        );
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
        &args.fields,
    )
}

fn emit(name: &str, capture: reader::Capture<'_>, fields: &[Field]) -> Result<i32, String> {
    let want_ip = fields.iter().any(|field| *field == Field::IpSrc);
    let want_tls = fields.iter().any(|field| *field == Field::TlsSni);
    let mut session = IpSrc::query(want_ip, want_tls);
    let mut counted = Vec::new();
    for (index, frame) in capture.frames.iter().enumerate() {
        let cell = session.walk(frame);
        let mut columns = Vec::with_capacity(fields.len());
        for field in fields {
            match field {
                Field::IpSrc => columns.push(escape_field(&cell.values.join(","))),
                Field::TlsSni => columns.push(escape_field(&cell.tls_sni.join(","))),
            }
        }
        println!("{}", columns.join("\t"));
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
    fields: Vec<Field>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    IpSrc,
    TlsSni,
}

fn parse(raw: impl Iterator<Item = OsString>) -> Result<Args, String> {
    let mut file = None;
    let mut fields_flag = false;
    let mut fields = Vec::new();
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
                fields_flag = true;
            }
            "-e" => {
                let value = next_str(&mut args, "-e")?;
                match value.as_str() {
                    "ip.src" => fields.push(Field::IpSrc),
                    "tls.handshake.extensions_server_name" => fields.push(Field::TlsSni),
                    other => return Err(format!("unsupported field {other}")),
                }
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
    if !fields_flag {
        return Err("missing -T fields".to_string());
    }
    if fields.is_empty() {
        return Err("missing -e".to_string());
    }
    Ok(Args { file, fields })
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

/// tshark 4.6.9 `-T fields` (`ws_escape_csv` with whitespace escapes).
fn escape_field(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\u{07}' => out.push_str("\\a"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0b}' => out.push_str("\\v"),
            '\\' => out.push_str("\\\\"),
            '\0' => out.push_str("\\0"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::escape_field;

    #[test]
    fn fields_escape_tab_newline_cr_backslash() {
        assert_eq!(escape_field("ab\tcd"), "ab\\tcd");
        assert_eq!(escape_field("ab\ncd"), "ab\\ncd");
        assert_eq!(escape_field("ab\rcd"), "ab\\rcd");
        assert_eq!(escape_field("ab\\cd"), "ab\\\\cd");
        assert_eq!(escape_field("ab\u{0c}cd"), "ab\\fcd");
        assert_eq!(escape_field("ab\u{0b}cd"), "ab\\vcd");
        assert_eq!(escape_field("ab\u{07}cd"), "ab\\acd");
        assert_eq!(escape_field("ab\u{08}cd"), "ab\\bcd");
    }
}
