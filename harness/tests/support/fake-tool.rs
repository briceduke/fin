use std::env;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let stem = env::current_exe()
        .ok()
        .and_then(|path| path.file_stem().map(|stem| stem.to_string_lossy().into_owned()))
        .unwrap_or_default();
    if args.first().map(String::as_str) == Some("--version") {
        let version = if stem.contains("old") {
            "4.0.0"
        } else if stem.contains("patch") {
            "4.6.90"
        } else {
            "4.6.9"
        };
        println!("TShark (Wireshark) {version}");
        return ExitCode::SUCCESS;
    }
    if stem.contains("tshark") {
        let dir = env::var("WIRESHARK_CONFIG_DIR").unwrap_or_default();
        let path = Path::new(&dir);
        let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
        if !path.is_dir() || !name.starts_with("fin-tshark-") {
            eprintln!("missing WIRESHARK_CONFIG_DIR");
            return ExitCode::from(2);
        }
        println!("10.0.0.1");
        return ExitCode::SUCCESS;
    }
    if stem.contains("bad") {
        println!("10.9.9.9");
        return ExitCode::SUCCESS;
    }
    println!("10.0.0.1");
    ExitCode::SUCCESS
}
