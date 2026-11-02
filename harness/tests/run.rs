use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use harness::{check_pair, run_pair, RunError};

struct Tools {
    tshark: PathBuf,
    tshark_old: PathBuf,
    tshark_patch: PathBuf,
    fin: PathBuf,
    fin_bad: PathBuf,
}

fn tools() -> &'static Tools {
    static TOOLS: OnceLock<Tools> = OnceLock::new();
    TOOLS.get_or_init(compile_tools)
}

fn work_dir() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = env::temp_dir().join(format!("fin-harness-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("test directory");
        dir
    })
}

fn compile_tools() -> Tools {
    let dir = work_dir().to_path_buf();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support/fake-tool.rs");
    let compiled = dir.join(format!("fake-tool{}", env::consts::EXE_SUFFIX));
    let status = Command::new("rustc")
        .arg("--edition")
        .arg("2021")
        .arg(&source)
        .arg("-o")
        .arg(&compiled)
        .status()
        .expect("rustc");
    assert!(status.success(), "rustc fake-tool");
    Tools {
        tshark: copy_tool(&compiled, &dir, "fake-tshark"),
        tshark_old: copy_tool(&compiled, &dir, "fake-tshark-old"),
        tshark_patch: copy_tool(&compiled, &dir, "fake-tshark-patch"),
        fin: copy_tool(&compiled, &dir, "fake-fin"),
        fin_bad: copy_tool(&compiled, &dir, "fake-fin-bad"),
    }
}

fn copy_tool(compiled: &Path, dir: &Path, name: &str) -> PathBuf {
    let dest = dir.join(format!("{name}{}", env::consts::EXE_SUFFIX));
    fs::copy(compiled, &dest).expect("copy fake tool");
    dest
}

fn sample_args() -> Vec<OsString> {
    ["-r", "unused", "-T", "fields", "-e", "ip.src"]
        .into_iter()
        .map(OsString::from)
        .collect()
}

#[test]
fn matching_pair_uses_an_empty_config_directory() {
    let tools = tools();
    let output = run_pair(&tools.tshark, &tools.fin, &sample_args()).unwrap();
    assert_eq!(output.tshark_stdout, "10.0.0.1\n");
    assert!(check_pair(&output).unwrap().faults.is_empty());
}

#[test]
fn an_older_tshark_is_rejected() {
    let tools = tools();
    let error = run_pair(&tools.tshark_old, &tools.fin, &sample_args()).unwrap_err();
    assert!(
        matches!(error, RunError::Version { ref found } if found.contains("4.0.0")),
        "{error}"
    );
}

#[test]
fn a_longer_version_token_is_rejected() {
    let tools = tools();
    let error = run_pair(&tools.tshark_patch, &tools.fin, &sample_args()).unwrap_err();
    assert!(
        matches!(error, RunError::Version { ref found } if found.contains("4.6.90")),
        "{error}"
    );
}

fn fin_diff_bin() -> PathBuf {
    let test_exe = env::current_exe().expect("test executable");
    let debug_dir = test_exe
        .parent()
        .and_then(Path::parent)
        .expect("target directory");
    let bin = debug_dir.join(format!("fin-diff{}", env::consts::EXE_SUFFIX));
    assert!(bin.is_file(), "missing {}", bin.display());
    bin
}

#[test]
fn usage_fails() {
    let output = Command::new(fin_diff_bin()).output().unwrap();
    assert!(!output.status.success());
}

#[test]
fn the_cli_accepts_a_matching_pair() {
    let tools = tools();
    let output = Command::new(fin_diff_bin())
        .arg("--tshark")
        .arg(&tools.tshark)
        .arg("--fin")
        .arg(&tools.fin)
        .arg("--")
        .args(sample_args())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn the_cli_reports_an_uncounted_difference() {
    let tools = tools();
    let output = Command::new(fin_diff_bin())
        .arg("--tshark")
        .arg(&tools.tshark)
        .arg("--fin")
        .arg(&tools.fin_bad)
        .arg("--")
        .args(sample_args())
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("frame 1 differs and fin did not count it"),
        "{stderr}"
    );
}
