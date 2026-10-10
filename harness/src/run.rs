use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::diff::PairOutput;

const TSHARK_VERSION: &str = "4.6.9";

/// Run tshark and fin on the same arguments.
///
/// tshark gets a fresh empty directory in `WIRESHARK_CONFIG_DIR`. The
/// tshark binary must report version 4.6.9.
pub fn run_pair(tshark: &Path, fin: &Path, args: &[OsString]) -> Result<PairOutput, RunError> {
    let config = ConfigDir::create()?;
    let version = spawn(
        "tshark",
        tshark,
        &[OsString::from("--version")],
        Some(config.path()),
    )?;
    if !accepts_version(&version.stdout) {
        return Err(RunError::Version {
            found: version_line(&version.stdout),
        });
    }
    let tshark_run = spawn("tshark", tshark, args, Some(config.path()))?;
    let fin_run = spawn("fin", fin, args, None)?;
    Ok(PairOutput {
        tshark_stdout: tshark_run.stdout,
        fin_stdout: fin_run.stdout,
        fin_stderr: fin_run.stderr,
        fin_exit_code: fin_run.exit_code,
    })
}

fn accepts_version(stdout: &str) -> bool {
    stdout
        .split_whitespace()
        .any(|token| token == TSHARK_VERSION)
}

fn version_line(stdout: &str) -> String {
    stdout
        .lines()
        .next()
        .unwrap_or("no version output")
        .trim()
        .to_string()
}

struct Captured {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

fn spawn(
    tool: &'static str,
    program: &Path,
    args: &[OsString],
    config_dir: Option<&Path>,
) -> Result<Captured, RunError> {
    let mut command = Command::new(program);
    command.args(args);
    if let Some(dir) = config_dir {
        command.env("WIRESHARK_CONFIG_DIR", dir);
    }
    let output = command
        .output()
        .map_err(|source| RunError::Spawn { tool, source })?;
    captured(tool, output)
}

fn captured(tool: &'static str, output: Output) -> Result<Captured, RunError> {
    let exit_code = output.status.code().ok_or(RunError::Signaled { tool })?;
    let stdout = String::from_utf8(output.stdout).map_err(|_| RunError::Utf8 { tool })?;
    let stderr = String::from_utf8(output.stderr).map_err(|_| RunError::Utf8 { tool })?;
    Ok(Captured {
        stdout,
        stderr,
        exit_code,
    })
}

struct ConfigDir {
    path: PathBuf,
}

impl ConfigDir {
    fn create() -> Result<Self, RunError> {
        let seq = CONFIG_SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "fin-tshark-{}-{}-{}",
            std::process::id(),
            nanos,
            seq
        ));
        std::fs::create_dir(&path).map_err(|source| RunError::Config { source })?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ConfigDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

static CONFIG_SEQ: AtomicU64 = AtomicU64::new(0);

/// A tshark or fin process could not be compared.
#[derive(Debug)]
pub enum RunError {
    Version {
        found: String,
    },
    Spawn {
        tool: &'static str,
        source: io::Error,
    },
    Utf8 {
        tool: &'static str,
    },
    Signaled {
        tool: &'static str,
    },
    Config {
        source: io::Error,
    },
}

impl fmt::Display for RunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunError::Version { found } => {
                write!(
                    formatter,
                    "tshark version must be {TSHARK_VERSION}, found {found}"
                )
            }
            RunError::Spawn { tool, source } => write!(formatter, "could not run {tool}: {source}"),
            RunError::Utf8 { tool } => write!(formatter, "{tool} output is not utf-8"),
            RunError::Signaled { tool } => write!(formatter, "{tool} was signaled"),
            RunError::Config { source } => {
                write!(
                    formatter,
                    "could not create the tshark config directory: {source}"
                )
            }
        }
    }
}

impl std::error::Error for RunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RunError::Spawn { source, .. } | RunError::Config { source } => Some(source),
            _ => None,
        }
    }
}
