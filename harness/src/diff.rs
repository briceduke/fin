use std::collections::BTreeSet;
use std::fmt;

/// Stdout and stderr from one tshark run and the matching fin run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairOutput {
    pub tshark_stdout: String,
    pub fin_stdout: String,
    pub fin_stderr: String,
    pub fin_exit_code: i32,
}

/// A failed check between tshark and fin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffFault {
    RowCount {
        tshark: usize,
        fin: usize,
    },
    UncountedDifference {
        frame: u64,
    },
    ColumnCount {
        frame: u64,
        tshark: usize,
        fin: usize,
    },
    NotASubset {
        frame: u64,
        column: usize,
    },
    CountedWithoutFailure,
}

/// The first faults, plus how many further faults were left out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffReport {
    pub faults: Vec<DiffFault>,
    pub omitted_faults: u64,
}

/// Fin stderr had a `counted` line the harness could not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountError {
    pub line: String,
}

const FAULT_LIMIT: usize = 8;

/// Compare field rows.
///
/// Rows are frames, starting at 1. Columns are tab-separated. Values inside
/// a column are comma-separated. A row that differs must be named by a
/// `counted <frame> <reason>` line on fin's stderr. On a counted frame, each
/// fin column is an ordered subset of the tshark column: fin may drop a
/// value, and it may not add or reorder one. A counted frame requires a
/// nonzero fin exit code.
pub fn check_pair(output: &PairOutput) -> Result<DiffReport, CountError> {
    let counted = counted_frames(&output.fin_stderr)?;
    Ok(judge(output, &counted))
}

fn counted_frames(stderr: &str) -> Result<BTreeSet<u64>, CountError> {
    let mut frames = BTreeSet::new();
    for line in stderr.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let Some(rest) = line.strip_prefix("counted ") else {
            continue;
        };
        let number = rest
            .split_once(' ')
            .map(|(number, _)| number)
            .unwrap_or(rest);
        let frame: u64 = number.parse().map_err(|_| CountError {
            line: line.to_string(),
        })?;
        if frame == 0 {
            return Err(CountError {
                line: line.to_string(),
            });
        }
        frames.insert(frame);
    }
    Ok(frames)
}

fn judge(output: &PairOutput, counted: &BTreeSet<u64>) -> DiffReport {
    let tshark_rows = rows(&output.tshark_stdout);
    let fin_rows = rows(&output.fin_stdout);
    let mut faults = Faults::default();
    if tshark_rows.len() != fin_rows.len() {
        faults.push(DiffFault::RowCount {
            tshark: tshark_rows.len(),
            fin: fin_rows.len(),
        });
    } else {
        for (index, (tshark_row, fin_row)) in tshark_rows.iter().zip(fin_rows.iter()).enumerate() {
            judge_row(index as u64 + 1, tshark_row, fin_row, counted, &mut faults);
        }
    }
    if !counted.is_empty() && output.fin_exit_code == 0 {
        faults.items.push(DiffFault::CountedWithoutFailure);
    }
    DiffReport {
        faults: faults.items,
        omitted_faults: faults.omitted,
    }
}

fn judge_row(frame: u64, tshark: &str, fin: &str, counted: &BTreeSet<u64>, faults: &mut Faults) {
    if tshark == fin {
        return;
    }
    if !counted.contains(&frame) {
        faults.push(DiffFault::UncountedDifference { frame });
        return;
    }
    let tshark_columns = columns(tshark);
    let fin_columns = columns(fin);
    if tshark_columns.len() != fin_columns.len() {
        faults.push(DiffFault::ColumnCount {
            frame,
            tshark: tshark_columns.len(),
            fin: fin_columns.len(),
        });
        return;
    }
    for (index, (tshark_cell, fin_cell)) in tshark_columns.iter().zip(fin_columns).enumerate() {
        let tshark_values = values(tshark_cell);
        let fin_values = values(fin_cell);
        if !is_ordered_subset(&fin_values, &tshark_values) {
            faults.push(DiffFault::NotASubset {
                frame,
                column: index + 1,
            });
        }
    }
}

fn rows(stdout: &str) -> Vec<&str> {
    if stdout.is_empty() {
        return Vec::new();
    }
    let mut lines: Vec<&str> = stdout
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect();
    if lines.last().copied() == Some("") {
        lines.pop();
    }
    lines
}

fn columns(row: &str) -> Vec<&str> {
    row.split('\t').collect()
}

fn values(cell: &str) -> Vec<&str> {
    if cell.is_empty() {
        Vec::new()
    } else {
        cell.split(',').collect()
    }
}

fn is_ordered_subset(fin: &[&str], tshark: &[&str]) -> bool {
    let mut start = 0;
    for value in fin {
        let Some(offset) = tshark[start..].iter().position(|item| item == value) else {
            return false;
        };
        start += offset + 1;
    }
    true
}

#[derive(Default)]
struct Faults {
    items: Vec<DiffFault>,
    omitted: u64,
}

impl Faults {
    fn push(&mut self, fault: DiffFault) {
        if self.items.len() < FAULT_LIMIT {
            self.items.push(fault);
        } else {
            self.omitted += 1;
        }
    }
}

impl fmt::Display for DiffFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiffFault::RowCount { tshark, fin } => {
                write!(
                    formatter,
                    "row count is {tshark} from tshark and {fin} from fin"
                )
            }
            DiffFault::UncountedDifference { frame } => {
                write!(formatter, "frame {frame} differs and fin did not count it")
            }
            DiffFault::ColumnCount { frame, tshark, fin } => write!(
                formatter,
                "frame {frame} has {tshark} tshark columns and {fin} fin columns"
            ),
            DiffFault::NotASubset { frame, column } => write!(
                formatter,
                "frame {frame} column {column} has a value tshark does not have"
            ),
            DiffFault::CountedWithoutFailure => {
                write!(formatter, "fin counted frames and exited 0")
            }
        }
    }
}

impl fmt::Display for DiffReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for fault in &self.faults {
            writeln!(formatter, "{fault}")?;
        }
        if self.omitted_faults > 0 {
            writeln!(formatter, "{} more faults", self.omitted_faults)?;
        }
        Ok(())
    }
}

impl fmt::Display for CountError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "bad counted line: {}", self.line)
    }
}

impl std::error::Error for CountError {}
