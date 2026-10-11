//! Diff tshark and fin field output.

mod diff;
mod run;

pub use diff::{check_pair, CountError, DiffFault, DiffReport, PairOutput};
pub use run::{run_pair, run_tshark, RunError, ToolOutput, TsharkSession};
