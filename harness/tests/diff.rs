use harness::{check_pair, DiffFault, PairOutput};

fn pair(tshark: &str, fin_stdout: &str, stderr: &str, exit_code: i32) -> PairOutput {
    PairOutput {
        tshark_stdout: tshark.to_string(),
        fin_stdout: fin_stdout.to_string(),
        fin_stderr: stderr.to_string(),
        fin_exit_code: exit_code,
    }
}

fn faults_of(output: PairOutput) -> Vec<DiffFault> {
    check_pair(&output).unwrap().faults
}

#[test]
fn matching_rows_pass_when_nothing_is_counted() {
    let output = pair("10.0.0.1\n10.0.0.2\n", "10.0.0.1\n10.0.0.2\n", "", 14);
    assert!(faults_of(output).is_empty());
}

#[test]
fn uncounted_difference_fails() {
    let output = pair("10.0.0.1\n", "10.0.0.2\n", "lines may differ\n", 1);
    assert_eq!(
        faults_of(output),
        vec![DiffFault::UncountedDifference { frame: 1 }]
    );
}

#[test]
fn dropped_second_address_passes() {
    let output = pair(
        "10.0.0.1,10.0.0.2\n",
        "10.0.0.1\n",
        "counted 1 icmp-error\n",
        1,
    );
    assert!(faults_of(output).is_empty());
}

#[test]
fn dropped_first_address_passes() {
    let output = pair(
        "10.0.0.1,10.0.0.2\n",
        "10.0.0.2\n",
        "counted 1 icmp-error\n",
        1,
    );
    assert!(faults_of(output).is_empty());
}

#[test]
fn added_address_fails() {
    let output = pair("10.0.0.1\n", "10.0.0.1,10.0.0.2\n", "counted 1 extra\n", 1);
    assert_eq!(
        faults_of(output),
        vec![DiffFault::NotASubset {
            frame: 1,
            column: 1
        }]
    );
}

#[test]
fn repeated_fin_value_fails() {
    let output = pair("10.0.0.1\n", "10.0.0.1,10.0.0.1\n", "counted 1 extra\n", 1);
    assert_eq!(
        faults_of(output),
        vec![DiffFault::NotASubset {
            frame: 1,
            column: 1
        }]
    );
}

#[test]
fn reordered_addresses_fail() {
    let output = pair(
        "10.0.0.1,10.0.0.2\n",
        "10.0.0.2,10.0.0.1\n",
        "counted 1 order\n",
        1,
    );
    assert_eq!(
        faults_of(output),
        vec![DiffFault::NotASubset {
            frame: 1,
            column: 1
        }]
    );
}

#[test]
fn counted_frame_with_exit_zero_fails() {
    let output = pair(
        "10.0.0.1,10.0.0.2\n",
        "10.0.0.1\n",
        "counted 1 icmp-error\n",
        0,
    );
    assert_eq!(faults_of(output), vec![DiffFault::CountedWithoutFailure]);
}

#[test]
fn counted_matching_row_passes() {
    let output = pair("10.0.0.1\n", "10.0.0.1\n", "counted 1 tunnel\n", 1);
    assert!(faults_of(output).is_empty());
}

#[test]
fn row_count_mismatch_fails() {
    let output = pair("10.0.0.1\n", "10.0.0.1\n10.0.0.2\n", "", 0);
    assert_eq!(
        faults_of(output),
        vec![DiffFault::RowCount { tshark: 1, fin: 2 }]
    );
}

#[test]
fn dropped_value_in_the_second_column_passes() {
    let output = pair(
        "10.0.0.1\texample.com\n",
        "10.0.0.1\t\n",
        "counted 1 server-name\n",
        1,
    );
    assert!(faults_of(output).is_empty());
}

#[test]
fn fewer_columns_fail() {
    let output = pair(
        "10.0.0.1\texample.com\n",
        "10.0.0.1\n",
        "counted 1 server-name\n",
        1,
    );
    assert_eq!(
        faults_of(output),
        vec![DiffFault::ColumnCount {
            frame: 1,
            tshark: 2,
            fin: 1,
        }]
    );
}

#[test]
fn blank_fin_cell_is_a_subset() {
    let output = pair("10.0.0.1\n", "\n", "counted 1 fragment\n", 1);
    assert!(faults_of(output).is_empty());
}

#[test]
fn value_against_a_blank_tshark_cell_fails() {
    let output = pair("\n", "10.0.0.1\n", "counted 1 invented\n", 1);
    assert_eq!(
        faults_of(output),
        vec![DiffFault::NotASubset {
            frame: 1,
            column: 1
        }]
    );
}

#[test]
fn prose_on_stderr_is_ignored() {
    let stderr = "lines may differ\nframe 9 counted 9\ncounted 2 gap\n";
    let output = pair("10.0.0.1\n10.0.0.2\n", "10.0.0.1\n\n", stderr, 1);
    assert!(faults_of(output).is_empty());
}

#[test]
fn frame_zero_is_rejected() {
    let error = check_pair(&pair("a\n", "a\n", "counted 0\n", 1)).unwrap_err();
    assert_eq!(error.line, "counted 0");
}

#[test]
fn a_non_numeric_count_is_rejected() {
    let error = check_pair(&pair("a\n", "a\n", "counted frame\n", 1)).unwrap_err();
    assert_eq!(error.line, "counted frame");
}

#[test]
fn carriage_returns_do_not_change_the_row() {
    let output = pair("10.0.0.1\r\n", "10.0.0.1\n", "", 0);
    assert!(faults_of(output).is_empty());
}

#[test]
fn extra_faults_are_omitted() {
    let mut tshark = String::new();
    let mut fin_stdout = String::new();
    for index in 0..9 {
        tshark.push_str(&format!("10.0.0.{index}\n"));
        fin_stdout.push_str("9.9.9.9\n");
    }
    let report = check_pair(&pair(&tshark, &fin_stdout, "", 0)).unwrap();
    assert_eq!(report.faults.len(), 8);
    assert_eq!(report.omitted_faults, 1);
    assert!(report.to_string().contains("1 more faults"));
}
