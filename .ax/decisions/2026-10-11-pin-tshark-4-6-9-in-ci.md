---
id: 2026-10-11-pin-tshark-4-6-9-in-ci
kind: decision
date: 2026-10-11
---

## Context

GitHub Actions `test` run 38178498663 failed only in `harness/tests/pcapng_options.rs` because ubuntu-latest has no tshark. The test spawned `"tshark"` and panicked. `harness/tests/run.rs` skips when the Windows binary is missing. `.github/workflows/test.yml` already said to install tshark 4.6.9 in CI once the sequential reader exists.

## Options

- Install exactly tshark 4.6.9 in `test.yml` from the official SHA256-pinned source tarball, keep the empty config dir and the 4.6.9 version check
- Gate the pcapng oracle like `run.rs` and leave CI without tshark
- Mark the test `#[ignore]`

## Choice

CI installs tshark 4.6.9 from the official SHA256-pinned source tarball; local oracle tests skip if that binary is missing.

## Why

Matching tshark 4.6.9 is the product, so CI must run the oracle, not skip it. Apt is unpinned. `#[ignore]` would skip local machines that have tshark. Skip-on-missing keeps `cargo test` usable without tshark; the workflow install and version grep make CI fail if 4.6.9 is absent.
