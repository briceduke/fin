---
id: 2026-11-02-fin-does-not-implement-version
kind: decision
date: 2026-11-02
---

## Context

The v1 lock's Why says the README and `fin --version` name tshark 4.6.9. Fin has no `--version` flag. Adding one would grow the CLI for a string the harness and README already pin.

## Options

- Add `fin --version` that prints tshark 4.6.9
- Leave the lock sentence standing with no flag
- Record that fin does not implement `--version`; the oracle version lives in the harness pin and README

## Choice

Fin does not implement --version; tshark 4.6.9 is the oracle, recorded in the harness pin and README.

## Why

The CLI accepts the tshark flags it can honor. `--version` is not one of them; an unrecognized flag is an error. The README headline and the harness version token still pin 4.6.9. This replaces the lock's `fin --version` claim without changing that lock's Choice.
