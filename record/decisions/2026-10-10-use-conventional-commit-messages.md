---
id: 2026-10-10-use-conventional-commit-messages
kind: decision
date: 2026-10-10
---

## Context

The first commits on this branch are plain sentences. A later session that keeps writing them that way will mix two styles in the history.

## Options

- Keep freeform sentence messages
- Use Conventional Commits from here on

## Choice

Commit messages use Conventional Commits: a type, an optional scope, and an imperative subject.

## Why

The type is one of feat, fix, docs, refactor, test, or chore. The subject is imperative, lowercase, and has no final period. Example: `docs: record the v1 reader and build order`.

The two commits already on `cursor/lock-v1-reader-architecture` are plain sentences. Rewriting them changes published history.
