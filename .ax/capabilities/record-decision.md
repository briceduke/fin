---
id: record-decision
kind: capability
when: a choice between real alternatives gets made
hints: [user-invocable]
---

When you make a real choice, write it down in this repo.

Log a decision only when a later chat would do the wrong thing without it. Skip it when the vision already says it, or when it is a task you are about to do. Every decision adds a line to AGENTS.md, and every chat loads that file.

1. Run `ax log decision "<short title>"` and pipe markdown on stdin: `## Context`, `## Options`, `## Choice`, `## Why`. ## Choice is one sentence, at most 200 characters. That sentence, plus the file path, is the line in AGENTS.md. ax rejects an empty choice, a second sentence, or a longer line. No pipe writes those headings empty. The command rewrites AGENTS.md and CLAUDE.md before it returns. Do not ask for a compile step.
2. Do not edit an old decision. Write a new one. If it replaces an older choice, pass `--supersedes <id>`.
3. Ask whether a machine can test the choice. If yes, add a check in `.ax/checks.yaml` in the same change and set `enforces:` to the new decision file.

Put detail in Context, Options, and Why. The root files get the Choice sentence only.
