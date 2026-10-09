---
id: sync-harness
kind: capability
when: you edit a file under .ax/ by hand
hints: [user-invocable]
---

Log saves already rewrite AGENTS.md and CLAUDE.md. If you edited `.ax/intent.md`, a capability, or a check by hand, run `ax compile`, then `ax check`. If the check fails, fix the source and run them again. Do not ask the human to run a weekly command schedule.
