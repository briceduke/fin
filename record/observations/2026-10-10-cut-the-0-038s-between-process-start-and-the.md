---
id: 2026-10-10-cut-the-0-038s-between-process-start-and-the
kind: observation
date: 2026-10-10
method: 10 Oct 2026 release bench, median of 3, stdout discarded
---

Cut the 0.038s between process start and the in-memory frame walk. On the million-packet Ethernet file the release process median was 0.057s and read_capture alone was 0.019s.
