---
id: 2026-10-10-further-cuts-after-the-16-thread-read-saved-less
kind: observation
date: 2026-10-10
method: cmd.exe, one warmup, median of three, stdout discarded, 10 Oct 2026
---

Further cuts after the 16-thread read saved less than 1ms. Shared handles, sequential scan, mapping, 32 threads, and thin LTO were slower or inside the noise. The process median stayed about 0.043s and the in-memory walk about 0.017s.
