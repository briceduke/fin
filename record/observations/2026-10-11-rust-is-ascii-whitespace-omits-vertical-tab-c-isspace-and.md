---
id: 2026-10-11-rust-is-ascii-whitespace-omits-vertical-tab-c-isspace-and
kind: observation
date: 2026-10-11
method: harness extra \x0b+1 vs tshark 4.6.9
---

Rust is_ascii_whitespace omits vertical tab; C isspace and tshark g_ascii_strtoull include 0x0b
