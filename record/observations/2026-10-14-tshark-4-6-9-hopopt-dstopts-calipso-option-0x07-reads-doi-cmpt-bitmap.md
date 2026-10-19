---
id: 2026-10-14-tshark-4-6-9-hopopt-dstopts-calipso-option-0x07-reads-doi-cmpt-bitmap
kind: observation
date: 2026-10-14
method: live tshark 4.6.9 empty WIRESHARK_CONFIG_DIR vs packet-ipv6.c dissect_opt_calipso
---

tshark 4.6.9 hopopt/dstopts CALIPSO (option 0x07) reads DOI/cmpt/bitmap past opt_len so a short header BoundsError-skips the next header
