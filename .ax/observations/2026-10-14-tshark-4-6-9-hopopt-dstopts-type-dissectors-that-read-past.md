---
id: 2026-10-14-tshark-4-6-9-hopopt-dstopts-type-dissectors-that-read-past
kind: observation
date: 2026-10-14
method: live tshark 4.6.9 empty WIRESHARK_CONFIG_DIR vs packet-ipv6.c dissect_opts offset snap
---

tshark 4.6.9 hopopt/dstopts type dissectors that read past opt_len leave offset there so leftover header bytes are not a new TLV and IPIP still walks
