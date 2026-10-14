---
id: 2026-10-14-tshark-4-6-9-tel-rtalert-dff-read-1-2-3-past-opt-len-so
kind: observation
date: 2026-10-14
method: live tshark 4.6.9 empty WIRESHARK_CONFIG_DIR vs packet-ipv6.c dissect_opt_tel rtalert dff mpl
---

tshark 4.6.9 TEL/rtalert/DFF read 1/2/3 past opt_len so leftover Jumbo BoundsErrors; MPL reads 2+seed_id_len and leftover 0x40 still walks IPIP
