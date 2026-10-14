---
id: 2026-10-14-tshark-4-6-9-hopopt-dstopts-apn6-0x13-and-smf-dpd-0x08
kind: observation
date: 2026-10-14
method: live tshark 4.6.9 empty WIRESHARK_CONFIG_DIR vs packet-ipv6.c dissect_opt_apn6 and dissect_opt_smf_dpd
---

tshark 4.6.9 hopopt/dstopts APN6 (0x13) and SMF_DPD (0x08) read past opt_len so a last-TLV short IPv4 BoundsError-skips the next header
