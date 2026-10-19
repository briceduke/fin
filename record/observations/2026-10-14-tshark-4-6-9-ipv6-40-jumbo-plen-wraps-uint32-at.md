---
id: 2026-10-14-tshark-4-6-9-ipv6-40-jumbo-plen-wraps-uint32-at
kind: observation
date: 2026-10-14
method: live tshark 4.6.9 empty WIRESHARK_CONFIG_DIR vs fin hopopt jumbo 0xFFFFFFD7..0xFFFFFFFF
---

tshark 4.6.9 IPv6 40+jumbo plen wraps uint32 at 0xFFFFFFD8 so ip.src is blank
