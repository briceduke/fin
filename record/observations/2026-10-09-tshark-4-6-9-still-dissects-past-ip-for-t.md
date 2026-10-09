---
id: 2026-10-09-tshark-4-6-9-still-dissects-past-ip-for-t
kind: observation
date: 2026-10-09
method: Wireshark v4.6.9 source read plus one-packet tshark probes
---

tshark 4.6.9 still dissects past IP for -T fields -e ip.src. Priming fills the proto tree. It does not stop dissect_record. --only-protocols is a manual kill switch and drops ip.src on VLAN unless vlan is listed.
