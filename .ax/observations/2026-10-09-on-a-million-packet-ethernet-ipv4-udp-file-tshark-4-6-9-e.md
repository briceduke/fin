---
id: 2026-10-09-on-a-million-packet-ethernet-ipv4-udp-file-tshark-4-6-9-e
kind: observation
date: 2026-10-09
method: median of 3 wall-clock runs, stdout discarded, -n, i9-14900HX
---

On a million-packet Ethernet/IPv4/UDP file, tshark 4.6.9 -e ip.src takes 7.97s (125k packets/s), matching -e frame.number. Disabling upper protocols saves 22%. -V is about 21x slower per packet. The extra walk is real and is a minority of the time.
