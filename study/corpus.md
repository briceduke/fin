# tshark baseline corpus

Captures live under `study/corpus/`. `.pcap` / `.pcapng` / `.cap` are gitignored. Synthetics were written by `study/write_corpus.py` as classic little-endian pcap (magic `d4 c3 b2 a1`, version 2.4, snaplen 65535, linktype 1 Ethernet). Checksums are zero. IPv4 source addresses walk `10.x.y.z` by packet index so frames are not one repeated blob.

Verified with Wireshark 4.6.9 `capinfos.exe` and `tshark.exe` (not on PATH; `C:\Program Files\Wireshark\`). Packet counts match. `tshark -n -c 2 -T fields -e frame.number -e eth.type -e ip.src` dissects as described below. On the 100-packet siblings: plain prints 100 `ip.src` values; QinQ still prints 100 addresses (VLAN did not hide IP); mixed-100 has 50 empty lines and 50 addresses.

## Synthetic

| File | Packets | Bytes | Layout |
| --- | ---: | ---: | --- |
| `corpus/eth-ipv4-udp.pcap` | 1,000,000 | 74,000,024 | Ethernet ethertype 0x0800, 20-byte IPv4 proto 17, UDP, 16-byte payload. IPv4 src at IP header byte 12 (frame offset 26). |
| `corpus/eth-ipv4-udp-100.pcap` | 100 | 7,424 | Same layout, 100 packets, for spot checks. |
| `corpus/eth-qinq-ipv4-udp.pcap` | 1,000,000 | 82,000,024 | Ethernet ethertype 0x88a8, outer VLAN 10, ethertype 0x8100, inner VLAN 20, ethertype 0x0800, then the same IPv4/UDP. IPv4 src is at frame offset 34, so a constant offset of 26 is wrong. tshark still prints `ip.src`. |
| `corpus/eth-qinq-ipv4-udp-100.pcap` | 100 | 8,224 | Same QinQ layout, 100 packets. |
| `corpus/mixed.pcap` | 1,000,000 | 66,000,024 | Even packets: Ethernet ethertype 0x0806 plus a 28-byte ARP request (no `ip.src`). Odd packets: the plain Ethernet+IPv4+UDP frame. Half the packets have no `ip.src`. |
| `corpus/mixed-100.pcap` | 100 | 6,624 | Same mixed layout, 100 packets (50 ARP, 50 IPv4/UDP). |

Spot-check `tshark -n -T fields -e ip.src` on the 100-packet files: 100 filled / 100 filled / 50 empty + 50 filled.

## Real

| File | Packets | Bytes |
| --- | ---: | ---: |
| `corpus/real/challenge01_ooo_stream.pcapng` | 1,670 | 1,648,580 |

Not synthesized. Official Wireshark test capture from the wireshark/wireshark tree:

- URL: https://raw.githubusercontent.com/wireshark/wireshark/master/test/captures/challenge01_ooo_stream.pcapng.gz
- Path in that repo: `test/captures/challenge01_ooo_stream.pcapng.gz` (1,522,510 bytes gzipped; stored here decompressed)
- Encapsulation: Ethernet. tshark shows `ip.src` on the first frames (10.120.81.185, 158.101.208.24).
- This file is above 1 MB. The wiki.wireshark.org `AttachFile` endpoint returned HTML, not captures, so this GitHub raw of the official test corpus was used instead.
