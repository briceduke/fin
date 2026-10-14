# ip.src vs tshark 4.6.9

Walk of `reader/src/ip_src.rs` against tshark 4.6.9 (`v4.6.9-0-g2d548b197c75`) `packet-eth`, `packet-vlan` / `packet-ieee8021ah` (802.1ad), `packet-ip`, `packet-ipv6` (hop-by-hop, routing, fragment, dest options, AH, ESP, mobility, shim6, no-next-header), `packet-udp`, `packet-icmp`, `packet-icmpv6`, `packet-vxlan`, `packet-etherip`, `packet-ipsec` (AH), IPIP (`ip.proto` 4 → `dissect_ip`), and TEB (`ethertype` 0x6558). Live checks use an empty `WIRESHARK_CONFIG_DIR`.

A counted miss is allowed. The table is only uncounted extras or uncounted drops.

## Divergences

| Layer | tshark 4.6.9 | fin before this audit | Status |
| --- | --- | --- | --- |
| IPv6 hopopt jumbo | `set_actual_length(tvb, 40 + plen)` is uint32. Jumbo `≥ 0xFFFFFFD8` wraps to 0..=39, so the IPv6 tvbuff has no payload and `ip.src` is blank. `0xFFFFFFD7` and `65536` still walk. | `take_len` used the unwrapped jumbo and printed inner `10.9.9.9`. | Fixed: `take_ipv6_payload` wraps `40 + plen` as `u32`. |
| VLAN TPID | `0x8100`, `0x88a8` (802.1ad, 4-byte tag), default QinQ `0x9100`. `0x9200` / `0x9300` are not VLAN. | Walked `0x9200` / `0x9300` as VLAN. | Already fixed. |
| IPv6 plen | Clip to 16-bit plen. Plen 0 is empty unless hopopt jumbo (`ipv6.tso_support` defaults off). | Walked captured bytes past plen. | Already fixed. |
| IPv4 tot_len | Print `ip.src` only when tot_len is 0 (TSO, default on) or tot_len ≥ IHL. | Printed when `0 < tot_len < IHL`. | Already fixed. |
| UDP length | Length < 8 does not walk. IPv6 length 0 is a jumbogram. | Walked the captured tail. | Already fixed. |
| IPv4 version 6 | `dissect_ip` / `dissect_ip_v4` hands version 6 to IPv6. | Returned without a count. | Already fixed. |
| ICMP embed tot_len | Same tot_len rule as outer IPv4. | Printed embed src on short tot_len; missed version-6 embeds. | Already fixed. |
| ICMP RFC 4884 embed | Types 3/4/11/12 clip when byte 5 is nonzero, ICMP is longer than `8 + length*4`, and `ntohs` at offset 10 (IPv4 tot_len / IPv6 flow low 16) is greater than `length*4`, to `(IHL_nibble + length)*4`. IPv6 IHL nibble is 0. Type 5 stays `IHL*4+8`. | Walked a version-6 ICMP embed past tshark's clip and printed inner `ip.src`. | Fixed: `rfc4884_embed_len` clips before `embedded_ipv4`. |
| IPv6 routing type 2 / 4 | `dissect_routing6` calls `ipv6_dissect_next`, but type 2 (`dissect_routing6_mipv6`) and type 4 (`dissect_routing6_srh`) read 16-byte addresses from tvbuff `total_len-4`. Type 2 needs 20 type bytes (hdrlen ≥ 2). Type 4 needs `4 + 16*(last_entry+1)`. Short → BoundsError, no next, blank `ip.src`. Type 0 / 3 / unknown hdrlen 0 still walk. | Always skipped `(hdrlen+1)*8` and walked next, printing inner `10.9.9.9`. | Fixed: `take_routing` stops on those BoundsError lengths. |
| ICMP / ICMPv6 fragments, ICMP IPIP leftover, IPv4 AH / EtherIP, TEB 0x6558 | tshark prints an inner `ip.src`. | Dropped with no count. | Already fixed (walk or count). |

## Length arithmetic (wrap / width)

| Site | Width | Wrap that changes `ip.src`? |
| --- | --- | --- |
| IPv6 `40 + plen` (`packet-ipv6.c` `set_actual_length`) | `IPv6_HDR_SIZE` (40) + `uint32_t` plen → `unsigned` | Yes. Jumbo `≥ 0xFFFFFFD8`. Matched. |
| IPv4 tot_len | `uint16` via `tvb_get_ntohs`; TSO 0 uses reported length (≤ 262144) | No. |
| UDP length | `uint16`; `< 8` stops; IPv6 0 uses remaining | No. |
| IPv6 hop/dest/routing `(hdrlen + 1) * 8` | `uint8` → int | No (max 2048). |
| AH `(payload_len + 2) * 4` | `uint8` → int | No (max 1028). |
| ICMP type 5 `IHL*4 + 8` | nibble | No (max 68). |
| ICMP RFC 4884 `(IHL_nibble + orig_len) * 4` | `uint8` | No wrap. Matched. Length 0 does not clip. Length 1–13 with flow `0x0100` clips an IPv6 embed short of the inner IPv4 src. Length 14 clips to 56 and still prints it. Flow `1` with length 1 fails `ntohs > length*4`. Type 5 stays `IHL*4+8`. |
| IPv6 TSO `reported - 40` | unsigned, preference off | No. |

IPv6 routing type 0 / 3 / unknown with hdrlen 0 still walk the next header on both (live: inner `10.9.9.9`). Type 2 hdrlen 0 / 1 and type 4 hdrlen 0 / 1 / hdrlen 2 with `last_entry=255` stay blank on both. Type 2 / 4 with hdrlen ≥ 2 and a fitting address list still walk. Shim6 (140) next=4 is a counted miss. Mobility (135) on an 8-byte stub is blank on both. ESP and no-next-header stop on both. GRE is counted. EtherIP still walks after a 2-byte header when the version is not 3 (tshark does too). AH payload-length 0 is an 8-byte header on both and still walks.
