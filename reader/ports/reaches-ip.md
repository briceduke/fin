# UDP/TCP paths that reach the IPv4 (`ip`) dissector

Source: Wireshark / tshark **4.6.9** tag `v4.6.9` (commit `g2d548b197c75`), official tarball
`wireshark-4.6.9.tar.xz` SHA256 `d062d416a1ab3a49975aafe3a671c882dde0562ccd71b078808ceb59d465fc0f`.

**Reaches-IP** means a UDP/TCP *port* dissector, *conversation* dissector, or **enabled** heuristic (`T` in `heuristic-decodes.txt`) can call the IPv4 packet dissector (`find_dissector("ip")` / `ip_handle`) on bytes inside this frame, or can call inner Ethernet / PPP / LLC / GRE / MPLS / X.25 / `pcap_pktdata` that then hits `ethertype` `ETHERTYPE_IP` (`epan/dissectors/packet-ip.c` `proto_reg_handoff_ip` registers `ipv4_handle` on `"ethertype"`). DNS putting an A record in the tree does **not** count.

Inner Ethernet is enough: `packet-eth.c` `proto_reg_handoff_eth` obtains `ethertype_handle`, and `packet-ip.c` binds `ETHERTYPE_IP` to `ipv4_handle`.

Default UDP/TCP `try_heuristic_first` is **false** (`static bool try_heuristic_first` in `packet-udp.c` / `packet-tcp.c`). Heuristics run only after both ports fail or reject. Disabled heuristics (`F` in `heuristic-decodes.txt`) are omitted even if the C file registers them (notably `teredo_udp`, `wassp_udp`, `rtp_udp`).

---

## Port dissectors

| name | ports | citation | why it reaches IP |
|---|---|---|---|
| `vxlan` | udp 4789,8472 | `epan/dissectors/packet-vxlan.c` `dissect_vxlan_common` — non-GPE path `call_dissector(eth_handle, next_tvb, …)` after the 8-byte header. | Inner Ethernet then `ethertype` IPv4. Always claims (`return tvb_captured_length`). |
| `vxlan_gpe` | udp 4790 | `epan/dissectors/packet-vxlan.c` `dissect_vxlan_common` — GPE path `dissector_try_uint(vxlan_dissector_table, vxlan_next_proto, …)`. | `packet-ip.c` `proto_reg_handoff_ip` registers `"vxlan.next_proto"` `VXLAN_IPV4` → `ip_handle`; next-proto Ethernet/NSH/MPLS also reach IP. |
| `geneve` | udp 6081 | `epan/dissectors/packet-geneve.c` `dissect_geneve` — `dissector_try_uint(ethertype_dissector_table, proto_type, next_tvb, …)`. | Protocol type `0x0800` is IPv4 via the ethertype table. |
| `gtp` | udp 2123,2152; tcp 2123,2152 | `epan/dissectors/packet-gtp.c` `dissect_gtp` / `dissect_gtp_common` — T-PDU default `dissect_tpdu_as = GTP_TPDU_AS_TPDU_HEUR` runs `heur_subdissector_list` `"gtp.tpdu"`. | `packet-ip.c` registers enabled heuristic `ip_gtp.tpdu`; same file registers `eth_gtp.tpdu` which `call_dissector(eth_handle, …)` on ethertype IP/IPv6/ARP/PPPoE. `g_gtp_over_tcp = true` also binds the same handles on TCP. |
| `gre` | udp 4754 | `epan/dissectors/packet-gre.c` `dissect_gre` — `dissector_try_uint_with_data(gre_dissector_table, type, next_tvb, …)`; handoff `dissector_add_uint("udp.port", GRE_IN_UDP_PORT, gre_handle)`. | `packet-ip.c` registers `"gre.proto"` `ETHERTYPE_IP` → `ip_handle`. |
| `mpls` | udp 6635 | `epan/dissectors/packet-mpls.c` `dissect_try_cw_first_nibble` — first nibble `4` `call_dissector(dissector_ip, tvb, …)`. | MPLS-in-UDP payload can be IPv4; `dissector_ip = find_dissector_add_dependency("ip", …)`. |
| `lisp` | udp 4342 | `epan/dissectors/packet-lisp.c` `dissect_lisp_ecm` — encapsulated version nibble `4` `call_dissector(ipv4_handle, next_tvb, …)` where `ipv4_handle` is `"ip"`. | LISP Encapsulated Control Message carries an inner IPv4 packet. |
| `lisp-data` | udp 4341 | `epan/dissectors/packet-lisp-data.c` `dissect_lisp_data` — version nibble `4` `call_dissector(ipv4_handle, next_tvb, …)`. | LISP data plane encapsulates IPv4. |
| `ayiya` | udp 5072 | `epan/dissectors/packet-ayiya.c` `dissect_ayiya` — opcode Forward `dissector_try_uint(ip_dissector_table, next_header, payload, …)` with `ip_dissector_table = find_dissector_table("ip.proto")`. | Next-header `IP_PROTO_IPIP` (4) is `ip_handle` (`packet-ip.c` `dissector_add_uint("ip.proto", IP_PROTO_IPIP, ip_handle)`). |
| `tzsp` | udp 37008 | `epan/dissectors/packet-tzsp.c` `proto_reg_handoff_tzsp` — `"tzsp.encap"` Ethernet → `eth_maybefcs`, RAW → `raw_ip`, PPP → `ppp_hdlc`, 802.11/prism/radiotap/AVS → WLAN dissectors. | Encapsulated capture frames include Ethernet/raw IP/PPP/WLAN that yield `ip.src`. |
| `sflow` | udp 6343 | `epan/dissectors/packet-sflow.c` `dissect_sflow_245` sampled-header path — `dissector_try_uint(header_subdissector_table, header_proto, …)` with default `global_dissect_samp_headers = true`. | `-G decodes` maps `sflow_245.header_protocol` `1` → `eth`, `11` → `ip`. |
| `cflow` | udp 2055,4739,9996; tcp 4739 | `epan/dissectors/packet-netflow.c` `dissect_netflow` — `call_dissector(eth_handle, …)` on decoded frame sections; `register_dissector("cflow", dissect_netflow, …)`. | NetFlow/IPFIX sampled or decoded Ethernet/IP payload is handed to `eth_withoutfcs`. |
| `amt` | udp 2268 | `epan/dissectors/packet-amt.c` `dissect_amt` — Membership Query/Update and Multicast Data `call_dissector(ip_handle, next_tvb, …)`. | AMT carries an inner IPv4 datagram. |
| `l2tp` | udp 1701 | `epan/dissectors/packet-l2tp.c` `dissect_l2tp_udp` — data messages `call_dissector(ppp_hdlc_handle, next_tvb, …)`; v3 data can `call_dissector(llc_handle, …)`. | `packet-ip.c` registers `"ppp.protocol"` `PPP_IP` / `ETHERTYPE_IP` → `ip_handle`; LLC SNAP ethertype is IPv4. Also `conversation_set_dissector(conv, l2tp_udp_handle)`. |
| `capwap.data` | udp 5247 | `epan/dissectors/packet-capwap.c` data path — `call_dissector(ieee8023_handle, next_tvb, …)` or WLAN handle; `ieee8023_handle = find_dissector_add_dependency("eth_withoutfcs", …)`. | Inner 802.3 Ethernet then IP. |
| `lwapp` | udp 12222,12223 | `epan/dissectors/packet-lwapp.c` `dissect_lwapp` — `call_dissector(eth_withoutfcs_handle, …)` or WLAN. | Inner Ethernet or 802.11 SNAP can yield IP. |
| `lwapp-l3` | udp 12220 | `epan/dissectors/packet-lwapp.c` `proto_reg_handoff_lwapp` — `LWAPP_8023_PORT` bound to `lwapp_l3_handle` in the same file that calls `eth_withoutfcs`. | LWAPP 802.3 port is Ethernet-in-UDP. |
| `llc` | udp 12000–12004 | `epan/dissectors/packet-llc.c` `dissect_llc` — `dissector_try_uint(ethertype_subdissector_table, etype, …)` and SNAP Ethernet. | Ethertype `0x0800` is IPv4. |
| `infiniband` | udp 4791 | `epan/dissectors/packet-infiniband.c` RoCE payload — `call_dissector(eth_handle, …)` and `dissector_try_uint(ethertype_dissector_table, …)`. | Ethernet-over-IB / ethertype IPv4. |
| `udpencap` | udp 4500 | `epan/dissectors/packet-ipsec-udp.c` `dissect_udpencap` — non-zero SPI `call_dissector(esp_handle, tvb, …)`. | `packet-ipsec.c` `dissect_esp` after decrypt `dissector_get_uint_handle(ip_dissector_table, encapsulated_protocol)` then `call_dissector`; next-header 4 is IPIP/`ip`. Needs ESP keys to actually show `ip.src`; the call exists in 4.6.9. |
| `openflow` | tcp 6653 | `epan/dissectors/packet-openflow.c` `dissect_openflow` → version dissectors; `packet-openflow_v1.c` / `_v4.c` / `_v5.c` / `_v6.c` `call_dissector(eth_withoutfcs_handle, next_tvb, …)` on packet-in / packet-out. | Embedded Ethernet frames. Heuristic `openflow_tcp` is enabled and `conversation_set_dissector(conversation, openflow_handle)`. |
| `msdp` | tcp 639 | `epan/dissectors/packet-msdp.c` SA TLV path — `call_dissector(ip_handle, next_tvb, …)` with `ip_handle = find_dissector_add_dependency("ip", proto_msdp)`. | Encapsulated IPv4 multicast source packets. |
| `mip` | udp 434 | `epan/dissectors/packet-mip.c` `dissect_mip` — `call_dissector(ip_handle, next_tvb, …)` for tunneled payload. | Mobile IP can carry an inner IPv4 packet. |
| `jmirror` | udp 30030 | `epan/dissectors/packet-jmirror.c` `dissect_jmirror` — version nibble `0x45` selects `ipv4_handle = find_dissector_add_dependency("ip", …)` then `call_dissector`. | Juniper mirrored IPv4 packets. |
| `msrcp` | udp 3343 | `epan/dissectors/packet-msrcp.c` `dissect_msrcp` — `call_dissector(eth_handle, next_tvb, …)`. | Inner Ethernet. |
| `wassp` | udp 13907,13910 | `epan/dissectors/packet-wassp.c` — `call_dissector(ip_handle, …)` and `call_dissector(eth_handle, …)`. | WASSP TLVs carry IP or Ethernet. (UDP heuristic `wassp_udp` is **disabled**; the port binding still applies.) |
| `acdr` | udp 925 | `epan/dissectors/packet-acdr.c` — `call_dissector(ip_dissector_handle, tvb, …)` with `ip_dissector_handle = find_dissector("ip")`. | Some AC DR media types are raw IP. `-G decodes` also maps `acdr.media_type` `0x0e` / `0x32` → `eth`. |
| `bat.gw` | udp 4306 | `epan/dissectors/packet-bat.c` gateway path — `call_dissector(ip_handle, next_tvb, …)` with `ip_handle = find_dissector_add_dependency("ip", proto_bat_gw)`. | BATMAN gateway encapsulation of IP. |
| `mint` | udp 24576,24577 | `epan/dissectors/packet-mint.c` `dissect_mint_ethshim_static` — `call_dissector(eth_handle, eth_tvb, …)`. | Inner Ethernet. |
| `xot` | tcp 1998 | `epan/dissectors/packet-xot.c` `dissect_xot` — `call_dissector(x25_handle, next_tvb, …)`; `conversation_set_dissector`. | `packet-ip.c` registers `"x.25.spi"` `NLPID_IP` → `ip_handle`. |
| `gsmtap` | udp 4729 | `epan/dissectors/packet-gsmtap.c` `proto_reg_handoff_gsmtap` — sub-handles include `"ppp"` and `"sndcp"`. | `packet-sndcp.c` holds `ip_handle`; PPP protocol IP is `ip_handle`. |
| `wg` | udp 0 (preference dummy; ignored by `decode_udp_ports`) | `epan/dissectors/packet-wireguard.c` `wg_decrypt_packet` — if `pref_dissect_packet` (default true) `call_dissector(ip_handle, new_tvb, …)`. | Enabled UDP heuristic `wg`. Inner IPv4 appears only when decryption keys work; the call is in tree. |

---

## Enabled UDP/TCP heuristics (parent `udp` or `tcp`, enabled column `T`)

| name | heuristic id | citation | why it reaches IP |
|---|---|---|---|
| `rpcap` | `rpcap_udp`, `rpcap_tcp` | `epan/dissectors/packet-rpcap.c` `dissect_rpcap` — `call_dissector_with_data(pcap_pktdata_handle, new_tvb, …, &linktype)`; TCP heuristic `conversation_set_dissector_from_frame_number`. | `packet-pcap_pktdata.c` `dissector_try_uint_with_data(wtap_encap_table, …)` including `WTAP_ENCAP_ETHERNET`. |
| `e100` | `e100_udp` | `epan/dissectors/packet-e100.c` `dissect_e100_heur` — `call_dissector(eth_handle, next_tvb, …)`. | Inner Ethernet. |
| `redbackli` | `redbackli_udp` | `epan/dissectors/packet-redbackli.c` — `call_dissector(ip_handle, next_tvb, …)`. | Lawful-intercept payload is IPv4. Decode-as UDP only (no default port in `-G`). |
| `peekremote` | `peekremote_udp` | `epan/dissectors/packet-peekremote.c` — `call_dissector(radiotap_handle, …)` / `wlan_radio`. | 802.11 SNAP can yield IP. |
| `rftap` | `rftap` | `epan/dissectors/packet-rftap.c` — `pcap_pktdata_handle = find_dissector_add_dependency("pcap_pktdata", …)`. | Same captured-frame path as rpcap. |
| `tcpencap` | `ipsec_tcp` | `epan/dissectors/packet-ipsec-tcp.c` `dissect_tcpencap` — ESP branch `call_dissector(esp_handle, …)`. | Same ESP-decrypt-to-`ip.proto` path as `udpencap`. Also `dissector_add_for_decode_as_with_preference("tcp.port", tcpencap_handle)`. |
| `openflow` | `openflow_tcp` | `epan/dissectors/packet-openflow.c` `dissect_openflow_heur` — locks the TCP conversation then `dissect_openflow`. | Same packet-in Ethernet as the port dissector. |
| `wg` | `wg` | `epan/dissectors/packet-wireguard.c` `dissect_wg_heur` / `wg_dissect` — `conversation_set_dissector`; decrypt path calls `ip_handle`. | See port row; the live default is this heuristic (UDP port 0 is skipped). |

GTP's enabled `ip_gtp.tpdu` / `eth_gtp.tpdu` heuristics are parent `gtp.tpdu`, not `udp`/`tcp`. They still fire from the `gtp` **port** dissector above.

---

## Unproven, treated as reaches-IP

These were not given a full inner-payload proof in this pass. Treat them as able to produce `ip.src` so a query-specific reader counts affected frames rather than missing them.

| name | why unproven |
|---|---|
| `teredo` (udp 3544) | Calls `ipv6` only (`packet-teredo.c` `data_handle = find_dissector("ipv6")`). IPv6 next-header 4 is IPIP, so 4in6 *could* reach `ip`; not traced packet-by-packet. Heuristic `teredo_udp` is **disabled**. |
| `capwap` control (udp 5246) | Control plane is DTLS, not Ethernet; listed so a mixed CAPWAP flow is not dropped. |
| `openvpn` (udp/tcp 1194) | Encrypted; no `ip_handle` found in a short read. |
| `dtls` / `tls` | Encrypted; no default inner-IP call without keys. |
| `stun` / `classicstun` | TURN ChannelData uses `data_handle = find_dissector("data")`, not `ip`. A STUN conversation can still steal the 5-tuple from a later tunnel via `conversation_set_dissector`. |
| `socks` | Wraps TCP/UDP streams via `decode_tcp_ports` / `decode_udp_ports`, not an IP packet. Nested UDP could then hit a tunnel. |
| `proxy` | HAProxy PROXY header; remainder is the original stream, not an IP datagram. |
| `nsh` | No `udp.port` binding; reached via VXLAN-GPE / Geneve / GRE (already counted). |
| `gue` | No `packet-gue.c` in 4.6.9. |
| `atmtcp` | TCP 281 (not fully traced). |
| `pptp` | TCP control only; GRE data is a separate IP proto, not this TCP port. |
| `hip` | UDP 10500 signaling; `dissect_hip_in_udp` does not call `ip`. |
| `pktgen` | Enabled UDP heuristic; magic-number header only, no inner IP. |
| `li5g` | Payload type 5 is `ip`, but default UDP/TCP port range is empty (not in `-G`). |
| `hp-erm` | Calls `eth_withoutfcs` but only decode-as UDP (not in `-G` ports). |
| `nas-eps` / `nas-5gs` / `pdcp-*` / `rlc-*` / `mac-*` / `dvb-s2_modeadapt` | Have `ip`/`eth` handles but their **UDP heuristics are disabled**. |

DNS (`dns` udp/tcp 53) is **not** reaches-IP: `dissect_dns_udp_sctp` never calls the IPv4 packet dissector (A records are tree fields).
