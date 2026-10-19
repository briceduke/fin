# UDP/TCP port dissectors that may reject

Source: Wireshark / tshark **4.6.9** tag `v4.6.9` (commit `g2d548b197c75`).

## Mechanism

`decode_udp_ports` (`epan/dissectors/packet-udp.c`) and `decode_tcp_ports` (`epan/dissectors/packet-tcp.c`) try the **lower port first**, then the higher port (TCP also tries a SYN-learned `server_port` first). `dissector_try_uint` / `dissector_try_uint_with_data` (`epan/packet.c`) call `call_dissector_work`. A new-style dissector that **`return 0`** is a reject: `packet.c` documents that 0 means the dissector did not think the tvbuff was its protocol, so the caller continues. After both ports reject (or are 0), UDP/TCP run the heuristic list unless `try_heuristic_first` is set (default **false**, `static bool try_heuristic_first` in both files).

Old-style void dissectors cannot reject (`epan/packet.c` comment above `dissector_try_uint_with_data`). In 4.6.9 the registered UDP/TCP handles used here are `int` dissectors; `return 0` in that function is may-reject.

A port dissector that **always** returns `tvb_captured_length` / `tvb_reported_length` with no `return 0` in the registered function is omitted. That proved-always-claim set includes `vxlan`, `vxlan_gpe`, `geneve`, `dns`, `discard`, `echo`, `gre`, `mpls`, `lisp`, `ayiya`, `tzsp`, `amt`, `teredo`, `openflow`, `llc`, `udpencap`, `mip`, `capwap`, `capwap.data`, `lwapp`, `msrcp`, `wassp`, `acdr`, `gtpprime`. `discard` (`epan/dissectors/packet-discard.c` `dissect_discard`) returns `cap_len` and never `return 0`; UDP 9 tries WOL first, then still claims.

## Proved may-reject

Why, unless noted: the registered port function contains `return 0`, so tshark can fall through to the other port and then to heuristics.

| name | ports | citation | why it may reject |
|---|---|---|---|
| `5co_legacy` | udp 7010; tcp 8004,8010 | `epan/dissectors/packet-5co-legacy.c` `dissect_FiveCoLegacy_tcp` — can `return 0` (function starts at line 628). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `a11` | udp 699 | `epan/dissectors/packet-3g-a11.c` `dissect_a11` — can `return 0` (function starts at line 1530). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `acap` | tcp 674 | `epan/dissectors/packet-acap.c` `dissect_acap` — can `return 0` (function starts at line 40). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `actrace` | udp 2428 | `epan/dissectors/packet-actrace.c` `dissect_actrace` — can `return 0` (function starts at line 433). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `adwin` | udp 6543 | `epan/dissectors/packet-adwin.c` `dissect_adwin` — can `return 0` (function starts at line 1068). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `aodv` | udp 654 | `epan/dissectors/packet-aodv.c` `dissect_aodv` — can `return 0` (function starts at line 623). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `aol` | tcp 5190 | `epan/dissectors/packet-aol.c` `dissect_aol` — can `return 0` (function starts at line 289). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `ardp` | udp 9955; tcp 9955 | `epan/dissectors/packet-alljoyn.c` `dissect_AllJoyn_ardp` — can `return 0` (function starts at line 2324). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `armagetronad` | udp 4533,4534 | `epan/dissectors/packet-armagetronad.c` `dissect_armagetronad` — can `return 0` (function starts at line 208). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `ath` | udp 45564 | `epan/dissectors/packet-ath.c` `dissect_ath` — can `return 0` (function starts at line 82). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `babel` | udp 6696 | `epan/dissectors/packet-babel.c` `dissect_babel` — can `return 0` (function starts at line 564). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `bgp` | tcp 179 | `epan/dissectors/packet-bgp.c` `dissect_bgp` — can `return 0` (function starts at line 11794). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `bundle` | udp 4556 | `epan/dissectors/packet-bpv6.c` `dissect_bundle` — can `return 0` (function starts at line 1960). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `busmirroring` | udp 30511 | `epan/dissectors/packet-busmirroring.c` `dissect_busmirroring` — can `return 0` (function starts at line 107). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `bvlc` | udp 47808 | `epan/dissectors/packet-bvlc.c` `dissect_bvlc` — can `return 0` (function starts at line 946). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `caneth` | udp 11898 | `epan/dissectors/packet-caneth.c` `dissect_caneth` — can `return 0` (function starts at line 139). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `cast` | tcp 4224 | `epan/dissectors/packet-cast.c` `dissect_cast` — can `return 0` (function starts at line 1009). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `cflow` | udp 2055,4739,9996; tcp 4739 | `epan/dissectors/packet-netflow.c` `dissect_netflow` — can `return 0` (function starts at line 4458). | `dissect_netflow` (also registered as `cflow`) can `return 0`. |
| `cmpp` | tcp 7890,7900,7930,9168 | `epan/dissectors/packet-cmpp.c` `dissect_cmpp` — can `return 0` (function starts at line 618). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `componentstatusprotocol` | udp 2960 | `epan/dissectors/packet-componentstatus.c` `dissect_componentstatusprotocol` — can `return 0` (function starts at line 255). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `couchbase` | tcp 11210 | `epan/dissectors/packet-couchbase.c` `dissect_couchbase_pdu` — can `return 0` (function starts at line 3784). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `cpfi` | udp 5001 | `epan/dissectors/packet-cpfi.c` `dissect_cpfi` — can `return 0` (function starts at line 295). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `cpha` | udp 8116 | `epan/dissectors/packet-cpha.c` `dissect_cpha` — can `return 0` (function starts at line 241). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `ddtp` | udp 1052 | `epan/dissectors/packet-ddtp.c` `dissect_ddtp` — can `return 0` (function starts at line 105). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `dhcp` | udp 67,68,4011 | `epan/dissectors/packet-dhcp.c` `dissect_dhcp` — can `return 0` (function starts at line 7153). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `dis` | udp 3000 | `epan/dissectors/packet-dis.c` `dissect_dis` — can `return 0` (function starts at line 20598). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `djiuav` | tcp 2001 | `epan/dissectors/packet-dji-uav.c` `dissect_djiuav_static` — can `return 0` (function starts at line 263). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `egd` | udp 18246 | `epan/dissectors/packet-egd.c` `dissect_egd` — can `return 0` (function starts at line 82). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `elcom` | tcp 5997 | `epan/dissectors/packet-elcom.c` `dissect_elcom` — can `return 0` (function starts at line 396). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `enip` | udp 2222,44818; tcp 44818 | `epan/dissectors/packet-enip.c` `dissect_enip_tcp` — can `return 0` (function starts at line 3661). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `esio` | udp 6060 | `epan/dissectors/packet-esio.c` `dissect_esio` — can `return 0` (function starts at line 109). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `gdsdb` | tcp 3050 | `epan/dissectors/packet-gdsdb.c` `dissect_gdsdb` — can `return 0` (function starts at line 1387). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `glbp` | udp 3222 | `epan/dissectors/packet-glbp.c` `dissect_glbp_static` — can `return 0` (function starts at line 393). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `gtp` | udp 2123,2152; tcp 2123,2152 | `epan/dissectors/packet-gtp.c` `dissect_gtp` — can `return 0` (function starts at line 11106). | Returns 0 if the first byte is missing or version > 2 (`dissect_gtp`); GTP-U T-PDU heuristics never run on a reject. |
| `gvcp` | udp 3956 | `epan/dissectors/packet-gvcp.c` `dissect_gvcp` — can `return 0` (function starts at line 2447). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `hicp` | udp 3250 | `epan/dissectors/packet-hicp.c` `dissect_hicp` — can `return 0` (function starts at line 83). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `hip` | udp 10500 | `epan/dissectors/packet-hip.c` `dissect_hip_in_udp` — can `return 0` (function starts at line 567). | UDP wrapper returns 0 unless the first 4 bytes are zero (`dissect_hip_in_udp`). |
| `hsrp` | udp 1985,2029 | `epan/dissectors/packet-hsrp.c` `dissect_hsrp` — can `return 0` (function starts at line 346). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `icq` | udp 4000 | `epan/dissectors/packet-icq.c` `dissect_icq` — can `return 0` (function starts at line 1214). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `ipdr` | tcp 4737 | `epan/dissectors/packet-ipdr.c` `dissect_ipdr` — can `return 0` (function starts at line 536). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `jmirror` | udp 30030 | `epan/dissectors/packet-jmirror.c` `dissect_jmirror` — can `return 0` (function starts at line 92). | `dissect_jmirror` can `return 0`; otherwise version nibble 4 calls `ip`. |
| `kismet` | tcp 2501 | `epan/dissectors/packet-kismet.c` `dissect_kismet` — can `return 0` (function starts at line 47). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `l2tp` | udp 1701 | `epan/dissectors/packet-l2tp.c` `dissect_l2tp_udp` — can `return 0` (function starts at line 2865). | Returns 0 if captured length < 2 or L2TP version is not 2 or 3 (`dissect_l2tp_udp`). |
| `ldp` | udp 646; tcp 646 | `epan/dissectors/packet-ldp.c` `dissect_ldp` — can `return 0` (function starts at line 3163). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `ldss` | udp 6087 | `epan/dissectors/packet-ldss.c` `dissect_ldss` — can `return 0` (function starts at line 746). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `lisp-data` | udp 4341 | `epan/dissectors/packet-lisp-data.c` `dissect_lisp_data` — can `return 0` (function starts at line 74). | Returns 0 on a too-short header (`dissect_lisp_data`). |
| `lsdp` | udp 11430 | `epan/dissectors/packet-lsdp.c` `dissect_lsdp` — can `return 0` (function starts at line 312). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `mbudp` | udp 502 | `epan/dissectors/packet-mbtcp.c` `dissect_mbudp` — can `return 0` (function starts at line 823). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `mgcp` | udp 2427,2727; tcp 2427,2727 | `epan/dissectors/packet-mgcp.c` `dissect_mgcp` — can `return 0` (function starts at line 458). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `mle` | udp 19788 | `epan/dissectors/packet-mle.c` `dissect_mle` — can `return 0` (function starts at line 668). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `mndp` | udp 5678 | `epan/dissectors/packet-mndp.c` `dissect_mndp_static` — can `return 0` (function starts at line 287). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `mpls-echo` | udp 3503 | `epan/dissectors/packet-mpls-echo.c` `dissect_mpls_echo` — can `return 0` (function starts at line 1841). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `msmms` | udp 1755; tcp 1755 | `epan/dissectors/packet-ms-mms.c` `dissect_msmms_pdu` — can `return 0` (function starts at line 306). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `nano` | udp 7075; tcp 7075 | `epan/dissectors/packet-nano.c` `dissect_nano` — can `return 0` (function starts at line 389). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `nbss` | tcp 139,445 | `epan/dissectors/packet-nbt.c` `dissect_nbss` — can `return 0` (function starts at line 1421). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `ndmp` | tcp 10000 | `epan/dissectors/packet-ndmp.c` `dissect_ndmp` — can `return 0` (function starts at line 3356). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `njack` | udp 5264,5265 | `epan/dissectors/packet-3com-njack.c` `dissect_njack_static` — can `return 0` (function starts at line 656). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `nxp_802154_sniffer` | udp 49999 | `epan/dissectors/packet-nxp_802154_sniffer.c` `dissect_nxp_802154_sniffer` — can `return 0` (function starts at line 87). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `oicq` | udp 8000 | `epan/dissectors/packet-oicq.c` `dissect_oicq` — can `return 0` (function starts at line 104). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `olsr` | udp 698 | `epan/dissectors/packet-olsr.c` `dissect_olsr` — can `return 0` (function starts at line 517). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `omapi` | tcp 7911 | `epan/dissectors/packet-omapi.c` `dissect_omapi` — can `return 0` (function starts at line 94). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `packetbb` | udp 269 | `epan/dissectors/packet-packetbb.c` `dissect_packetbb` — can `return 0` (function starts at line 925). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `pathport` | udp 3792 | `epan/dissectors/packet-pathport.c` `dissect_pathport` — can `return 0` (function starts at line 598). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `pcomtcp` | tcp 20256 | `epan/dissectors/packet-pcomtcp.c` `dissect_pcomtcp` — can `return 0` (function starts at line 190). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `pgsql` | tcp 5432 | `epan/dissectors/packet-pgsql.c` `dissect_pgsql` — can `return 0` (function starts at line 1561). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `portcontrol` | udp 5350,5351 | `epan/dissectors/packet-nat-pmp.c` `dissect_portcontrol` — can `return 0` (function starts at line 643). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `pulse` | udp 539 | `epan/dissectors/packet-pulse.c` `dissect_pulse` — can `return 0` (function starts at line 42). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `pvfs` | tcp 3334 | `epan/dissectors/packet-pvfs2.c` `dissect_pvfs` — can `return 0` (function starts at line 295). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `radius` | udp 1645,1646,1700,1812,1813,3799 | `epan/dissectors/packet-radius.c` `dissect_radius` — can `return 0` (function starts at line 2000). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `rmcp` | udp 623 | `epan/dissectors/packet-rmcp.c` `dissect_rmcp` — can `return 0` (function starts at line 78). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `roon_disco` | udp 9003 | `epan/dissectors/packet-roon_discovery.c` `dissect_roon_discover` — can `return 0` (function starts at line 233). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `rtpproxy` | udp 22222; tcp 22222 | `epan/dissectors/packet-rtpproxy.c` `dissect_rtpproxy` — can `return 0` (function starts at line 534). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `rx` | udp 7000,7001,7002,7003,7004,7005,7006,7007,7008,7009,7021 | `epan/dissectors/packet-rx.c` `dissect_rx` — can `return 0` (function starts at line 405). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `s101` | tcp 9000 | `epan/dissectors/packet-s101.c` `dissect_S101` — can `return 0` (function starts at line 338). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `saphdb` | tcp 30013,30015 | `epan/dissectors/packet-saphdb.c` `dissect_saphdb` — can `return 0` (function starts at line 1257). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `sbus` | udp 5050 | `epan/dissectors/packet-sbus.c` `dissect_sbus` — can `return 0` (function starts at line 891). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `sflow` | udp 6343 | `epan/dissectors/packet-sflow.c` `dissect_sflow_245` — can `return 0` (function starts at line 2553). | `dissect_sflow_245` can `return 0`; sampled-header IP/Ethernet is skipped on reject. |
| `sigcomp` | udp 5555,6666; tcp 5555,6666 | `epan/dissectors/packet-sigcomp.c` `dissect_sigcomp` — can `return 0` (function starts at line 4768). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `sip` | udp 5060; tcp 5060 | `epan/dissectors/packet-sip.c` `dissect_sip` — can `return 0` (function starts at line 3175). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `skinny` | tcp 2000 | `epan/dissectors/packet-skinny.c` `dissect_skinny` — can `return 0` (function starts at line 8348). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `slimp3` | udp 1069,3483 | `epan/dissectors/packet-slimp3.c` `dissect_slimp3` — can `return 0` (function starts at line 234). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `snmp` | udp 161,162,8161; tcp 161,162 | `epan/dissectors/packet-snmp.c` `dissect_snmp` — can `return 0` (function starts at line 3385). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `ssyncp` | udp 60001 | `epan/dissectors/packet-ssyncp.c` `dissect_ssyncp` — can `return 0` (function starts at line 106). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `steam_ihs_discovery` | udp 27036 | `epan/dissectors/packet-steam-ihs-discovery.c` `dissect_steam_ihs_discovery` — can `return 0` (function starts at line 999). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `stun` | udp 3478; tcp 3478 | `epan/dissectors/packet-stun.c` `dissect_stun_message` — can `return 0` (function starts at line 980). | Returns 0 on short packets, bad ChannelData numbers, missing magic cookie (`dissect_stun_message`). Shared by UDP and TCP port handles. |
| `tapa` | udp 5000 | `epan/dissectors/packet-tapa.c` `dissect_tapa_static` — can `return 0` (function starts at line 454). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `tftp` | udp 69 | `epan/dissectors/packet-tftp.c` `dissect_tftp` — can `return 0` (function starts at line 902). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `tns` | tcp 1521 | `epan/dissectors/packet-tns.c` `dissect_tns` — can `return 0` (function starts at line 1277). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `tpcp` | udp 3121 | `epan/dissectors/packet-nt-tpcp.c` `dissect_tpcp` — can `return 0` (function starts at line 94). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `tplink-smarthome` | udp 9999; tcp 9999 | `epan/dissectors/packet-tplink-smarthome.c` `dissect_tplink_smarthome` — can `return 0` (function starts at line 159). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `tpncp` | udp 2424; tcp 2424 | `epan/dissectors/packet-tpncp.c` `dissect_tpncp` — can `return 0` (function starts at line 272). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `trdp` | udp 17224,17225; tcp 17225 | `epan/dissectors/packet-trdp.c` `dissect_trdp` — can `return 0` (function starts at line 127). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `uftp` | udp 1044 | `epan/dissectors/packet-uftp.c` `dissect_uftp` — can `return 0` (function starts at line 1378). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `vicp` | tcp 1861 | `epan/dissectors/packet-vicp.c` `dissect_vicp` — can `return 0` (function starts at line 36). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `wccp` | udp 2048 | `epan/dissectors/packet-wccp.c` `dissect_wccp` — can `return 0` (function starts at line 2657). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `wg` | udp 0 | `epan/dissectors/packet-wireguard.c` `dissect_wg` — can `return 0` (function starts at line 1577). | `dissect_wg` can `return 0`; live default is the enabled UDP heuristic. |
| `wow` | tcp 3724 | `epan/dissectors/packet-wow.c` `dissect_wow` — can `return 0` (function starts at line 909). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `xot` | tcp 1998 | `epan/dissectors/packet-xot.c` `dissect_xot_tcp_heur` — can `return 0` (function starts at line 314). | `dissect_xot_tcp_heur` can `return 0` before X.25 (which can carry IP). |
| `zabbix` | tcp 10050,10051 | `epan/dissectors/packet-zabbix.c` `dissect_zabbix` — can `return 0` (function starts at line 1087). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `zebra` | tcp 2600 | `epan/dissectors/packet-zebra.c` `dissect_zebra` — can `return 0` (function starts at line 2407). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |
| `zep` | udp 17754 | `epan/dissectors/packet-zep.c` `dissect_zep` — can `return 0` (function starts at line 107). | Registered dissect function can `return 0`; `dissector_try_uint` then continues. |

**101** names from `-G` `udp.port` / `tcp.port` proved may-reject.

## Unproven, treated as may-reject

Could not prove the `-G` port handle always claims (handle/filter name mismatch, or the dissect function was not extracted). Cap the study: **treat as may-reject**.

`5co_rap`, `ams`, `atmtcp`, `bittorrent`, `bjnp`, `c1222`, `c2p`, `cmp`, `cql`, `db-lsp`, `db-lsp-disc`, `dcc`, `dhcpv6.bulk_leasequery`, `diameter`, `dlep`, `dlm3`, `dlsw`, `dmp`, `dnp3`, `do-irp`, `dof`, `dpp`, `dtls`, `dtps`, `ecatf`, `ecmp`, `edonkey`, `elasticsearch`, `enttec`, `epl`, `epmd`, `exec`, `ff`, `gadu-gadu`, `git`, `gprs-ns`, `gryphon`, `gsm_ipa`, `h225`, `h501`, `hart_ip`, `hiqnet`, `http`, `ieee1722`, `infiniband`, `iperf3`, `irc`, `isakmp`, `isns`, `kerberos`, `kf`, `kip`, `knet`, `kpasswd`, `krb4`, `laplink`, `lmp`, `m3ua`, `mactelnet`, `memcache`, `mint`, `mipv6`, `mongo`, `mpeg_dsmcc`, `mrcpv2`, `msdp`, `nbdgm`, `ndps`, `nvme-tcp`, `omron`, `opcua`, `opensafety`, `opensafety_udp`, `openvpn`, `pn_rt`, `pnrp`, `rtmpt`, `sapni`, `scop`, `sir`, `smrse`, `socks`, `tivoconnect`, `tls`, `uma`, `vines_frp`, `wimaxasncp`, `wsp`, `wtp`, `z3950`.

**90** unproven port names.

Notable leftovers in that list that *do* reach IP (see `reaches-ip.md`) and must not be assumed to always claim: `infiniband`, `msdp`, `mint`.

