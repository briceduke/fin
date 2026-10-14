# Cross-frame facts (tshark 4.6.9)

Source: Wireshark / tshark **4.6.9** tag `v4.6.9` (commit `g2d548b197c75`).

These are not per-port lists. They are the two capture-wide behaviors a sequential `ip.src` reader must treat as “count the frames they could affect.”

---

## 1. Conversations and sticky decode change later frames

UDP and TCP try a **conversation dissector before ports**.

`epan/dissectors/packet-udp.c` `decode_udp_ports` — after the visited-heuristic shortcut, `try_conversation_dissector_strat(pinfo, CONVERSATION_UDP, next_tvb, …)` runs; a hit `return`s and never tries ports or heuristics.

`epan/dissectors/packet-tcp.c` `decode_tcp_ports` — `try_conversation_dissector(&pinfo->src, &pinfo->dst, CONVERSATION_TCP, src_port, dst_port, …)` is first (after keepalive skip). A hit `return true`s. TCP then prefers a Decode-As / preference-changed `tcpd->server_port` via `dissector_is_uint_changed` before low/high ports.

**Visited UDP heuristic lock.** Same `decode_udp_ports`: if `PINFO_FD_VISITED(pinfo)` and `udp_p_info->heur_dtbl_entry != NULL`, it `call_heur_dissector_direct` and returns. The first pass stored that entry when `dissector_try_heuristic` succeeded. A later frame of the same UDP layer is not re-tried against ports.

**Paths that reach IP and set this state** (so later frames on the 5-tuple can be inner IP even when the ports would say otherwise):

| setter | citation | effect |
|---|---|---|
| L2TP | `epan/dissectors/packet-l2tp.c` `dissect_l2tp_udp` — `conversation_new` + `conversation_set_dissector(conv, l2tp_udp_handle)` | Later UDP on the negotiated ports is L2TP → PPP/LLC → IP. |
| OpenFlow | `epan/dissectors/packet-openflow.c` `dissect_openflow_heur` — `conversation_set_dissector(conversation, openflow_handle)` | Later TCP segments of that connection are OpenFlow, including packet-in Ethernet. |
| RPCAP | `epan/dissectors/packet-rpcap.c` `dissect_rpcap_heur_tcp` — `conversation_set_dissector_from_frame_number(..., rpcap_tcp_handle)` | Later TCP of that conversation is RPCAP → `pcap_pktdata` → Ethernet/IP. |
| WireGuard | `epan/dissectors/packet-wireguard.c` — `conversation_set_dissector(conversation, wg_handle)` | Later UDP of that conversation is WG; decrypt path calls `ip`. |
| XOT | `epan/dissectors/packet-xot.c` — `conversation_set_dissector(conversation, xot_tcp_handle)` | Later TCP is X.25, which can carry IP (`"x.25.spi"` `NLPID_IP`). |
| Decode As / port prefs | `epan/packet.c` `dissector_is_uint_changed`; UDP/TCP try changed ports **before** the default low/high order | A sticky `udp.port`/`tcp.port` Decode As can bind VXLAN/GTP/… on a non-default port for the rest of the capture. |

**SDP/RTP** (`epan/dissectors/packet-sdp.c` calls `srtp_add_address` / `rtp_add_address` with `PT_UDP`) installs an RTP conversation. The UDP RTP heuristic is **disabled** (`rtp_udp` `F F`); the conversation still wins. RTP does **not** call the IPv4 packet dissector. Recorded so a reader does not confuse “conversation changed decode” with “that path reaches IP.”

**STUN** (`epan/dissectors/packet-stun.c`) `conversation_set_dissector` on STUN/TURN 5-tuples. TURN ChannelData is handed to `data`, not `ip`, but the sticky STUN handle can **block** a later tunnel on those ports. Count frames on a STUN-locked 5-tuple as maybe-not-the-port-table.

Any conversation or Decode-As that can reach IP (L2TP, OpenFlow, RPCAP, WG, XOT, GTP/VXLAN Decode As, …) means fin **counts** later frames on that flow: it cannot prove from this frame’s ports alone that `ip.src` is absent.

---

## 2. TCP desegmentation (on by default)

`epan/dissectors/packet-tcp.c`:

- `static bool tcp_desegment = true;`
- Preference `desegment_tcp_streams` (“Allow subdissector to reassemble TCP streams”) binds that flag.
- `dissect_tcp` sets `pinfo->can_desegment = 2` when `tcp_desegment` is true, the segment is complete enough, checksum policy allows it, and the segment is not in an error packet.
- `dissect_tcp_payload` calls `desegment_tcp(...)` when `pinfo->can_desegment` is set; otherwise it calls `process_tcp_payload` on this segment alone.
- `tcp_dissect_pdus` is the helper OpenFlow, RPCAP, XOT, MSDP, and other TCP protocols use to wait until `get_pdu_len` bytes are assembled.

A protocol carried over TCP is dissected in the **frame where reassembly completes**. Earlier segments are TCP payload (or “segment data”) without the inner dissector. Any TCP path that reaches IP (`openflow`, `rpcap`, `msdp`, `xot`, `gtp` over TCP, `cflow` over TCP, `tcpencap`) is already on `reaches-ip.md`, so `ip.src` is probably safe if those flows are counted — the inner IPv4 header is not required to sit in the first TCP segment.

`epan/packet.c` `call_dissector_work` decrements `can_desegment` for the subdissector (`saved_can_desegment - 1`) so only the dissector immediately above TCP may request reassembly.

---

## Port order (same 4.6.9)

UDP `decode_udp_ports` (`packet-udp.c`): if `uh_sport > uh_dport` then `low_port = uh_dport`, else `low_port = uh_sport`. Comment: try the lower port number first, then the higher, so both directions pick the same dissector and well-known ports win. Port 0 is skipped. Conversation and Decode-As-changed ports override that default order. Heuristics after ports unless `try_heuristic_first`.

TCP `decode_tcp_ports` (`packet-tcp.c`): same low-then-high after optional `server_port` (from SYN) and Decode-As-changed ports. Default `try_heuristic_first` is false.
