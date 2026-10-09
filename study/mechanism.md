# tshark field output still walks the whole packet

Preliminary experiment, 9 Oct 2026. This checks tshark's behavior. It is not a fin benchmark.

**Verdict: confirmed.** On Wireshark/tshark 4.6.9 (`C:\Program Files\Wireshark\tshark.exe`, `v4.6.9-0-g2d548b197c75`), `-T fields -e ip.src` still dissects past IPv4. A one-packet Ethernet+IPv4+UDP/53 capture reports `frame.protocols` as `eth:ethertype:ip:udp:dns`, and the DNS dissector still parses a pointer-loop name. Priming (`output_fields_prime_edt` / `epan_dissect_prime_with_dfilter`) marks requested hfids so they are not faked in the proto tree; it does not stop `dissect_record` from calling the frame dissector and walking next protocols. `--only-protocols` is a manual kill switch (`proto_disable_all` then enable the listed names). tshark does not infer that list from `-e`. `--only-protocols eth,ip` still prints `ip.src` on a plain Ethernet+IPv4 packet, but hides it on a VLAN-tagged copy because the `vlan` dissector is gone.

Source of truth for the call path is tag [v4.6.9](https://github.com/wireshark/wireshark/tree/v4.6.9). The one-packet probes used for the commands below were not kept. All commands use `-n`.

## Call path

Field output is not a header-only reader. `-T fields` sets `print_details = true` so a proto tree is built, then immediately marks that tree **not visible** when any `-e` fields are present, so unrequested items can be faked:

- `tshark.c`: `-T fields` needs a tree; `visible` is false whenever `output_fields_num_fields() != 0`. Comment in `process_packet_single_pass` / the two-pass readers: if `-e` was given, prime those fields later.

Per packet, `process_packet_single_pass` (one-pass file read; `process_packet_second_pass` is the same priming sequence) does:

1. `epan_dissect_prime_with_dfilter(edt, cf->dfcode)` if there is a display/read filter (`-Y` / `-R`).
2. `output_fields_prime_edt(edt, output_fields)` for every `-e`.
3. `epan_dissect_run_with_taps(...)`.

`output_fields_prime_edt` in `epan/print.c` looks up each `-e` name and calls `proto_tree_prime_with_hfid_print`. That sets `hfinfo->ref_type = HF_REF_TYPE_PRINT` and marks the parent protocol `HF_REF_TYPE_INDIRECT` (`epan/proto.c`). Complex `-e` expressions that are not a registered field name are compiled as dfilters and primed with `epan_dissect_prime_with_dfilter`.

`epan_dissect_prime_with_dfilter` in `epan/epan.c` is a thin wrapper around `dfilter_prime_proto_tree` in `epan/dfilter/dfilter.c`, which loops `df->interesting_fields` and calls `proto_tree_prime_with_hfid`. Same idea: force fields into the tree. No early-out of dissection.

`epan_dissect_run` / `epan_dissect_run_with_taps` always call `dissect_record` (`epan/packet.c`). `dissect_record` always `call_dissector_with_data(frame_handle, ...)`. There is no branch that means "only IP." Ethernet then ethertype then IP then UDP then DNS (or whatever the next dissector handle says).

What priming *does* change is tree materialization. `TRY_TO_FAKE_THIS_ITEM` in `epan/proto.c` skips allocating a real `field_info` when the tree is not visible and the hfid is not `HF_REF_TYPE_DIRECT` / `HF_REF_TYPE_PRINT`. Dissector functions still run; they still hand the remainder of the tvbuff to the next protocol.

`--only-protocols` is the actual stop. `tshark.c` hands it to `dissect_opts_handle_opt` in `ui/dissect_opts.c`, which calls `proto_disable_all()` and appends the comma-separated names to the enable list. That is independent of `-e`. `--disable-protocol udp` is the same machinery, one name at a time.

## Behavioral evidence

Binary: `C:\Program Files\Wireshark\tshark.exe`. Filter names from `tshark -G protocols` (third column): `eth`, `ethertype`, `ip`, `udp`, `dns`, `vlan`, `frame`. 802.1Q is `vlan`, not `ieee8021q`.

Captures (one packet each), IPv4 src `10.0.0.1` at byte 12 of a 20-byte IP header:

| Probe | Frame | Link |
| --- | --- | --- |
| plain Ethernet + IPv4 + UDP | 60 bytes | Ethernet type `0x0800` |
| Ethernet + VLAN + IPv4 + UDP | 64 bytes | Ethernet type `0x8100`, VLAN 1, inner type `0x0800` |

UDP dest 53, DNS query with a compression pointer that loops. IPv4 src is therefore at frame offset 26 on the plain packet and 30 on the VLAN packet.

### 1. `-e ip.src` still walks UDP and DNS

```
& "C:\Program Files\Wireshark\tshark.exe" -n -r study\mechanism-pcaps\eth-ipv4-udp.pcap -T fields -e ip.src
```

```
10.0.0.1
```

```
& "C:\Program Files\Wireshark\tshark.exe" -n -r study\mechanism-pcaps\eth-ipv4-udp.pcap -T fields -e ip.src -e frame.protocols
```

```
10.0.0.1	eth:ethertype:ip:udp:dns
```

```
& "C:\Program Files\Wireshark\tshark.exe" -n -r study\mechanism-pcaps\eth-vlan-ipv4-udp.pcap -T fields -e ip.src -e frame.protocols
```

```
10.0.0.1	eth:ethertype:vlan:ethertype:ip:udp:dns
```

```
& "C:\Program Files\Wireshark\tshark.exe" -n -r study\mechanism-pcaps\eth-ipv4-udp.pcap -T fields -e frame.protocols
```

```
eth:ethertype:ip:udp:dns
```

**Caveat.** `-e ip.src` alone cannot print `frame.protocols` because that hfid is not primed. Adding `-e frame.protocols` primes the protocols-in-frame string; it does not change `ip.src` (`10.0.0.1` either way) and does not add extra dissectors. `pinfo->layers` is filled as `call_dissector` runs, independent of that field. So requesting `frame.protocols` is how we *observe* the walk, not how we cause it. `-V` on the same file also shows `[Protocols in frame: eth:ethertype:ip:udp:dns]`; that path uses a visible tree (`-V` has no `-e` list), which is a different tree-filling mode, not a different dissector sequence.

### 2. Kill switches vs stock `-e ip.src`

Same `-T fields -e ip.src -e frame.protocols`, plain packet:

| Extra args | stdout |
| --- | --- |
| (none) | `10.0.0.1	eth:ethertype:ip:udp:dns` |
| `--disable-protocol udp` | `10.0.0.1	eth:ethertype:ip:data` |
| `--disable-protocol dns` | `10.0.0.1	eth:ethertype:ip:udp:data` |
| `--only-protocols eth,ip` | `10.0.0.1	eth:ethertype:ip:data` |

`ip.src` is unchanged. UDP/DNS drop off only when those dissectors are disabled. `--only-protocols eth,ip` is enough on this packet because Ethernet's type `0x0800` still reaches IPv4; `ethertype` does not have to be listed (it is not a separately enabled protocol in the same way; `-G` marks it `F` in the last column). Adding `frame` or `ethertype` to the list does not change the result.

VLAN packet:

| Extra args | stdout |
| --- | --- |
| (none) | `10.0.0.1	eth:ethertype:vlan:ethertype:ip:udp:dns` |
| `--only-protocols eth,ip` | `\teth:ethertype:data` (`ip.src` empty) |
| `--only-protocols eth,vlan,ip` | `10.0.0.1	eth:ethertype:vlan:ethertype:ip:data` |
| `--disable-protocol vlan` | `\teth:ethertype:data` |
| `--disable-protocol udp` | `10.0.0.1	eth:ethertype:vlan:ethertype:ip:data` |

`--only-protocols eth,ip` hides `ip.src` on the VLAN frame: without `vlan`, the tag is `data` and IP never runs. The vlan-safe set is `eth,vlan,ip`. That list is something the operator types; tshark does not build it from `-e ip.src`.

Without `-e frame.protocols` the `ip.src` column matches the table: still `10.0.0.1` for stock / `--disable-protocol udp` / `--only-protocols eth,ip` on the plain packet, empty for `--only-protocols eth,ip` on the VLAN packet, `10.0.0.1` for `--only-protocols eth,vlan,ip`.

### 3. Upper dissector really ran (DNS pointer loop)

Stderr for `-e ip.src` is empty, including `--log-level warning`. DNS does not print expert text to the console. The complaint is in the DNS tree:

```
& "C:\Program Files\Wireshark\tshark.exe" -n -r study\mechanism-pcaps\eth-ipv4-udp.pcap -T fields -e ip.src -e dns.qry.name
```

```
10.0.0.1	<Name contains a pointer that loops>
```

`-e _ws.expert.message` on the same packet is blank: this payload is a generated DNS name string, not a `_ws.expert` record. `-V` shows the same name under `Domain Name System (query)`. `--disable-protocol dns` turns `frame.protocols` into `eth:ethertype:ip:udp:data`, which is the control that the DNS layer was not just a label.

`--log-level info` logs `[DFilter INFO] -- Compiled display filter: ip.src` during field validation (`output_fields_valid` compiles each `-e` as a dfilter to check it). That is not an upper-protocol warning, and it is not the per-packet walk.

## What this means for a shallow header walk

IPv4 source is fixed at offset 12 of a 20-byte IPv4 header (`ip.hdr_len` is 20 on both captures). It is **not** fixed in the frame. VLAN (here +4 bytes), and the same class of shims (MPLS, Linux SLL, extra Ethernet tags), sit in front and move the IP header. A walker that wants `ip.src` has to parse those shims, then the IP header, and can stop. tshark does not do that: after IP it still runs UDP and whatever port 53 binds.

`--only-protocols` can fake a shallow walk for this query (`eth,ip` or `eth,vlan,ip`), but the operator must name every shim. Missing `vlan` drops `ip.src`. That is the opposite of inferring a stop from `-e`.

Queries that cannot stop after the IP header even in a purpose-built walker: IP reassembly, heuristic subdissectors, decrypted TLS fields, anything reconstructed across packets. Those need the upper dissectors (and often two passes). `ip.src` on a complete IPv4 header is not one of those queries.

For this repo: treating tshark `-T fields -e ip.src` as a cost model for "read four bytes at a known offset" is wrong. tshark's field path is "dissect the frame, fake uninteresting tree nodes, keep the primed ones."
