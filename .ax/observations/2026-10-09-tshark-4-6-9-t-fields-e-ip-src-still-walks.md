---
id: 2026-10-09-tshark-4-6-9-t-fields-e-ip-src-still-walks
kind: observation
date: 2026-10-09
method: v4.6.9 source (output_fields_prime_edt, dissect_record, proto_tree_prime_with_hfid_print) plus two 1-packet pcaps under study/mechanism-pcaps
---

tshark 4.6.9 -T fields -e ip.src still walks UDP/DNS; priming does not early-out; --only-protocols is a manual kill switch and drops ip.src on VLAN unless vlan is listed
