---
id: 2026-10-13-claim-a-udp-or-tcp-payload-only-when
kind: decision
date: 2026-10-13
---

## Context
tshark may still run heuristics or an inner IP dissector after UDP/TCP ports. Fin cannot model every accept path. The walk claims only what the snapshotted port table plus the always-claim and reaches-IP lists can prove.

## Options
- Count every UDP and TCP payload
- Prove a payload when the winning port dissector always claims and does not reach IP, walk VXLAN, and count the rest

## Choice
A non-empty UDP or TCP payload is proved when the winning port dissector always claims and does not reach IP, except VXLAN which is walked; otherwise the frame is counted.

## Why
Lower port then higher port, from the 4.6.9 dump. No dissector means heuristics, so count. A may-reject or IP-reaching dissector that fin does not walk is a count. Empty payloads need no claim. HTTP and TLS stay counted until those steps model them.
