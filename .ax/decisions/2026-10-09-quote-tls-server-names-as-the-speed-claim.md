---
id: 2026-10-09-quote-tls-server-names-as-the-speed-claim
kind: decision
date: 2026-10-09
---

## Context

Skipping upper protocols inside tshark saves about 22% on a light ip.src query. The per-packet engine is still most of the time. A purpose-built reader then matched tshark on ip.src and on TLS server names. A later session that keeps tuning tshark's dissector walk, or that quotes the synthetic ip.src ratio as the product claim, will aim at the wrong thing.

## Options

- Treat "skip upper protocols" as the product edge
- Treat a query-specific reader as the edge, and quote TLS server names on a real capture as the headline number

## Choice

fin's speed comes from a query-specific reader, and the headline number is TLS server-name extraction against tshark.

## Why

The TLS query is a real analyst question on a real capture, and the output matches tshark. The synthetic ip.src ratio is a ceiling check on tiny packets. It is not the number to quote.
