# Intent

## What is being built

Open-source packet analyzer. The CLI takes tshark's flags and filters. A field query reads only the bytes that field needs, so it runs near the speed of memory or disk instead of the speed of tshark's per-packet engine. The same reader indexes capture archives, exports Parquet, and drives a desktop app that replaces Wireshark.

## For whom

Network engineers and security analysts who already use Wireshark and tshark.

## Disciplines

software

## Constraints

none recorded

## Team

solo

## Values

Correctness.

## Taste

Short files.

## Process weight

Low
