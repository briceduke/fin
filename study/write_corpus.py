"""Emit classic little-endian Ethernet pcaps for the tshark baseline corpus."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

MAGIC = 0xA1B2C3D4
SNAPLEN = 65535
LINKTYPE_ETHERNET = 1
GLOBAL_HDR = struct.pack("<IHHIIII", MAGIC, 2, 4, 0, 0, SNAPLEN, LINKTYPE_ETHERNET)
PKT_HDR = struct.Struct("<IIII")

ETH_DST = bytes.fromhex("ffffffffffff")
ETH_SRC = bytes.fromhex("020000000001")
IP_DST = bytes((10, 255, 255, 1))
UDP_PAYLOAD = b"fin-corpus-pkt\x00\x00"
assert len(UDP_PAYLOAD) == 16

IP_TOTAL_LEN = 20 + 8 + 16
UDP_LEN = 8 + 16
PLAIN_IP_SRC_OFF = 14 + 12
QINQ_IP_SRC_OFF = 22 + 12


def src_ip(index: int) -> bytes:
    n = index & 0x00FFFFFF
    return bytes((10, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF))


def ipv4_udp(src: bytes) -> bytes:
    ip = bytearray(20)
    ip[0] = 0x45
    ip[2:4] = IP_TOTAL_LEN.to_bytes(2, "big")
    ip[8] = 64
    ip[9] = 17
    ip[12:16] = src
    ip[16:20] = IP_DST
    udp = bytearray(8)
    udp[0:2] = (12345).to_bytes(2, "big")
    udp[2:4] = (9).to_bytes(2, "big")
    udp[4:6] = UDP_LEN.to_bytes(2, "big")
    return bytes(ip) + bytes(udp) + UDP_PAYLOAD


def eth_ipv4_udp(src: bytes) -> bytes:
    return ETH_DST + ETH_SRC + (0x0800).to_bytes(2, "big") + ipv4_udp(src)


def qinq_ipv4_udp(src: bytes) -> bytes:
    return (
        ETH_DST
        + ETH_SRC
        + (0x88A8).to_bytes(2, "big")
        + (0x000A).to_bytes(2, "big")
        + (0x8100).to_bytes(2, "big")
        + (0x0014).to_bytes(2, "big")
        + (0x0800).to_bytes(2, "big")
        + ipv4_udp(src)
    )


def arp_request(src: bytes) -> bytes:
    body = (
        (1).to_bytes(2, "big")
        + (0x0800).to_bytes(2, "big")
        + bytes((6, 4))
        + (1).to_bytes(2, "big")
        + ETH_SRC
        + src
        + bytes(6)
        + IP_DST
    )
    return ETH_DST + ETH_SRC + (0x0806).to_bytes(2, "big") + body


def write_uniform(path: Path, frame: bytearray, ip_off: int, count: int) -> None:
    rec_len = 16 + len(frame)
    rec = bytearray(rec_len)
    rec[16:] = frame
    ip_abs = 16 + ip_off
    batch_n = 4096
    batch = bytearray(rec_len * batch_n)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb", buffering=8 * 1024 * 1024) as out:
        out.write(GLOBAL_HDR)
        written = 0
        while written < count:
            n = min(batch_n, count - written)
            for i in range(n):
                idx = written + i
                PKT_HDR.pack_into(rec, 0, idx // 1_000_000, idx % 1_000_000, len(frame), len(frame))
                rec[ip_abs : ip_abs + 4] = src_ip(idx)
                start = i * rec_len
                batch[start : start + rec_len] = rec
            out.write(batch[: n * rec_len])
            written += n


def write_mixed(path: Path, count: int) -> None:
    arp = arp_request(src_ip(0))
    udp = eth_ipv4_udp(src_ip(0))
    arp_rec = bytearray(16 + len(arp))
    udp_rec = bytearray(16 + len(udp))
    arp_rec[16:] = arp
    udp_rec[16:] = udp
    arp_spa = 16 + 14 + 14
    ip_abs = 16 + PLAIN_IP_SRC_OFF
    pair = bytearray(len(arp_rec) + len(udp_rec))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb", buffering=8 * 1024 * 1024) as out:
        out.write(GLOBAL_HDR)
        idx = 0
        while idx + 1 < count:
            ts_sec, ts_usec = divmod(idx, 1_000_000)
            PKT_HDR.pack_into(arp_rec, 0, ts_sec, ts_usec, len(arp), len(arp))
            arp_rec[arp_spa : arp_spa + 4] = src_ip(idx)
            ts_sec, ts_usec = divmod(idx + 1, 1_000_000)
            PKT_HDR.pack_into(udp_rec, 0, ts_sec, ts_usec, len(udp), len(udp))
            udp_rec[ip_abs : ip_abs + 4] = src_ip(idx + 1)
            pair[: len(arp_rec)] = arp_rec
            pair[len(arp_rec) :] = udp_rec
            out.write(pair)
            idx += 2
        if idx < count:
            ts_sec, ts_usec = divmod(idx, 1_000_000)
            PKT_HDR.pack_into(arp_rec, 0, ts_sec, ts_usec, len(arp), len(arp))
            arp_rec[arp_spa : arp_spa + 4] = src_ip(idx)
            out.write(arp_rec)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parent / "corpus")
    args = parser.parse_args()
    out = args.out
    out.mkdir(parents=True, exist_ok=True)

    plain = bytearray(eth_ipv4_udp(src_ip(0)))
    qinq = bytearray(qinq_ipv4_udp(src_ip(0)))
    jobs = (
        ("eth-ipv4-udp.pcap", 1_000_000, "plain"),
        ("eth-ipv4-udp-100.pcap", 100, "plain"),
        ("eth-qinq-ipv4-udp.pcap", 1_000_000, "qinq"),
        ("eth-qinq-ipv4-udp-100.pcap", 100, "qinq"),
        ("mixed.pcap", 1_000_000, "mixed"),
        ("mixed-100.pcap", 100, "mixed"),
    )
    for name, count, kind in jobs:
        path = out / name
        print(f"writing {path} ({count} packets, {kind})", flush=True)
        if kind == "plain":
            write_uniform(path, plain, PLAIN_IP_SRC_OFF, count)
        elif kind == "qinq":
            write_uniform(path, qinq, QINQ_IP_SRC_OFF, count)
        else:
            write_mixed(path, count)
        print(f"  {path.stat().st_size} bytes", flush=True)


if __name__ == "__main__":
    main()
