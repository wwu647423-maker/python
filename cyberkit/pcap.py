"""
pcap — read a classic PCAP capture file and decode every packet.

Implements the libpcap "savefile" format from scratch (no third-party
deps): 24-byte global header followed by per-record (16-byte header +
payload). Both byte orders (magic 0xa1b2c3d4 / 0xd4c3b2a1) and both
timestamp resolutions (us / ns) are supported.

Decoding piggy-backs on cyberkit.packetparse, so anything that module
knows about (Ethernet/IPv4/IPv6/TCP/UDP/ICMP/DNS) shows up here.
"""

from __future__ import annotations

import argparse
import struct
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Iterator, NamedTuple

from ._common import bold, cyan, dim, emit_jsonl, green, magenta, print_table, yellow
from .packetparse import auto_decode, parse_ethernet, parse_ipv4, parse_ipv6

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_NULL = 0
LINKTYPE_LINUX_SLL = 113

_MAGICS: dict[bytes, tuple[str, bool]] = {
    b"\xd4\xc3\xb2\xa1": ("<", False),
    b"\xa1\xb2\xc3\xd4": (">", False),
    b"\x4d\x3c\xb2\xa1": ("<", True),
    b"\xa1\xb2\x3c\x4d": (">", True),
}


class Header(NamedTuple):
    byteorder: str
    nano: bool
    snaplen: int
    linktype: int


class Packet(NamedTuple):
    index: int
    ts: float
    captured_len: int
    original_len: int
    raw: bytes
    decoded: dict


def _parse_global_header(blob: bytes) -> tuple[Header, int]:
    """
    Detect byte order via raw magic bytes. The PCAP magic 0xA1B2C3D4 is
    written in the file's *native* byte order, so the same logical
    constant appears on disk as either \\xa1\\xb2\\xc3\\xd4 or
    \\xd4\\xc3\\xb2\\xa1, depending on the writer. Comparing the
    literal 4 bytes is endianness-agnostic; *which* of the two we see
    tells us how to unpack the rest of the file.
    """
    if len(blob) < 24:
        raise ValueError("PCAP global header truncated")
    magic_bytes = blob[:4]
    if magic_bytes not in _MAGICS:
        raise ValueError(f"not a PCAP file (magic={magic_bytes.hex()})")
    bo, nano = _MAGICS[magic_bytes]
    fmt = bo + "HHiIII"
    _ver_major, _ver_minor, _thiszone, _sigfigs, snaplen, linktype = struct.unpack(fmt, blob[4:24])
    return Header(bo, nano, snaplen, linktype), 24


def iter_packets(blob: bytes) -> Iterator[Packet]:
    hdr, off = _parse_global_header(blob)
    ts_div = 1e9 if hdr.nano else 1e6
    pkt_hdr_fmt = hdr.byteorder + "IIII"
    pkt_hdr_size = 16
    idx = 0
    while off + pkt_hdr_size <= len(blob):
        sec, sub, incl_len, orig_len = struct.unpack(pkt_hdr_fmt,
                                                     blob[off:off + pkt_hdr_size])
        off += pkt_hdr_size
        if off + incl_len > len(blob):
            break
        raw = blob[off:off + incl_len]
        off += incl_len
        ts = sec + sub / ts_div
        decoded = _decode_by_linktype(hdr.linktype, raw)
        yield Packet(idx, ts, incl_len, orig_len, raw, decoded)
        idx += 1


def _decode_by_linktype(lt: int, raw: bytes) -> dict:
    if lt == LINKTYPE_ETHERNET:
        return {"layer": "ethernet", "ethernet": parse_ethernet(raw)}
    if lt == LINKTYPE_RAW:
        if raw and (raw[0] >> 4) == 6:
            return {"layer": "ipv6", "ipv6": parse_ipv6(raw)}
        return {"layer": "ipv4", "ipv4": parse_ipv4(raw)}
    if lt == LINKTYPE_NULL and len(raw) >= 4:
        return auto_decode(raw[4:])
    if lt == LINKTYPE_LINUX_SLL and len(raw) >= 16:
        return auto_decode(raw[16:])
    return auto_decode(raw)


def _classify(decoded: dict) -> tuple[str, str, str]:
    """Return (l3, l4, info) summary tuple."""
    if "ethernet" in decoded:
        eth = decoded["ethernet"]
        if "ipv4" in eth:
            ip = eth["ipv4"]
            return _ip_summary(ip, version=4)
        if "ipv6" in eth:
            ip = eth["ipv6"]
            return _ip_summary(ip, version=6)
        if "arp" in eth:
            arp = eth["arp"]
            return ("ARP", "",
                    f"{arp.get('sender_ip')} → {arp.get('target_ip')} op={arp.get('op')}")
        return (eth.get("ethertype_name", "?"), "", "")
    if decoded.get("layer") == "ipv4":
        return _ip_summary(decoded["ipv4"], version=4)
    if decoded.get("layer") == "ipv6":
        return _ip_summary(decoded["ipv6"], version=6)
    return ("?", "", "")


def _ip_summary(ip: dict, version: int) -> tuple[str, str, str]:
    src = ip.get("src", "")
    dst = ip.get("dst", "")
    l4 = ""
    info = f"{src} → {dst}"
    if "tcp" in ip:
        tcp = ip["tcp"]
        l4 = "TCP"
        flags = ",".join(tcp.get("flags", []))
        info = f"{src}:{tcp.get('src_port')} → {dst}:{tcp.get('dst_port')} [{flags}]"
    elif "udp" in ip:
        udp = ip["udp"]
        l4 = "UDP"
        info = f"{src}:{udp.get('src_port')} → {dst}:{udp.get('dst_port')} len={udp.get('length')}"
        if "dns" in udp:
            rcode = udp["dns"]["rcode"]
            info += f"  DNS rcode={rcode} records={len(udp['dns']['records'])}"
    elif "icmp" in ip or "icmpv6" in ip:
        l4 = "ICMP" if version == 4 else "ICMPv6"
    else:
        l4 = ip.get("protocol_name") or ip.get("next_header_name") or "?"
    return (f"IPv{version}", l4, info)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="cyberkit pcap",
                                 description="Read a libpcap file and decode every packet.")
    ap.add_argument("file", help="path to .pcap")
    ap.add_argument("-n", "--limit", type=int, default=0,
                    help="show only the first N packets (0 = all)")
    ap.add_argument("--proto", default="",
                    help="filter by protocol (TCP/UDP/ICMP/ARP/...)")
    ap.add_argument("--port", type=int, default=0,
                    help="filter by TCP/UDP src or dst port")
    ap.add_argument("--summary", action="store_true",
                    help="print only the protocol histogram + top talkers, no per-packet table")
    ap.add_argument("--json", action="store_true",
                    help="emit one JSON record per packet")
    args = ap.parse_args(argv)

    try:
        with open(args.file, "rb") as fh:
            blob = fh.read()
    except OSError as e:
        print(f"pcap: {e}", file=sys.stderr); return 2

    try:
        packets = list(iter_packets(blob))
    except (ValueError, struct.error) as e:
        print(f"pcap: {e}", file=sys.stderr); return 2

    proto_filter = args.proto.upper()
    port_filter = args.port

    def _keep(p: Packet) -> bool:
        l3, l4, _ = _classify(p.decoded)
        if proto_filter and proto_filter not in (l3.upper(), l4.upper()):
            return False
        if port_filter:
            d = p.decoded
            ip = (d.get("ethernet", {}) or d).get("ipv4") or (d.get("ethernet", {}) or d).get("ipv6") or {}
            tcp = ip.get("tcp") if isinstance(ip, dict) else None
            udp = ip.get("udp") if isinstance(ip, dict) else None
            ports = []
            if tcp: ports += [tcp["src_port"], tcp["dst_port"]]
            if udp: ports += [udp["src_port"], udp["dst_port"]]
            if port_filter not in ports:
                return False
        return True

    filtered = [p for p in packets if _keep(p)]
    if args.limit:
        filtered = filtered[: args.limit]

    if args.json:
        emit_jsonl([{
            "index": p.index, "ts": p.ts,
            "captured_len": p.captured_len, "original_len": p.original_len,
            "decoded": p.decoded,
        } for p in filtered])
        return 0

    proto_counts: Counter = Counter()
    talker_counts: Counter = Counter()
    for p in packets:
        l3, l4, info = _classify(p.decoded)
        key = f"{l3}/{l4}".rstrip("/")
        proto_counts[key] += 1
        if " → " in info:
            talker_counts[info.split(" [")[0]] += 1

    print(f"{bold('file')}        {args.file}")
    print(f"{bold('packets')}     {len(packets)} total"
          + (f", {len(filtered)} after filter" if proto_filter or port_filter else ""))
    print(dim("-" * 64))
    print(bold("protocol histogram:"))
    rows = [[cyan(k), str(v)] for k, v in proto_counts.most_common(10)]
    print_table(["PROTO", "COUNT"], rows)
    print()
    print(bold("top talkers (top 8):"))
    rows = [[magenta(k), str(v)] for k, v in talker_counts.most_common(8)]
    print_table(["FLOW", "COUNT"], rows)

    if args.summary:
        return 0

    print()
    print(bold(f"packets ({len(filtered)}):"))
    rows = []
    first_ts = filtered[0].ts if filtered else 0
    for p in filtered[:200]:
        l3, l4, info = _classify(p.decoded)
        rows.append([
            str(p.index),
            f"+{p.ts - first_ts:.4f}s" if first_ts else f"{p.ts:.4f}",
            f"{p.captured_len}",
            cyan(l3),
            green(l4),
            info[:80],
        ])
    print_table(["#", "TIME", "LEN", "L3", "L4", "INFO"], rows)
    if len(filtered) > 200:
        print(yellow(f"... {len(filtered) - 200} more packets (use --limit / --json)"))
    return 0
