"""
packetparse — decode a raw packet given as hex.

Useful when you've copy-pasted bytes out of Wireshark/tcpdump and want a
quick L2..L7 breakdown without firing up a heavy tool. Decodes:

    Ethernet II → IPv4 / IPv6 → TCP / UDP / ICMP → (DNS for UDP/53)

Input forms accepted:
    raw spaced hex   '45 00 00 3c ...'
    contiguous hex   '4500003c...'
    tcpdump-style    '0x0000:  4500 003c ...'

The parser is defensive: every layer reports what it managed to decode
plus its raw bytes, even if higher layers fail.
"""

from __future__ import annotations

import argparse
import re
import socket
import struct
import sys
from typing import Any

from ._common import bold, cyan, dim, emit_json, green, magenta, red, yellow
from ._dns import parse_response as _dns_parse, DnsError

ETHERTYPES = {0x0800: "IPv4", 0x86DD: "IPv6", 0x0806: "ARP",
              0x8100: "802.1Q", 0x88CC: "LLDP"}
IPPROTO = {1: "ICMP", 6: "TCP", 17: "UDP", 50: "ESP", 51: "AH", 58: "ICMPv6"}
TCP_FLAGS = [("FIN", 0x01), ("SYN", 0x02), ("RST", 0x04), ("PSH", 0x08),
             ("ACK", 0x10), ("URG", 0x20), ("ECE", 0x40), ("CWR", 0x80)]


_TCPDUMP_PREFIX = re.compile(r"(?mi)^\s*0x[0-9a-f]+:\s*")
_ASCII_TAIL = re.compile(r"\s{2,}[\x20-\x7e]*$", re.M)


def _normalize_hex(text: str) -> bytes:
    """Accept raw hex, contiguous hex, or tcpdump-style hex dumps."""
    text = _TCPDUMP_PREFIX.sub("", text)
    text = _ASCII_TAIL.sub("", text)
    cleaned = "".join(c for c in text if c in "0123456789abcdefABCDEF")
    if len(cleaned) % 2 != 0:
        raise ValueError(f"odd number of hex nibbles ({len(cleaned)})")
    return bytes.fromhex(cleaned)


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def parse_ethernet(data: bytes) -> dict[str, Any]:
    if len(data) < 14:
        return {"_error": "shorter than 14-byte ethernet header"}
    dst, src, ethertype = struct.unpack(">6s6sH", data[:14])
    out: dict[str, Any] = {
        "dst": _mac(dst),
        "src": _mac(src),
        "ethertype": f"0x{ethertype:04x}",
        "ethertype_name": ETHERTYPES.get(ethertype, "?"),
        "payload_len": len(data) - 14,
    }
    payload = data[14:]
    if ethertype == 0x0800:
        out["ipv4"] = parse_ipv4(payload)
    elif ethertype == 0x86DD:
        out["ipv6"] = parse_ipv6(payload)
    elif ethertype == 0x0806:
        out["arp"] = parse_arp(payload)
    else:
        out["raw_payload"] = payload.hex()
    return out


def parse_ipv4(data: bytes) -> dict[str, Any]:
    if len(data) < 20:
        return {"_error": "shorter than 20-byte IPv4 header"}
    vihl = data[0]
    version = vihl >> 4
    ihl = (vihl & 0x0F) * 4
    if version != 4 or ihl < 20:
        return {"_error": f"not IPv4 (version={version}, ihl={ihl})"}
    tos = data[1]
    total_len, ident, flags_frag, ttl, proto, _csum = struct.unpack(
        ">HHHBBH", data[2:12])
    src = socket.inet_ntop(socket.AF_INET, data[12:16])
    dst = socket.inet_ntop(socket.AF_INET, data[16:20])
    flags = (flags_frag >> 13) & 0x7
    frag_off = flags_frag & 0x1FFF
    out: dict[str, Any] = {
        "version": 4, "ihl": ihl, "tos": tos, "total_length": total_len,
        "id": ident, "flags": {"DF": bool(flags & 0x2), "MF": bool(flags & 0x1)},
        "fragment_offset": frag_off, "ttl": ttl,
        "protocol": proto, "protocol_name": IPPROTO.get(proto, "?"),
        "src": src, "dst": dst,
    }
    payload = data[ihl:total_len] if total_len and total_len <= len(data) else data[ihl:]
    if proto == 6: out["tcp"] = parse_tcp(payload)
    elif proto == 17: out["udp"] = parse_udp(payload)
    elif proto == 1: out["icmp"] = parse_icmp(payload)
    else: out["raw_payload"] = payload.hex()
    return out


def parse_ipv6(data: bytes) -> dict[str, Any]:
    if len(data) < 40:
        return {"_error": "shorter than 40-byte IPv6 header"}
    vtcfl, plen, nxt, hlim = struct.unpack(">IHBB", data[:8])
    version = vtcfl >> 28
    if version != 6:
        return {"_error": f"not IPv6 (version={version})"}
    src = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, data[24:40])
    out: dict[str, Any] = {
        "version": 6, "payload_length": plen, "next_header": nxt,
        "next_header_name": IPPROTO.get(nxt, "?"), "hop_limit": hlim,
        "src": src, "dst": dst,
    }
    payload = data[40:40 + plen] if plen and 40 + plen <= len(data) else data[40:]
    if nxt == 6: out["tcp"] = parse_tcp(payload)
    elif nxt == 17: out["udp"] = parse_udp(payload)
    elif nxt == 58: out["icmpv6"] = parse_icmp(payload)
    else: out["raw_payload"] = payload.hex()
    return out


def parse_tcp(data: bytes) -> dict[str, Any]:
    if len(data) < 20:
        return {"_error": "shorter than 20-byte TCP header"}
    src, dst, seq, ack, off_flags, window = struct.unpack(">HHIIHH", data[:16])
    data_offset = (off_flags >> 12) * 4
    flag_bits = off_flags & 0xFF
    set_flags = [name for name, mask in TCP_FLAGS if flag_bits & mask]
    payload = data[data_offset:]
    return {
        "src_port": src, "dst_port": dst,
        "seq": seq, "ack": ack,
        "data_offset": data_offset, "flags": set_flags,
        "window": window, "payload_len": len(payload),
        "payload_preview": payload[:32].decode("latin-1", errors="replace"),
    }


def parse_udp(data: bytes) -> dict[str, Any]:
    if len(data) < 8:
        return {"_error": "shorter than 8-byte UDP header"}
    src, dst, length, _csum = struct.unpack(">HHHH", data[:8])
    payload = data[8:length] if length and length <= len(data) else data[8:]
    out: dict[str, Any] = {
        "src_port": src, "dst_port": dst, "length": length,
        "payload_len": len(payload),
    }
    if src == 53 or dst == 53:
        try:
            rcode, recs = _dns_parse(payload)
            out["dns"] = {"rcode": rcode,
                          "records": [r._asdict() for r in recs]}
        except DnsError as e:
            out["dns_error"] = str(e)
    return out


def parse_icmp(data: bytes) -> dict[str, Any]:
    if len(data) < 4:
        return {"_error": "shorter than 4-byte ICMP header"}
    type_, code, _csum = struct.unpack(">BBH", data[:4])
    return {"type": type_, "code": code, "rest_len": len(data) - 4}


def parse_arp(data: bytes) -> dict[str, Any]:
    if len(data) < 28:
        return {"_error": "shorter than 28-byte ARP header"}
    htype, ptype, hlen, plen, op = struct.unpack(">HHBBH", data[:8])
    if hlen != 6 or plen != 4:
        return {"_error": f"unexpected ARP sizes hlen={hlen} plen={plen}"}
    sender_mac = _mac(data[8:14])
    sender_ip = socket.inet_ntop(socket.AF_INET, data[14:18])
    target_mac = _mac(data[18:24])
    target_ip = socket.inet_ntop(socket.AF_INET, data[24:28])
    return {"htype": htype, "ptype": f"0x{ptype:04x}", "op": op,
            "sender_mac": sender_mac, "sender_ip": sender_ip,
            "target_mac": target_mac, "target_ip": target_ip}


def auto_decode(data: bytes) -> dict[str, Any]:
    """Detect the outermost layer heuristically and parse downward."""
    if len(data) >= 14:
        ethertype = (data[12] << 8) | data[13]
        if ethertype in ETHERTYPES:
            return {"layer": "ethernet", "ethernet": parse_ethernet(data)}
    if data and (data[0] >> 4) == 4:
        return {"layer": "ipv4", "ipv4": parse_ipv4(data)}
    if data and (data[0] >> 4) == 6:
        return {"layer": "ipv6", "ipv6": parse_ipv6(data)}
    return {"layer": "unknown", "raw": data.hex()}


def _print_dict(d: dict[str, Any], indent: int = 0) -> None:
    pad = "  " * indent
    for k, v in d.items():
        key = magenta(k) if not k.startswith("_") else red(k)
        if isinstance(v, dict):
            print(f"{pad}{key}:")
            _print_dict(v, indent + 1)
        elif isinstance(v, list) and v and isinstance(v[0], dict):
            print(f"{pad}{key}:")
            for i, item in enumerate(v):
                print(f"{pad}  [{i}]:")
                _print_dict(item, indent + 2)
        else:
            print(f"{pad}{key}: {cyan(str(v))}")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="cyberkit packetparse",
                                 description="Decode a packet given as hex (Ethernet/IP/TCP/UDP/ICMP/DNS).")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--hex", help="literal hex string")
    src.add_argument("--file", help="read hex from a file (- for stdin)")
    ap.add_argument("--layer", choices=("auto", "ethernet", "ipv4", "ipv6"),
                    default="auto")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.hex is not None:
        text = args.hex
    elif args.file == "-":
        text = sys.stdin.read()
    else:
        try:
            with open(args.file, "r", encoding="utf-8") as fh:
                text = fh.read()
        except OSError as e:
            print(f"packetparse: {e}", file=sys.stderr); return 2

    try:
        data = _normalize_hex(text)
    except ValueError as e:
        print(f"packetparse: {e}", file=sys.stderr); return 2

    if args.layer == "auto":
        decoded = auto_decode(data)
    elif args.layer == "ethernet":
        decoded = {"layer": "ethernet", "ethernet": parse_ethernet(data)}
    elif args.layer == "ipv4":
        decoded = {"layer": "ipv4", "ipv4": parse_ipv4(data)}
    elif args.layer == "ipv6":
        decoded = {"layer": "ipv6", "ipv6": parse_ipv6(data)}
    else:
        decoded = auto_decode(data)

    if args.json:
        emit_json({"bytes": len(data), **decoded})
        return 0

    print(f"{bold('input')}  {len(data)} bytes  ({args.layer})")
    print(dim("-" * 64))
    _print_dict(decoded)
    return 0
