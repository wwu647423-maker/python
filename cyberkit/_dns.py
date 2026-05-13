"""
Pure-stdlib DNS resolver (RFC 1035) over UDP, with TCP support for AXFR.

Implements only what we need for recon: A, AAAA, NS, CNAME, SOA, PTR, MX,
TXT, AXFR. Handles name compression (0xC0 pointers), multi-string TXT
records, and bounded recursion for malformed responses.

Stdlib's `socket.getaddrinfo` already does A/AAAA, but no other record
type — hence this module.
"""

from __future__ import annotations

import random
import socket
import struct
from typing import NamedTuple

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_PTR = 12
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_AXFR = 252
TYPE_ANY = 255

CLASS_IN = 1

TYPE_NAMES: dict[int, str] = {
    TYPE_A: "A", TYPE_NS: "NS", TYPE_CNAME: "CNAME", TYPE_SOA: "SOA",
    TYPE_PTR: "PTR", TYPE_MX: "MX", TYPE_TXT: "TXT", TYPE_AAAA: "AAAA",
}
TYPE_BY_NAME: dict[str, int] = {v: k for k, v in TYPE_NAMES.items()}

RCODE_NAMES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL",
    3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
}


class Record(NamedTuple):
    name: str
    rtype: str
    ttl: int
    data: str


class DnsError(Exception):
    pass


def _encode_name(name: str) -> bytes:
    out = bytearray()
    name = name.strip(".")
    if not name:
        return bytes([0])
    for label in name.split("."):
        b = label.encode("idna", errors="strict") if any(ord(c) > 127 for c in label) else label.encode("ascii")
        if not 1 <= len(b) <= 63:
            raise ValueError(f"bad label: {label!r}")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)


def _decode_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    """Decode a possibly-compressed name. Returns (name, new_offset)."""
    if depth > 32:
        raise DnsError("name compression too deep / loop")
    labels: list[str] = []
    jumped = False
    next_offset = offset
    while True:
        if offset >= len(data):
            raise DnsError("name parse out-of-bounds")
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                next_offset = offset
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                raise DnsError("truncated compression pointer")
            ptr = struct.unpack_from(">H", data, offset)[0] & 0x3FFF
            if not jumped:
                next_offset = offset + 2
                jumped = True
            offset = ptr
            depth += 1
            if depth > 32:
                raise DnsError("name compression loop")
            continue
        if (length & 0xC0) != 0:
            raise DnsError(f"unknown label type 0x{length:02x}")
        offset += 1
        if offset + length > len(data):
            raise DnsError("label extends past packet")
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels), next_offset


def build_query(name: str, qtype: int, qid: int | None = None) -> bytes:
    if qid is None:
        qid = random.randint(0, 0xFFFF)
    flags = 0x0100
    header = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 0)
    question = _encode_name(name) + struct.pack(">HH", qtype, CLASS_IN)
    return header + question


def _decode_rdata(rtype: int, rdata: bytes, full: bytes, rdata_off: int) -> str:
    if rtype == TYPE_A:
        if len(rdata) != 4:
            return rdata.hex()
        return socket.inet_ntop(socket.AF_INET, rdata)
    if rtype == TYPE_AAAA:
        if len(rdata) != 16:
            return rdata.hex()
        return socket.inet_ntop(socket.AF_INET6, rdata)
    if rtype in (TYPE_NS, TYPE_CNAME, TYPE_PTR):
        name, _ = _decode_name(full, rdata_off)
        return name
    if rtype == TYPE_MX:
        if len(rdata) < 2:
            return rdata.hex()
        pref = struct.unpack_from(">H", full, rdata_off)[0]
        name, _ = _decode_name(full, rdata_off + 2)
        return f"{pref} {name}"
    if rtype == TYPE_TXT:
        out: list[str] = []
        i = 0
        while i < len(rdata):
            ln = rdata[i]
            i += 1
            out.append(rdata[i:i + ln].decode("utf-8", errors="replace"))
            i += ln
        return " ".join(out)
    if rtype == TYPE_SOA:
        mname, off = _decode_name(full, rdata_off)
        rname, off = _decode_name(full, off)
        if off + 20 > len(full):
            return f"{mname} {rname} (truncated)"
        serial, refresh, retry, expire, minimum = struct.unpack_from(">IIIII", full, off)
        return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
    return rdata.hex()


def parse_response(data: bytes) -> tuple[int, list[Record]]:
    """Parse a DNS reply packet. Returns (rcode, all records from AN+NS+AR)."""
    if len(data) < 12:
        raise DnsError("response shorter than 12 bytes")
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    rcode = flags & 0xF
    offset = 12

    for _ in range(qd):
        _, offset = _decode_name(data, offset)
        if offset + 4 > len(data):
            raise DnsError("question section truncated")
        offset += 4

    records: list[Record] = []
    for _ in range(an + ns + ar):
        name, offset = _decode_name(data, offset)
        if offset + 10 > len(data):
            raise DnsError("RR header truncated")
        rtype, _rclass, ttl, rdlength = struct.unpack_from(">HHIH", data, offset)
        offset += 10
        if offset + rdlength > len(data):
            raise DnsError("RR data truncated")
        rdata = data[offset:offset + rdlength]
        try:
            value = _decode_rdata(rtype, rdata, data, offset)
        except DnsError:
            value = rdata.hex()
        records.append(Record(name=name, rtype=TYPE_NAMES.get(rtype, str(rtype)),
                              ttl=ttl, data=value))
        offset += rdlength
    return rcode, records


def query(name: str, qtype: int | str, server: str = "8.8.8.8",
          timeout: float = 3.0) -> list[Record]:
    """Send a recursive UDP DNS query. Raises DnsError on RCODE != 0."""
    if isinstance(qtype, str):
        qtype = TYPE_BY_NAME[qtype.upper()]
    pkt = build_query(name, qtype)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(pkt, (server, 53))
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout as e:
            raise DnsError(f"timeout querying {server}") from e
    rcode, records = parse_response(data)
    if rcode == 3:
        return []
    if rcode != 0:
        raise DnsError(f"server returned {RCODE_NAMES.get(rcode, rcode)}")
    return [r for r in records if r.rtype == TYPE_NAMES.get(qtype, str(qtype))]


def axfr(zone: str, server: str, timeout: float = 5.0) -> list[Record]:
    """Attempt a zone transfer (AXFR) over TCP. Returns all RRs received."""
    pkt = build_query(zone, TYPE_AXFR)
    framed = struct.pack(">H", len(pkt)) + pkt
    out: list[Record] = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((server, 53))
        sock.sendall(framed)
        while True:
            hdr = _recv_exact(sock, 2)
            if not hdr:
                break
            mlen = struct.unpack(">H", hdr)[0]
            if mlen == 0:
                continue
            msg = _recv_exact(sock, mlen)
            if not msg or len(msg) < mlen:
                break
            rcode, recs = parse_response(msg)
            if rcode != 0:
                raise DnsError(f"AXFR rcode {RCODE_NAMES.get(rcode, rcode)}")
            out.extend(recs)
    return out


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            return bytes(buf)
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)
