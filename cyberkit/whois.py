"""
whois — minimal WHOIS client over TCP/43 with referral chasing.

Lookup strategy:

  1. If --server is given, query that.
  2. Else if the query looks like an IP / CIDR → start at whois.iana.org
     to discover the right RIR (ARIN/RIPE/APNIC/LACNIC/AFRINIC), then
     query that.
  3. Else (domain) → query whois.iana.org for the TLD, then follow the
     'whois:' / 'refer:' line to the authoritative registry.
  4. From there, follow any 'Registrar WHOIS Server:' redirect once
     more (the typical .com pattern).

Output is the concatenated raw response of every server consulted,
with each section prefixed by which server it came from. JSON mode
returns the structured chain.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import socket
import sys
from typing import NamedTuple

from ._common import bold, cyan, dim, emit_json, green, magenta

IANA_HOST = "whois.iana.org"

_REFER = re.compile(r"^\s*(?:refer|whois|ReferralServer):\s*(?:rwhois://|whois://)?([A-Za-z0-9.\-]+)",
                    re.M | re.I)
_REGISTRAR_WHOIS = re.compile(r"^\s*Registrar WHOIS Server:\s*([A-Za-z0-9.\-]+)",
                              re.M | re.I)


class Hop(NamedTuple):
    server: str
    response: str


def _query(server: str, query: str, timeout: float = 10.0, port: int = 43) -> str:
    """Single TCP/43 round-trip (port overridable for tests)."""
    with socket.create_connection((server, port), timeout=timeout) as sock:
        sock.sendall((query.strip() + "\r\n").encode("utf-8"))
        chunks: list[bytes] = []
        sock.settimeout(timeout)
        while True:
            try:
                chunk = sock.recv(8192)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


def _is_ip(arg: str) -> bool:
    try:
        ipaddress.ip_address(arg.split("/")[0])
        return True
    except ValueError:
        return False


def _seed_server(arg: str) -> str:
    return IANA_HOST


def _follow_referrals(response: str) -> str | None:
    for pat in (_REGISTRAR_WHOIS, _REFER):
        m = pat.search(response)
        if m:
            host = m.group(1).strip().lower()
            if host and "." in host:
                return host
    return None


def lookup(query: str, server: str | None = None, timeout: float = 10.0,
            max_hops: int = 4) -> list[Hop]:
    """Perform a WHOIS lookup, chasing referrals up to `max_hops` times."""
    target_server = server or _seed_server(query)
    seen: set[str] = set()
    chain: list[Hop] = []

    current = target_server
    q = query
    for _ in range(max_hops):
        if current in seen:
            break
        seen.add(current)
        if current == "whois.verisign-grs.com" or current.endswith(".verisign-grs.com"):
            sent = f"={q}"
        else:
            sent = q
        try:
            resp = _query(current, sent, timeout=timeout)
        except (OSError, socket.timeout) as e:
            chain.append(Hop(current, f"(query failed: {e})"))
            break
        chain.append(Hop(current, resp))
        nxt = _follow_referrals(resp)
        if not nxt or nxt == current:
            break
        current = nxt
    return chain


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="cyberkit whois",
                                 description="WHOIS client with referral chasing.")
    ap.add_argument("query", help="domain, IP, or AS number")
    ap.add_argument("-s", "--server", default=None,
                    help="override the initial WHOIS server")
    ap.add_argument("-t", "--timeout", type=float, default=10.0)
    ap.add_argument("--hops", type=int, default=4,
                    help="maximum referral hops (default: 4)")
    ap.add_argument("--raw", action="store_true",
                    help="print just the final hop's response, no headers")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    chain = lookup(args.query, server=args.server, timeout=args.timeout,
                    max_hops=args.hops)
    if not chain:
        print("whois: no servers responded", file=sys.stderr)
        return 1

    if args.json:
        emit_json({"query": args.query,
                   "hops": [h._asdict() for h in chain]})
        return 0

    if args.raw:
        sys.stdout.write(chain[-1].response)
        return 0

    for i, hop in enumerate(chain):
        marker = bold("==>") + " "
        print(f"\n{marker}{magenta(hop.server)} {dim(f'(hop {i+1}/{len(chain)})')}")
        print(dim("-" * 64))
        print(hop.response.rstrip())
    return 0
