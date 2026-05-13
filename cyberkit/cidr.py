"""
cidr — IPv4/IPv6 subnet arithmetic.

Subcommands:
    info        network / broadcast / first / last / count / prefix
    contains    does CIDR include IP?
    summarize   collapse a list of CIDRs / IPs to the minimal set
    split       carve a CIDR into smaller /N subnets
    iter        list every address (with --limit safety guard)

Built on stdlib `ipaddress`; we just expose it as a focused CLI.
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
from typing import Iterable

from ._common import bold, cyan, dim, emit_json, green, print_table, red, yellow

IPNet = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddr = ipaddress.IPv4Address | ipaddress.IPv6Address


def _net(arg: str) -> IPNet:
    return ipaddress.ip_network(arg, strict=False)


def info(net: IPNet) -> dict:
    out = {
        "input": str(net),
        "network": str(net.network_address),
        "broadcast": str(net.broadcast_address) if isinstance(net, ipaddress.IPv4Network) else None,
        "prefix_length": net.prefixlen,
        "num_addresses": net.num_addresses,
        "first_host": None,
        "last_host": None,
        "netmask": str(net.netmask),
        "hostmask": str(net.hostmask),
        "version": net.version,
        "is_private": net.is_private,
        "is_loopback": net.is_loopback,
        "is_multicast": net.is_multicast,
        "is_global": net.is_global,
    }
    n = net.num_addresses
    if n == 1:
        out["first_host"] = out["last_host"] = str(net[0])
    elif net.version == 4 and n >= 4:
        out["first_host"] = str(net[1])
        out["last_host"] = str(net[-2])
    elif net.version == 4:
        out["first_host"] = str(net[0])
        out["last_host"] = str(net[-1])
    else:
        out["first_host"] = str(net[0])
        out["last_host"] = str(net[n - 1])
    return out


def contains(net: IPNet, addr: IPAddr) -> bool:
    if net.version != addr.version:
        return False
    return addr in net


def summarize(items: Iterable[str]) -> list[str]:
    nets: list[IPNet] = []
    for s in items:
        s = s.strip()
        if not s:
            continue
        try:
            nets.append(_net(s))
        except ValueError:
            try:
                addr = ipaddress.ip_address(s)
                nets.append(_net(f"{addr}/{32 if addr.version == 4 else 128}"))
            except ValueError as e:
                raise ValueError(f"bad CIDR or IP: {s!r}") from e

    v4 = [n for n in nets if n.version == 4]
    v6 = [n for n in nets if n.version == 6]
    collapsed: list[IPNet] = []
    if v4:
        collapsed.extend(ipaddress.collapse_addresses(v4))  # type: ignore[arg-type]
    if v6:
        collapsed.extend(ipaddress.collapse_addresses(v6))  # type: ignore[arg-type]
    return [str(n) for n in collapsed]


def split(net: IPNet, new_prefix: int) -> list[str]:
    return [str(s) for s in net.subnets(new_prefix=new_prefix)]


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="cyberkit cidr",
                                 description="IPv4 / IPv6 subnet calculator.")
    sub = ap.add_subparsers(dest="mode", required=True)

    p = sub.add_parser("info", help="network / broadcast / count / range")
    p.add_argument("cidr")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("contains")
    p.add_argument("cidr")
    p.add_argument("ip")

    p = sub.add_parser("summarize",
                       help="collapse CIDRs / IPs into the minimal set")
    p.add_argument("items", nargs="*",
                   help="CIDRs / IPs; if empty, read one per line from stdin")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("split", help="split a CIDR into smaller /N subnets")
    p.add_argument("cidr")
    p.add_argument("new_prefix", type=int)
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("iter", help="enumerate addresses (use --limit)")
    p.add_argument("cidr")
    p.add_argument("--limit", type=int, default=1024,
                   help="safety cap on number of addresses to print (default: 1024)")

    args = ap.parse_args(argv)

    try:
        if args.mode == "info":
            data = info(_net(args.cidr))
            if args.json:
                emit_json(data); return 0
            print(f"{bold('input')}        {data['input']}")
            print(f"{bold('version')}      IPv{data['version']}")
            print(f"{bold('network')}      {green(data['network'])}/"
                  f"{data['prefix_length']}")
            if data["broadcast"]:
                print(f"{bold('broadcast')}    {green(data['broadcast'])}")
            print(f"{bold('netmask')}      {data['netmask']}")
            print(f"{bold('hostmask')}     {data['hostmask']}")
            print(f"{bold('addresses')}    {data['num_addresses']:,}")
            if data["first_host"]:
                print(f"{bold('host range')}   {cyan(data['first_host'])}"
                      f"  →  {cyan(data['last_host'])}")
            flags = []
            for k in ("is_private", "is_loopback", "is_multicast", "is_global"):
                if data[k]:
                    flags.append(k.replace("is_", ""))
            if flags:
                print(f"{bold('flags')}        {yellow(', '.join(flags))}")
            return 0

        if args.mode == "contains":
            net = _net(args.cidr)
            addr = ipaddress.ip_address(args.ip)
            ok = contains(net, addr)
            print(green("yes") if ok else red("no"))
            return 0 if ok else 1

        if args.mode == "summarize":
            items = args.items
            if not items:
                items = [ln.strip() for ln in sys.stdin if ln.strip()]
            try:
                merged = summarize(items)
            except ValueError as e:
                print(f"cidr: {e}", file=sys.stderr); return 2
            if args.json:
                emit_json(merged); return 0
            print(f"{bold('input')}    {len(items)} items")
            print(f"{bold('merged')}   {len(merged)} CIDRs")
            print(dim("-" * 64))
            for s in merged:
                print(s)
            return 0

        if args.mode == "split":
            net = _net(args.cidr)
            try:
                parts = split(net, args.new_prefix)
            except ValueError as e:
                print(f"cidr: {e}", file=sys.stderr); return 2
            if args.json:
                emit_json(parts); return 0
            for s in parts:
                print(s)
            return 0

        if args.mode == "iter":
            net = _net(args.cidr)
            n = 0
            for a in net:
                if n >= args.limit:
                    print(yellow(f"... stopped at --limit {args.limit}"),
                          file=sys.stderr)
                    break
                print(a)
                n += 1
            return 0
    except ValueError as e:
        print(f"cidr: {e}", file=sys.stderr); return 2

    return 2
