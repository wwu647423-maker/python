"""
dnsenum — DNS reconnaissance.

Modes:
  * default   : query A AAAA NS MX TXT SOA CNAME for a domain
  * --axfr    : after listing NS records, try AXFR zone transfer
                against every authoritative NS over TCP
  * --brute W : concurrent subdomain enumeration using wordlist W
                (skips wildcard-DNS domains by detecting that a random
                made-up label resolves)
"""

from __future__ import annotations

import argparse
import secrets as _secrets
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from ._common import bold, cyan, dim, emit_json, green, print_table, red, yellow
from ._dns import DnsError, Record, TYPE_BY_NAME, axfr, query

DEFAULT_TYPES = ["A", "AAAA", "NS", "MX", "TXT", "SOA", "CNAME"]


def resolve_all(domain: str, server: str, timeout: float,
                types: list[str] | None = None) -> dict[str, list[Record]]:
    types = types or DEFAULT_TYPES
    out: dict[str, list[Record]] = {}
    for t in types:
        try:
            out[t] = query(domain, t, server=server, timeout=timeout)
        except (DnsError, OSError):
            out[t] = []
    return out


def detect_wildcard(domain: str, server: str, timeout: float) -> bool:
    """Return True if the domain answers A for random labels (wildcard DNS)."""
    probe = _secrets.token_hex(8) + "." + domain
    try:
        recs = query(probe, "A", server=server, timeout=timeout)
        return bool(recs)
    except (DnsError, OSError):
        return False


def _resolve_one(label: str, domain: str, server: str, timeout: float) -> tuple[str, list[Record]]:
    name = f"{label}.{domain}".strip(".")
    try:
        recs = query(name, "A", server=server, timeout=timeout)
        return name, recs
    except (DnsError, OSError):
        return name, []


def brute_subdomains(domain: str, words: list[str], server: str,
                     workers: int, timeout: float) -> list[tuple[str, list[Record]]]:
    found: list[tuple[str, list[Record]]] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(_resolve_one, w.strip(), domain, server, timeout)
                for w in words if w.strip() and not w.strip().startswith("#")]
        for f in as_completed(futs):
            name, recs = f.result()
            if recs:
                found.append((name, recs))
    found.sort()
    return found


def attempt_axfr(domain: str, nameservers: list[str], timeout: float) -> dict[str, list[Record]]:
    out: dict[str, list[Record]] = {}
    for ns in nameservers:
        try:
            out[ns] = axfr(domain, ns, timeout=timeout)
        except (DnsError, OSError) as e:
            out[ns] = []
            yield_err = str(e)
            if yield_err:
                pass
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="cyberkit dnsenum",
                                 description="DNS reconnaissance: record dump, AXFR, subdomain brute.")
    ap.add_argument("domain", help="target domain (e.g. example.com)")
    ap.add_argument("-s", "--server", default="1.1.1.1",
                    help="DNS resolver to query (default: 1.1.1.1)")
    ap.add_argument("-t", "--timeout", type=float, default=3.0)
    ap.add_argument("-w", "--workers", type=int, default=64,
                    help="brute-force concurrency (default: 64)")
    ap.add_argument("--axfr", action="store_true",
                    help="attempt zone transfer (AXFR) against each NS")
    ap.add_argument("--brute", metavar="WORDLIST",
                    help="enumerate subdomains using this wordlist")
    ap.add_argument("--types", default=",".join(DEFAULT_TYPES),
                    help="comma-separated record types (default: A,AAAA,NS,MX,TXT,SOA,CNAME)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    types = [t.strip().upper() for t in args.types.split(",") if t.strip()]
    for t in types:
        if t not in TYPE_BY_NAME:
            print(f"dnsenum: unsupported record type {t}", file=sys.stderr)
            return 2

    records = resolve_all(args.domain, args.server, args.timeout, types)

    axfr_results: dict[str, list[Record]] = {}
    if args.axfr:
        ns_targets: list[str] = []
        for r in records.get("NS", []):
            ns_targets.append(r.data.rstrip("."))
        for ns in ns_targets:
            try:
                axfr_results[ns] = axfr(args.domain, ns, timeout=args.timeout)
            except (DnsError, OSError) as e:
                axfr_results[ns] = []

    brute_results: list[tuple[str, list[Record]]] = []
    wildcard = False
    if args.brute:
        try:
            with open(args.brute, "r", encoding="utf-8", errors="replace") as fh:
                words = fh.read().splitlines()
        except OSError as e:
            print(f"dnsenum: {e}", file=sys.stderr)
            return 2
        wildcard = detect_wildcard(args.domain, args.server, args.timeout)
        if wildcard:
            print(yellow(f"warning: {args.domain} appears to use wildcard DNS; "
                         "brute-force results are unreliable"), file=sys.stderr)
        brute_results = brute_subdomains(args.domain, words, args.server,
                                          args.workers, args.timeout)

    if args.json:
        emit_json({
            "domain": args.domain,
            "server": args.server,
            "records": {t: [r._asdict() for r in rs] for t, rs in records.items()},
            "axfr": {ns: [r._asdict() for r in rs] for ns, rs in axfr_results.items()},
            "wildcard_dns": wildcard,
            "brute": [{"name": n, "records": [r._asdict() for r in rs]}
                      for n, rs in brute_results],
        })
        return 0

    print(f"{bold('domain')}   {args.domain}")
    print(f"{bold('resolver')} {args.server}")
    print(dim("-" * 64))
    for t in types:
        rs = records.get(t, [])
        if not rs:
            print(f"{cyan(t):<8} {dim('(no records)')}")
            continue
        for r in rs:
            print(f"{cyan(r.rtype):<8} {dim(f'ttl={r.ttl:6d}')}  {green(r.data)}")

    if args.axfr:
        print(dim("\n" + "-" * 64))
        print(bold("zone-transfer attempts:"))
        for ns, recs in axfr_results.items():
            if recs:
                print(red(f"  [!] AXFR succeeded against {ns} — {len(recs)} records:"))
                for r in recs[:50]:
                    print(f"    {r.name:30} {r.rtype:5} {r.data}")
                if len(recs) > 50:
                    print(dim(f"    ... and {len(recs) - 50} more"))
            else:
                print(f"  [-] AXFR refused by {ns}")

    if args.brute:
        print(dim("\n" + "-" * 64))
        print(bold(f"subdomain brute ({len(brute_results)} hits"
                   f"{' — WILDCARD DNS, distrust results' if wildcard else ''}):"))
        rows = []
        for name, recs in brute_results:
            ips = ", ".join(r.data for r in recs if r.rtype == "A")
            rows.append([cyan(name), green(ips)])
        if rows:
            print_table(["NAME", "A"], rows)
    return 0
