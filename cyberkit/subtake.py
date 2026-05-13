"""
subtake — subdomain takeover detector.

For each input subdomain we:

  1. Resolve its CNAME chain via our pure-stdlib resolver.
  2. If the final CNAME points to a recognized third-party service
     (Heroku, GitHub Pages, AWS S3, Azure CloudApp, Shopify, ...), we
     fetch the HTTP response and look for the canonical 'unclaimed'
     fingerprint string published by that service.
  3. Anything that resolves the CNAME but returns the orphan
     fingerprint is flagged as VULNERABLE; CNAME-to-service without
     the fingerprint is reported as 'potential' so an operator can
     review.

Service signatures are based on the public can-i-take-over-xyz catalogue.
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import NamedTuple

from ._common import bold, cyan, dim, emit_jsonl, green, magenta, red, yellow
from ._dns import DnsError, query


class Service(NamedTuple):
    name: str
    cname_pattern: re.Pattern
    body_pattern: re.Pattern | None


SERVICES: list[Service] = [
    Service("GitHub Pages",
            re.compile(r"\.github\.io$", re.I),
            re.compile(r"There isn't a GitHub Pages site here", re.I)),
    Service("Heroku",
            re.compile(r"\.herokuapp\.com$|\.herokussl\.com$", re.I),
            re.compile(r"No such app|herokucdn\.com/error-pages/no-such-app", re.I)),
    Service("AWS S3",
            re.compile(r"\.s3[.\-][a-z0-9\-]*\.amazonaws\.com$|\.s3\.amazonaws\.com$", re.I),
            re.compile(r"NoSuchBucket|The specified bucket does not exist", re.I)),
    Service("AWS CloudFront",
            re.compile(r"\.cloudfront\.net$", re.I),
            re.compile(r"Bad request\.\s*Code: NoSuchDistribution", re.I)),
    Service("Azure CloudApp",
            re.compile(r"\.cloudapp\.net$|\.azurewebsites\.net$|\.trafficmanager\.net$",
                       re.I),
            re.compile(r"404 Web Site not found|Error 404 - Web app not found", re.I)),
    Service("Shopify",
            re.compile(r"\.myshopify\.com$", re.I),
            re.compile(r"Sorry, this shop is currently unavailable", re.I)),
    Service("Fastly",
            re.compile(r"\.fastly\.net$", re.I),
            re.compile(r"Fastly error: unknown domain", re.I)),
    Service("Tumblr",
            re.compile(r"\.tumblr\.com$", re.I),
            re.compile(r"Whatever you were looking for doesn't currently exist", re.I)),
    Service("Unbounce",
            re.compile(r"\.unbouncepages\.com$", re.I),
            re.compile(r"The requested URL was not found on this server", re.I)),
    Service("Webflow",
            re.compile(r"\.webflow\.io$|proxy\.webflow\.com$", re.I),
            re.compile(r"The page you are looking for doesn't exist", re.I)),
    Service("Pantheon",
            re.compile(r"\.pantheonsite\.io$", re.I),
            re.compile(r"The gods are wise, but do not know of the site which you seek\.",
                       re.I)),
    Service("Surge.sh",
            re.compile(r"\.surge\.sh$", re.I),
            re.compile(r"project not found", re.I)),
    Service("Bitbucket",
            re.compile(r"\.bitbucket\.io$", re.I),
            re.compile(r"Repository not found", re.I)),
    Service("Read the Docs",
            re.compile(r"\.readthedocs\.io$", re.I),
            re.compile(r"unknown to Read the Docs", re.I)),
]


class Result(NamedTuple):
    subdomain: str
    cname_chain: list[str]
    service: str
    verdict: str
    detail: str


def _trace_cname(name: str, server: str, timeout: float, max_hops: int = 10) -> list[str]:
    chain: list[str] = []
    current = name
    for _ in range(max_hops):
        try:
            recs = query(current, "CNAME", server=server, timeout=timeout)
        except (DnsError, OSError):
            break
        if not recs:
            break
        target = recs[0].data.rstrip(".")
        chain.append(target)
        if target == current:
            break
        current = target
    return chain


def _http_get(url: str, timeout: float) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "cyberkit/subtake"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(65536).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read()[:65536].decode("utf-8", errors="replace") if hasattr(e, "read") else ""
        except Exception:
            body = ""
        return e.code, body
    except (urllib.error.URLError, OSError):
        return 0, ""


def check(subdomain: str, server: str, timeout: float,
          schemes: tuple[str, ...] = ("http", "https")) -> Result:
    sub = subdomain.strip().rstrip(".")
    chain = _trace_cname(sub, server, timeout)
    if not chain:
        return Result(sub, [], "", "no-cname",
                      "no CNAME chain — direct A/AAAA or NXDOMAIN")

    final = chain[-1]
    service = next((s for s in SERVICES if s.cname_pattern.search(final)), None)
    if not service:
        return Result(sub, chain, "", "cname-not-service",
                      f"CNAME chain ends at {final} — not a known SaaS")

    for scheme in schemes:
        status, body = _http_get(f"{scheme}://{sub}", timeout)
        if service.body_pattern and service.body_pattern.search(body):
            return Result(sub, chain, service.name, "VULNERABLE",
                          f"{scheme} {status}: orphan fingerprint matched")
    return Result(sub, chain, service.name, "potential",
                  f"CNAME points to {service.name} but no orphan fingerprint matched — review")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="cyberkit subtake",
                                 description="Detect dangling-CNAME subdomain takeover candidates.")
    ap.add_argument("inputs", nargs="*",
                    help="subdomains to check; otherwise read one per line from stdin")
    ap.add_argument("-s", "--server", default="1.1.1.1")
    ap.add_argument("-t", "--timeout", type=float, default=4.0)
    ap.add_argument("-w", "--workers", type=int, default=16)
    ap.add_argument("--http-only", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    names = list(args.inputs)
    if not names:
        if sys.stdin.isatty():
            ap.error("no subdomain given and stdin is a TTY")
        names = [ln.strip() for ln in sys.stdin if ln.strip()]
    if not names:
        print("subtake: no input subdomains", file=sys.stderr); return 2

    schemes = ("http",) if args.http_only else ("http", "https")
    results: list[Result] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futs = [pool.submit(check, n, args.server, args.timeout, schemes) for n in names]
        for f in as_completed(futs):
            results.append(f.result())

    sort_key = {"VULNERABLE": 0, "potential": 1, "cname-not-service": 2, "no-cname": 3}
    results.sort(key=lambda r: (sort_key.get(r.verdict, 99), r.subdomain))

    if args.json:
        emit_jsonl([r._asdict() for r in results])
        return 1 if any(r.verdict == "VULNERABLE" for r in results) else 0

    verdict_color = {"VULNERABLE": red, "potential": yellow,
                     "cname-not-service": dim, "no-cname": dim}
    for r in results:
        line = (f"{verdict_color[r.verdict](r.verdict):<14}"
                f" {cyan(r.subdomain):<40}"
                f" {magenta(r.service or '-'):<18}"
                f" {r.detail}")
        if r.verdict in ("VULNERABLE", "potential") and r.cname_chain:
            line += dim("  chain=" + " -> ".join(r.cname_chain))
        print(line)
    return 1 if any(r.verdict == "VULNERABLE" for r in results) else 0
