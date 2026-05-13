"""
dirfuzz — HTTP content discovery.

Probes a base URL for each entry in a wordlist and reports paths that
look genuinely different from the site's 404 page. Many web apps return
200 OK on missing paths (soft-404), so plain status-code filtering is
noisy. We fingerprint the not-found response *first* (by hitting two
random made-up paths), then filter responses whose status, size, and
title closely match that fingerprint.
"""

from __future__ import annotations

import argparse
import secrets as _secrets
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from typing import NamedTuple

from ._common import bold, cyan, dim, emit_jsonl, green, magenta, print_table, red, yellow

DEFAULT_UA = "Mozilla/5.0 (cyberkit/dirfuzz)"


class _Title(HTMLParser):
    def __init__(self):
        super().__init__()
        self._in = False
        self.title = ""

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "title":
            self._in = True

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self._in = False

    def handle_data(self, data):
        if self._in and not self.title:
            self.title = data.strip()


class Probe(NamedTuple):
    path: str
    url: str
    status: int
    length: int
    title: str
    content_type: str
    redirect: str
    error: str


def _request(url: str, timeout: float, ua: str) -> Probe:
    req = urllib.request.Request(url, headers={"User-Agent": ua, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(65536)
            status = resp.status
            headers = {k: v for k, v in resp.headers.items()}
            final = resp.geturl()
    except urllib.error.HTTPError as e:
        body = e.read()[:65536] if hasattr(e, "read") else b""
        status = e.code
        headers = {k: v for k, v in e.headers.items()} if e.headers else {}
        final = url
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return Probe(path="", url=url, status=0, length=0, title="",
                     content_type="", redirect="", error=str(e))
    title = ""
    try:
        t = _Title()
        t.feed(body.decode("utf-8", errors="replace"))
        title = t.title[:80]
    except Exception:
        pass
    redirect = headers.get("Location", "") if 300 <= status < 400 else ""
    return Probe(path="", url=url, status=status, length=len(body), title=title,
                 content_type=headers.get("Content-Type", "").split(";")[0].strip(),
                 redirect=redirect, error="")


class Fingerprint(NamedTuple):
    status: int
    length: int
    title: str
    valid: bool


def calibrate_404(base: str, timeout: float, ua: str) -> Fingerprint:
    """Probe two random made-up paths; consider their shared shape the 404 fp."""
    probes: list[Probe] = []
    for _ in range(2):
        path = "/" + _secrets.token_hex(12) + ".nope"
        probes.append(_request(base.rstrip("/") + path, timeout, ua))
    p1, p2 = probes
    if p1.status == 0 or p2.status == 0:
        return Fingerprint(0, 0, "", False)
    if p1.status == 404 and p2.status == 404:
        return Fingerprint(404, -1, "", True)
    if p1.status == p2.status and abs(p1.length - p2.length) < 64 and p1.title == p2.title:
        return Fingerprint(p1.status, p1.length, p1.title, True)
    return Fingerprint(0, 0, "", False)


def is_noise(probe: Probe, fp: Fingerprint, tolerance: int = 64) -> bool:
    if probe.status == 0:
        return True
    if not fp.valid:
        return probe.status >= 400 and probe.status != 401 and probe.status != 403
    if probe.status != fp.status:
        return False
    if fp.length == -1:
        return True
    if abs(probe.length - fp.length) <= tolerance and probe.title == fp.title:
        return True
    return False


def _probe_path(base: str, path: str, timeout: float, ua: str) -> Probe:
    if not path.startswith("/"):
        path = "/" + path
    url = base.rstrip("/") + path
    r = _request(url, timeout, ua)
    return r._replace(path=path)


def fuzz(base: str, words: list[str], workers: int, timeout: float, ua: str,
         fingerprint: Fingerprint) -> list[Probe]:
    hits: list[Probe] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(_probe_path, base, w.strip(), timeout, ua)
                for w in words if w.strip() and not w.strip().startswith("#")]
        for f in as_completed(futs):
            r = f.result()
            if not is_noise(r, fingerprint):
                hits.append(r)
    hits.sort(key=lambda p: (p.status, p.path))
    return hits


def _color_status(c: int) -> str:
    if c == 0: return red("ERR")
    if 200 <= c < 300: return green(str(c))
    if 300 <= c < 400: return cyan(str(c))
    if c in (401, 403): return magenta(str(c))
    if 400 <= c < 500: return yellow(str(c))
    return red(str(c))


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="cyberkit dirfuzz",
                                 description="HTTP content discovery with 404 fingerprinting.")
    ap.add_argument("base_url", help="base URL, e.g. https://target.example.com")
    ap.add_argument("-w", "--wordlist", default=None,
                    help="path to wordlist (default: bundled cyberkit/data/dirs-small.txt)")
    ap.add_argument("-T", "--threads", type=int, default=24)
    ap.add_argument("-t", "--timeout", type=float, default=6.0)
    ap.add_argument("-U", "--user-agent", default=DEFAULT_UA)
    ap.add_argument("--no-calibrate", action="store_true",
                    help="skip 404 fingerprinting (rely on status code only)")
    ap.add_argument("--tolerance", type=int, default=64,
                    help="byte-length tolerance for 404 matching (default: 64)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if not args.base_url.startswith(("http://", "https://")):
        args.base_url = "http://" + args.base_url

    if args.wordlist is None:
        from pathlib import Path
        args.wordlist = str(Path(__file__).resolve().parent / "data" / "dirs-small.txt")

    try:
        with open(args.wordlist, "r", encoding="utf-8", errors="replace") as fh:
            words = fh.read().splitlines()
    except OSError as e:
        print(f"dirfuzz: {e}", file=sys.stderr)
        return 2

    fp = Fingerprint(0, 0, "", False)
    if not args.no_calibrate:
        fp = calibrate_404(args.base_url, args.timeout, args.user_agent)

    hits = fuzz(args.base_url, words, args.threads, args.timeout,
                args.user_agent, fp)

    if args.json:
        emit_jsonl([h._asdict() for h in hits])
        return 0

    print(f"{bold('target')}   {args.base_url}")
    print(f"{bold('wordlist')} {args.wordlist}  ({sum(1 for w in words if w.strip())} entries)")
    if fp.valid:
        print(f"{bold('404 fp')}   status={fp.status} length~{fp.length} title={fp.title!r}")
    else:
        print(f"{bold('404 fp')}   {dim('none — filtering by status only')}")
    print(dim("-" * 64))

    if not hits:
        print(yellow("no hits."))
        return 0

    rows = [[_color_status(h.status),
             cyan(h.path),
             str(h.length),
             h.content_type or dim("-"),
             (h.redirect or h.title)[:50] or dim("-")]
            for h in hits]
    print_table(["STATUS", "PATH", "SIZE", "TYPE", "TITLE/REDIRECT"], rows)
    print(dim("-" * 64))
    print(f"{len(hits)} hits")
    return 0
