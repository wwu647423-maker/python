"""
httpprobe — HTTP(S) endpoint fingerprinting.

For each URL we issue a single GET, capture response code, server/title,
security-relevant headers, and run a small signature ruleset over the
headers/body to guess the underlying tech stack (server, framework, CDN,
CMS). Operates concurrently when multiple URLs are supplied.
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from typing import NamedTuple

from ._common import bold, cyan, dim, emit_jsonl, green, print_table, red, yellow

DEFAULT_UA = "Mozilla/5.0 (cyberkit/httpprobe)"

SIGNATURES: list[tuple[str, str, re.Pattern, str]] = [
    ("Server",            "nginx",            re.compile(r"\bnginx\b", re.I), "header"),
    ("Server",            "Apache",           re.compile(r"\bapache\b", re.I), "header"),
    ("Server",            "Caddy",            re.compile(r"\bcaddy\b", re.I), "header"),
    ("Server",            "Microsoft-IIS",    re.compile(r"\biis\b", re.I), "header"),
    ("Server",            "LiteSpeed",        re.compile(r"\blitespeed\b", re.I), "header"),
    ("Server",            "Kestrel",          re.compile(r"\bkestrel\b", re.I), "header"),
    ("Server",            "gunicorn",         re.compile(r"\bgunicorn\b", re.I), "header"),
    ("Server",            "uvicorn",          re.compile(r"\buvicorn\b", re.I), "header"),
    ("Server",            "Werkzeug/Flask",   re.compile(r"\bwerkzeug\b", re.I), "header"),
    ("X-Powered-By",      "PHP",              re.compile(r"\bphp\b", re.I), "header"),
    ("X-Powered-By",      "ASP.NET",          re.compile(r"asp\.net", re.I), "header"),
    ("X-Powered-By",      "Express",          re.compile(r"\bexpress\b", re.I), "header"),
    ("X-Powered-By",      "Next.js",          re.compile(r"\bnext\.js\b", re.I), "header"),
    ("X-Powered-By",      "Nuxt",             re.compile(r"\bnuxt\b", re.I), "header"),
    ("X-Generator",       "Drupal",           re.compile(r"\bdrupal\b", re.I), "header"),
    ("X-AspNet-Version",  "ASP.NET",          re.compile(r".+", re.I), "header"),
    ("X-AspNetMvc-Version","ASP.NET MVC",     re.compile(r".+", re.I), "header"),
    ("X-Drupal-Cache",    "Drupal",           re.compile(r".+", re.I), "header"),
    ("Via",               "Cloudflare",       re.compile(r"cloudflare", re.I), "header"),
    ("CF-Ray",            "Cloudflare",       re.compile(r".+", re.I), "header"),
    ("X-Amz-Cf-Id",       "AWS CloudFront",   re.compile(r".+", re.I), "header"),
    ("X-Cache",           "Varnish",          re.compile(r"varnish", re.I), "header"),
    ("X-Vercel-Id",       "Vercel",           re.compile(r".+", re.I), "header"),
    ("X-Nf-Request-Id",   "Netlify",          re.compile(r".+", re.I), "header"),
    ("X-Render-Origin-Server","Render",       re.compile(r".+", re.I), "header"),
    ("Set-Cookie",        "Django",           re.compile(r"csrftoken|sessionid", re.I), "header"),
    ("Set-Cookie",        "Laravel",          re.compile(r"laravel_session|XSRF-TOKEN", re.I), "header"),
    ("Set-Cookie",        "PHP",              re.compile(r"PHPSESSID", re.I), "header"),
    ("Set-Cookie",        "ASP.NET",          re.compile(r"ASP\.NET_SessionId", re.I), "header"),
    ("Set-Cookie",        "JSP/Java",         re.compile(r"JSESSIONID", re.I), "header"),
    ("Set-Cookie",        "Express",          re.compile(r"connect\.sid", re.I), "header"),
    ("BODY",              "WordPress",        re.compile(r"wp-content|wp-includes", re.I), "body"),
    ("BODY",              "Drupal",           re.compile(r"sites/default/files|drupal\.js", re.I), "body"),
    ("BODY",              "Joomla",           re.compile(r"/components/com_|joomla!", re.I), "body"),
    ("BODY",              "Next.js",          re.compile(r"__NEXT_DATA__", re.I), "body"),
    ("BODY",              "React",            re.compile(r"data-reactroot|react-dom", re.I), "body"),
    ("BODY",              "Vue.js",           re.compile(r"\bvue\.js\b|data-v-[0-9a-f]{6,}", re.I), "body"),
    ("BODY",              "Angular",          re.compile(r"ng-version=|ng-app=", re.I), "body"),
    ("BODY",              "Svelte",           re.compile(r"svelte-[0-9a-z]{6,}", re.I), "body"),
    ("BODY",              "jQuery",           re.compile(r"jquery[.-][0-9]", re.I), "body"),
    ("BODY",              "GraphQL endpoint", re.compile(r'"/graphql"|GraphQL', re.I), "body"),
    ("BODY",              "Magento",          re.compile(r"Mage\.Cookies|/mage/", re.I), "body"),
    ("BODY",              "Shopify",          re.compile(r"cdn\.shopify\.com|Shopify\.theme", re.I), "body"),
    ("BODY",              "Ghost",            re.compile(r'<meta\s+name="generator"\s+content="Ghost', re.I), "body"),
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


class _TitleExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self._in_title = False
        self.title = ""

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title and not self.title:
            self.title = data.strip()


class Probe(NamedTuple):
    url: str
    status: int
    final_url: str
    server: str
    title: str
    content_type: str
    content_length: int
    tech: list[str]
    missing_security_headers: list[str]
    error: str


def _detect_tech(headers: dict[str, str], body: str) -> list[str]:
    found: set[str] = set()
    for hkey, tech, pat, scope in SIGNATURES:
        if scope == "header":
            for k, v in headers.items():
                if k.lower() == hkey.lower() and pat.search(v):
                    found.add(tech)
        else:
            if pat.search(body):
                found.add(tech)
    return sorted(found)


def probe(url: str, timeout: float = 6.0, ua: str = DEFAULT_UA,
          max_body: int = 65536, prefer_https: bool = True) -> Probe:
    if not url.startswith(("http://", "https://")):
        if prefer_https:
            https_url = "https://" + url
            r = _do_request(https_url, timeout, ua, max_body)
            if r.status != 0:
                return r
            url = "http://" + url
        else:
            url = "http://" + url
    return _do_request(url, timeout, ua, max_body)


def _do_request(url: str, timeout: float, ua: str, max_body: int) -> Probe:
    req = urllib.request.Request(url, headers={"User-Agent": ua, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k: v for k, v in resp.headers.items()}
            body_bytes = resp.read(max_body)
            final = resp.geturl()
            status = resp.status
    except urllib.error.HTTPError as e:
        headers = {k: v for k, v in e.headers.items()} if e.headers else {}
        body_bytes = e.read()[:max_body] if hasattr(e, "read") else b""
        final = url
        status = e.code
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return Probe(url=url, status=0, final_url=url, server="", title="",
                     content_type="", content_length=0, tech=[],
                     missing_security_headers=[], error=str(e))

    body = body_bytes.decode("utf-8", errors="replace")
    title = ""
    try:
        ext = _TitleExtractor()
        ext.feed(body)
        title = ext.title[:120]
    except Exception:
        pass

    missing = [h for h in SECURITY_HEADERS
               if not any(k.lower() == h.lower() for k in headers)]

    return Probe(
        url=url,
        status=status,
        final_url=final,
        server=headers.get("Server", ""),
        title=title,
        content_type=headers.get("Content-Type", "").split(";")[0].strip(),
        content_length=len(body_bytes),
        tech=_detect_tech(headers, body),
        missing_security_headers=missing,
        error="",
    )


def _color_status(code: int) -> str:
    if code == 0: return red("ERR")
    if 200 <= code < 300: return green(str(code))
    if 300 <= code < 400: return cyan(str(code))
    if 400 <= code < 500: return yellow(str(code))
    return red(str(code))


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="cyberkit httpprobe",
                                 description="Fingerprint HTTP(S) endpoints.")
    ap.add_argument("urls", nargs="*",
                    help="one or more URLs; if omitted, read one per line from stdin")
    ap.add_argument("-t", "--timeout", type=float, default=6.0)
    ap.add_argument("-w", "--workers", type=int, default=16)
    ap.add_argument("-U", "--user-agent", default=DEFAULT_UA)
    ap.add_argument("--json", action="store_true",
                    help="emit JSON-Lines instead of a table")
    args = ap.parse_args(argv)

    urls = args.urls
    if not urls:
        if sys.stdin.isatty():
            ap.error("no URLs given and stdin is a TTY")
        urls = [ln.strip() for ln in sys.stdin if ln.strip()]
    if not urls:
        print("httpprobe: no URLs", file=sys.stderr)
        return 2

    results: list[Probe] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futs = {pool.submit(probe, u, args.timeout, args.user_agent): u for u in urls}
        for f in as_completed(futs):
            results.append(f.result())

    if args.json:
        emit_jsonl([r._asdict() for r in results])
        return 0

    rows = [[
        _color_status(r.status),
        r.url if len(r.url) < 40 else r.url[:37] + "…",
        r.server[:20] or dim("-"),
        ", ".join(r.tech) or dim("-"),
        r.title[:40] or dim("-"),
    ] for r in results]
    print_table(["STATUS", "URL", "SERVER", "TECH", "TITLE"], rows)

    if any(r.missing_security_headers for r in results if r.status > 0):
        print(dim("-" * 64))
        print(bold("missing security headers:"))
        for r in results:
            if r.status > 0 and r.missing_security_headers:
                print(f"  {r.url}: {yellow(', '.join(r.missing_security_headers))}")
    return 0
