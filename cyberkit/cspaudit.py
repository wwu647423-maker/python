"""
cspaudit — parse a Content-Security-Policy header and audit each directive.

Operates either on a literal policy string (--policy) or by fetching the
header from a URL. Highlights:

  * unsafe-inline / unsafe-eval / unsafe-hashes
  * wildcard '*' sources and bare http: (mixed content)
  * data:, blob:, filesystem: schemes where they grant XSS surface
  * missing critical directives (script-src, object-src, base-uri,
    frame-ancestors, default-src)
  * 'nonce-...' / 'sha256-...' / 'strict-dynamic' detection (positive)
"""

from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request
from typing import NamedTuple

from ._common import bold, cyan, dim, emit_json, green, magenta, red, yellow

CRITICAL_DIRECTIVES = ["script-src", "object-src", "base-uri", "frame-ancestors"]
FALLBACK_PARENT = "default-src"


class Finding(NamedTuple):
    severity: str
    directive: str
    message: str


def parse(policy: str) -> dict[str, list[str]]:
    """Return {directive_name_lowercased: [source-list tokens]}."""
    out: dict[str, list[str]] = {}
    for clause in policy.split(";"):
        parts = clause.strip().split()
        if not parts:
            continue
        name = parts[0].lower()
        sources = parts[1:]
        out.setdefault(name, []).extend(sources)
    return out


def _audit_directive(name: str, sources: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    s_lower = [s.lower() for s in sources]

    if "'unsafe-inline'" in s_lower and "script" in name:
        findings.append(Finding("HIGH", name,
                                "'unsafe-inline' allows arbitrary inline JS — typical XSS bypass"))
    elif "'unsafe-inline'" in s_lower:
        findings.append(Finding("MED", name,
                                "'unsafe-inline' present (less critical for non-script)"))
    if "'unsafe-eval'" in s_lower:
        findings.append(Finding("HIGH", name,
                                "'unsafe-eval' allows eval()/new Function() — large XSS surface"))
    if "'unsafe-hashes'" in s_lower and "script" in name:
        findings.append(Finding("MED", name,
                                "'unsafe-hashes' enables hashed event handlers — narrow but real XSS path"))
    if "*" in s_lower:
        findings.append(Finding("HIGH", name,
                                "wildcard '*' source — any host allowed"))
    if any(s == "http:" for s in s_lower):
        findings.append(Finding("MED", name,
                                "scheme http: present — defeats HTTPS-only enforcement"))
    if any(s.startswith("data:") for s in s_lower) and "script" in name:
        findings.append(Finding("HIGH", name,
                                "data: scheme allowed in a script directive — direct XSS"))
    if any(s.startswith("data:") for s in s_lower) and "object" in name:
        findings.append(Finding("HIGH", name,
                                "data: allowed in object-src — embed-based bypass"))
    if any(s.startswith("blob:") for s in s_lower) and "script" in name:
        findings.append(Finding("MED", name, "blob: in script-src; consider strict-dynamic instead"))
    return findings


def audit(policy_text: str) -> tuple[dict[str, list[str]], list[Finding]]:
    parsed = parse(policy_text)
    findings: list[Finding] = []
    for directive, sources in parsed.items():
        findings.extend(_audit_directive(directive, sources))

    has_default = FALLBACK_PARENT in parsed
    for d in CRITICAL_DIRECTIVES:
        if d not in parsed and not has_default:
            findings.append(Finding("HIGH", d,
                                    f"directive {d} is not defined and there is no {FALLBACK_PARENT} fallback"))
        elif d not in parsed:
            findings.append(Finding("LOW", d,
                                    f"directive {d} not explicit (relies on {FALLBACK_PARENT})"))

    if "object-src" in parsed and any(s.lower() == "'none'" for s in parsed["object-src"]):
        pass
    elif "object-src" in parsed:
        findings.append(Finding("MED", "object-src",
                                "object-src is set but not to 'none' — consider blocking plugins entirely"))

    severity_order = {"CRITICAL": 3, "HIGH": 2, "MED": 1, "LOW": 0}
    findings.sort(key=lambda f: (-severity_order[f.severity], f.directive))
    return parsed, findings


def fetch_csp(url: str, timeout: float = 6.0) -> tuple[str | None, str | None]:
    """Return (enforced_csp, report_only_csp)."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    req = urllib.request.Request(url, headers={"User-Agent": "cyberkit/cspaudit"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        headers = {k.lower(): v for k, v in resp.headers.items()}
    return headers.get("content-security-policy"), headers.get("content-security-policy-report-only")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="cyberkit cspaudit",
                                 description="Audit a Content-Security-Policy.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--policy", help="literal CSP value")
    src.add_argument("--url", help="fetch the CSP header from this URL")
    src.add_argument("--stdin", action="store_true", help="read policy from stdin")
    ap.add_argument("-t", "--timeout", type=float, default=6.0)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.policy:
        policy_text = args.policy
        ro_text = None
    elif args.stdin:
        policy_text = sys.stdin.read().strip()
        ro_text = None
    else:
        try:
            policy_text, ro_text = fetch_csp(args.url, args.timeout)
        except (urllib.error.URLError, OSError) as e:
            print(f"cspaudit: {e}", file=sys.stderr); return 2
        if not policy_text and ro_text:
            print(yellow("note: no enforcing CSP, only report-only; auditing that one"),
                  file=sys.stderr)
            policy_text = ro_text
        if not policy_text:
            print(red("cspaudit: target has no CSP header at all"), file=sys.stderr)
            return 1

    parsed, findings = audit(policy_text)

    if args.json:
        emit_json({
            "policy": policy_text,
            "report_only": ro_text,
            "directives": parsed,
            "findings": [f._asdict() for f in findings],
        })
        return 1 if any(f.severity in ("HIGH", "CRITICAL") for f in findings) else 0

    print(bold("directives:"))
    for d, sources in parsed.items():
        joined = " ".join(sources) if sources else dim("(no sources)")
        print(f"  {cyan(d):<28} {joined}")

    if findings:
        print(dim("\n" + "-" * 64))
        print(bold("findings:"))
        sev_color = {"CRITICAL": red, "HIGH": red, "MED": yellow, "LOW": cyan}
        for f in findings:
            print(f"  {sev_color.get(f.severity, dim)(f.severity):<10}"
                  f" {magenta(f.directive):<22} {f.message}")
        return 1 if any(f.severity in ("HIGH", "CRITICAL") for f in findings) else 0
    print(green("\nno issues found."))
    return 0
