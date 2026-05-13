"""
mailcheck — email authentication posture (SPF / DMARC / DKIM / MX).

Pulls the relevant TXT/MX records via our pure-stdlib resolver and runs
a focused audit:

  * SPF      missing  /  permissive +all  /  no -all~all terminal  /
              chained `redirect=`  /  more than 10 lookups (RFC 7208 §4.6.4)
  * DMARC    missing on _dmarc.<domain>  /  weak `p=none`  /  pct<100  /
              no rua report endpoint
  * DKIM     for each --selector, fetch <sel>._domainkey.<domain> TXT,
              parse k= / p= and flag short / missing keys
  * MX       at least one MX with reachable A record
"""

from __future__ import annotations

import argparse
import re
import sys
from typing import NamedTuple

from ._common import bold, cyan, dim, emit_json, green, magenta, red, yellow
from ._dns import DnsError, query


class Finding(NamedTuple):
    severity: str
    component: str
    message: str


def _get_txt(name: str, server: str, timeout: float) -> list[str]:
    try:
        recs = query(name, "TXT", server=server, timeout=timeout)
    except (DnsError, OSError):
        return []
    return [r.data for r in recs]


def _get_mx(name: str, server: str, timeout: float) -> list[str]:
    try:
        recs = query(name, "MX", server=server, timeout=timeout)
    except (DnsError, OSError):
        return []
    return [r.data for r in recs]


def _get_a(name: str, server: str, timeout: float) -> list[str]:
    try:
        recs = query(name, "A", server=server, timeout=timeout)
    except (DnsError, OSError):
        return []
    return [r.data for r in recs]


SPF_LOOKUP_MECHS = re.compile(r"\b(include|a|mx|ptr|exists|redirect)[:=]", re.I)


def audit_spf(txts: list[str]) -> tuple[str | None, list[Finding]]:
    spfs = [t for t in txts if t.lower().lstrip('"').startswith("v=spf1")]
    findings: list[Finding] = []
    if not spfs:
        findings.append(Finding("HIGH", "SPF", "no SPF record (v=spf1 ...)"))
        return None, findings
    if len(spfs) > 1:
        findings.append(Finding("HIGH", "SPF",
                                f"multiple SPF records found ({len(spfs)}) "
                                "— RFC 7208 requires exactly one"))
    spf = spfs[0]
    if re.search(r"\+all\b", spf, re.I):
        findings.append(Finding("CRITICAL", "SPF",
                                "policy ends with +all — anyone can spoof this domain"))
    elif re.search(r"~all\b", spf, re.I):
        findings.append(Finding("LOW", "SPF",
                                "policy ends with ~all (softfail); -all is stricter"))
    elif re.search(r"-all\b", spf, re.I):
        pass
    else:
        findings.append(Finding("MED", "SPF",
                                "policy has no terminal -all / ~all — implicit ?all (neutral)"))
    lookups = len(SPF_LOOKUP_MECHS.findall(spf))
    if lookups > 10:
        findings.append(Finding("MED", "SPF",
                                f"{lookups} DNS-lookup mechanisms — RFC 7208 caps at 10"))
    return spf, findings


def audit_dmarc(txts: list[str]) -> tuple[str | None, list[Finding]]:
    dmarcs = [t for t in txts if t.lower().lstrip('"').startswith("v=dmarc1")]
    findings: list[Finding] = []
    if not dmarcs:
        findings.append(Finding("HIGH", "DMARC", "no DMARC record at _dmarc.<domain>"))
        return None, findings
    d = dmarcs[0]
    tags = {k.strip().lower(): v.strip() for k, _, v in
            (item.strip().partition("=") for item in d.split(";")) if k}
    policy = tags.get("p", "")
    if policy == "none":
        findings.append(Finding("HIGH", "DMARC",
                                "policy p=none — receivers will not reject spoofed mail"))
    elif policy == "quarantine":
        findings.append(Finding("LOW", "DMARC",
                                "policy p=quarantine; p=reject is the strongest"))
    elif policy not in ("reject",):
        findings.append(Finding("HIGH", "DMARC", f"missing or invalid p= ({policy!r})"))

    pct = tags.get("pct")
    if pct and pct != "100":
        findings.append(Finding("MED", "DMARC",
                                f"pct={pct} — only {pct}% of mail subject to policy"))
    if "rua" not in tags:
        findings.append(Finding("MED", "DMARC",
                                "no rua= report endpoint — you won't get aggregate reports"))
    if tags.get("sp", policy) == "none":
        findings.append(Finding("MED", "DMARC", "sp=none — subdomain policy is off"))
    if tags.get("aspf") == "r":
        findings.append(Finding("LOW", "DMARC", "aspf=r (relaxed); s=strict is tighter"))
    if tags.get("adkim") == "r":
        findings.append(Finding("LOW", "DMARC", "adkim=r (relaxed); s=strict is tighter"))
    return d, findings


def audit_dkim(domain: str, selectors: list[str], server: str,
               timeout: float) -> tuple[dict[str, str], list[Finding]]:
    out: dict[str, str] = {}
    findings: list[Finding] = []
    for sel in selectors:
        txts = _get_txt(f"{sel}._domainkey.{domain}", server, timeout)
        joined = " ".join(t for t in txts if "p=" in t.lower() or "k=" in t.lower())
        if not joined:
            findings.append(Finding("MED", f"DKIM[{sel}]",
                                    f"no DKIM record at {sel}._domainkey.{domain}"))
            continue
        out[sel] = joined
        m = re.search(r"\bp=([A-Za-z0-9+/=]*)", joined)
        if m:
            pubkey = m.group(1)
            if not pubkey:
                findings.append(Finding("HIGH", f"DKIM[{sel}]",
                                        "revoked key (p= is empty)"))
            elif len(pubkey) < 200:
                findings.append(Finding("MED", f"DKIM[{sel}]",
                                        "DKIM key looks short (<1024-bit RSA?)"))
        k = re.search(r"\bk=([A-Za-z0-9]+)", joined)
        if k and k.group(1).lower() not in ("rsa", "ed25519"):
            findings.append(Finding("MED", f"DKIM[{sel}]",
                                    f"unusual key algorithm: {k.group(1)}"))
    return out, findings


def audit_mx(domain: str, server: str, timeout: float) -> tuple[list[str], list[Finding]]:
    findings: list[Finding] = []
    mx = _get_mx(domain, server, timeout)
    if not mx:
        findings.append(Finding("MED", "MX", "no MX records — domain cannot receive mail"))
        return [], findings
    hosts: list[str] = []
    for entry in mx:
        _, _, host = entry.partition(" ")
        host = host.rstrip(".")
        hosts.append(host)
        if not _get_a(host, server, timeout):
            findings.append(Finding("LOW", "MX",
                                    f"MX target {host} has no A record"))
    return hosts, findings


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="cyberkit mailcheck",
                                 description="Audit a domain's email authentication posture.")
    ap.add_argument("domain", help="target domain (e.g. example.com)")
    ap.add_argument("-s", "--server", default="1.1.1.1")
    ap.add_argument("-t", "--timeout", type=float, default=3.0)
    ap.add_argument("--selector", action="append", default=[],
                    help="DKIM selector; may be given multiple times "
                         "(common: default, google, selector1, k1, mail)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    domain = args.domain.strip(".")

    spf_record, spf_findings = audit_spf(_get_txt(domain, args.server, args.timeout))
    dmarc_record, dmarc_findings = audit_dmarc(_get_txt(f"_dmarc.{domain}", args.server, args.timeout))
    dkim_records, dkim_findings = audit_dkim(domain, args.selector, args.server, args.timeout)
    mx_hosts, mx_findings = audit_mx(domain, args.server, args.timeout)

    findings = spf_findings + dmarc_findings + dkim_findings + mx_findings
    severity_order = {"CRITICAL": 3, "HIGH": 2, "MED": 1, "LOW": 0}
    findings.sort(key=lambda f: (-severity_order.get(f.severity, 0), f.component))

    if args.json:
        emit_json({
            "domain": domain,
            "spf": spf_record,
            "dmarc": dmarc_record,
            "dkim": dkim_records,
            "mx": mx_hosts,
            "findings": [f._asdict() for f in findings],
        })
        return 1 if any(f.severity in ("HIGH", "CRITICAL") for f in findings) else 0

    print(f"{bold('domain')}  {domain}")
    print(dim("-" * 64))
    print(f"{bold('SPF')}    {green(spf_record) if spf_record else red('(missing)')}")
    print(f"{bold('DMARC')}  {green(dmarc_record) if dmarc_record else red('(missing)')}")
    if dkim_records:
        for sel, txt in dkim_records.items():
            preview = txt if len(txt) < 80 else txt[:77] + "…"
            print(f"{bold('DKIM')}   [{cyan(sel)}] {preview}")
    elif args.selector:
        print(f"{bold('DKIM')}   {red('(none of the requested selectors had a record)')}")
    if mx_hosts:
        print(f"{bold('MX')}     " + ", ".join(magenta(h) for h in mx_hosts))
    else:
        print(f"{bold('MX')}     {red('(missing)')}")

    if findings:
        print(dim("\n" + "-" * 64))
        print(bold("findings:"))
        sev_color = {"CRITICAL": red, "HIGH": red, "MED": yellow, "LOW": cyan}
        for f in findings:
            print(f"  {sev_color.get(f.severity, dim)(f.severity):<10}"
                  f" {magenta(f.component):<18} {f.message}")
        return 1 if any(f.severity in ("HIGH", "CRITICAL") for f in findings) else 0
    return 0
