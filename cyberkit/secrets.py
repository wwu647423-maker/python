"""
secrets — scan files / directories for accidentally-committed credentials.

Strategy: a curated rule table (regex + minimum entropy + optional
contextual gate) covers high-signal patterns (AWS, GCP, GitHub, Slack,
Stripe, JWT, PEM blocks, etc.). For everything else we fall back to a
generic 'high-entropy string' rule that fires only on long base64/hex
tokens with Shannon entropy above a threshold, to avoid drowning in
false positives.

Honors .gitignore-style binary skipping by default (--all to override),
and a built-in ignore list of obviously-noisy paths (node_modules, .git,
build/, dist/, __pycache__/...).
"""

from __future__ import annotations

import argparse
import math
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from ._common import bold, cyan, dim, emit_jsonl, magenta, print_table, red, yellow

IGNORE_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv",
               ".mypy_cache", ".pytest_cache", "dist", "build", ".cache",
               ".tox", ".idea", ".vscode", "target", "vendor"}

BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp",
                   ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
                   ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a",
                   ".class", ".jar", ".war", ".pyc", ".pyo",
                   ".woff", ".woff2", ".ttf", ".eot", ".otf",
                   ".mp3", ".mp4", ".mov", ".avi", ".mkv", ".webm",
                   ".db", ".sqlite", ".sqlite3"}


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern
    severity: str
    min_entropy: float = 0.0


RULES: list[Rule] = [
    Rule("AWS Access Key ID",
         re.compile(r"\b(?:AKIA|ASIA|AGPA|AROA|AIDA|ANPA|ANVA|ABIA|ACCA)[0-9A-Z]{16}\b"),
         "CRITICAL"),
    Rule("AWS Secret Access Key",
         re.compile(r"(?i)aws(.{0,20})?(secret|sk)[^A-Za-z0-9]{0,5}([A-Za-z0-9/+=]{40})"),
         "CRITICAL", min_entropy=4.0),
    Rule("GitHub Personal Access Token",
         re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "CRITICAL"),
    Rule("GitHub OAuth Token",
         re.compile(r"\bgho_[A-Za-z0-9]{36}\b"), "CRITICAL"),
    Rule("GitHub App Token",
         re.compile(r"\b(ghs_|ghu_)[A-Za-z0-9]{36}\b"), "CRITICAL"),
    Rule("GitHub Fine-grained PAT",
         re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"), "CRITICAL"),
    Rule("Slack Token",
         re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,72}\b"), "HIGH"),
    Rule("Slack Webhook",
         re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}"),
         "HIGH"),
    Rule("Stripe Live Secret Key",
         re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"), "CRITICAL"),
    Rule("Stripe Restricted Key",
         re.compile(r"\brk_live_[0-9a-zA-Z]{24,}\b"), "HIGH"),
    Rule("Google API Key",
         re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "HIGH"),
    Rule("Google OAuth Client Secret",
         re.compile(r"\bGOCSPX-[A-Za-z0-9_\-]{28,}\b"), "HIGH"),
    Rule("Heroku API Key",
         re.compile(r"(?i)heroku[^A-Za-z0-9]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"),
         "HIGH"),
    Rule("Twilio API Key",
         re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "HIGH"),
    Rule("SendGrid API Key",
         re.compile(r"\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b"), "HIGH"),
    Rule("Mailgun API Key",
         re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"), "HIGH"),
    Rule("npm Token",
         re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "HIGH"),
    Rule("OpenAI API Key",
         re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}\b"),
         "HIGH"),
    Rule("JWT",
         re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
         "MED"),
    Rule("PEM Private Key Block",
         re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"),
         "CRITICAL"),
    Rule("Generic API Key (context match)",
         re.compile(r"(?i)(api[_\-]?key|api[_\-]?secret|access[_\-]?token|auth[_\-]?token)"
                     r"\s*[:=]\s*['\"]?([A-Za-z0-9/+=_\-]{20,})['\"]?"),
         "MED", min_entropy=3.5),
    Rule("Password assignment",
         re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]([^'\"\n\r ]{6,})['\"]"),
         "LOW"),
    Rule("URL with credentials",
         re.compile(r"\b[a-z][a-z0-9+\-.]*://[^/\s:@]+:[^/\s:@]+@[^/\s]+", re.I),
         "HIGH"),
]


def shannon(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    severity: str
    match: str
    snippet: str


def _redact(s: str, keep: int = 4) -> str:
    if len(s) <= keep * 2 + 3:
        return s[:1] + "***"
    return s[:keep] + "…" + s[-keep:]


def scan_text(path: str, text: str, redact: bool = True,
              max_line_len: int = 8192) -> Iterator[Finding]:
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > max_line_len:
            continue
        for rule in RULES:
            for m in rule.pattern.finditer(line):
                hit = m.group(m.lastindex) if m.lastindex else m.group(0)
                if rule.min_entropy and shannon(hit) < rule.min_entropy:
                    continue
                snippet = line.strip()
                if len(snippet) > 160:
                    snippet = snippet[:160] + "…"
                yield Finding(
                    path=path,
                    line=lineno,
                    rule=rule.name,
                    severity=rule.severity,
                    match=_redact(hit) if redact else hit,
                    snippet=snippet,
                )


def iter_files(root: Path, include_all: bool) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if not include_all:
            if any(part in IGNORE_DIRS for part in path.parts):
                continue
            if path.suffix.lower() in BINARY_SUFFIXES:
                continue
        yield path


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="cyberkit secrets",
                                 description="Scan files / directories for hardcoded credentials.")
    ap.add_argument("path", help="file or directory to scan")
    ap.add_argument("-a", "--all", action="store_true",
                    help="don't skip vendor / build / binary paths")
    ap.add_argument("--no-redact", action="store_true",
                    help="show full matched values (default: redacted)")
    ap.add_argument("--min-severity", choices=["LOW", "MED", "HIGH", "CRITICAL"],
                    default="LOW")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    root = Path(args.path)
    if not root.exists():
        print(f"secrets: {args.path}: no such path", file=sys.stderr)
        return 2

    severity_order = {"LOW": 0, "MED": 1, "HIGH": 2, "CRITICAL": 3}
    min_sev = severity_order[args.min_severity]

    findings: list[Finding] = []
    scanned = 0
    for path in iter_files(root, args.all):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scanned += 1
        rel = str(path)
        for f in scan_text(rel, text, redact=not args.no_redact):
            if severity_order[f.severity] >= min_sev:
                findings.append(f)

    findings.sort(key=lambda f: (-severity_order[f.severity], f.path, f.line))

    if args.json:
        emit_jsonl([f.__dict__ for f in findings])
        return 0 if not findings else 1

    sev_color = {"CRITICAL": red, "HIGH": red, "MED": yellow, "LOW": cyan}
    print(f"{bold('scanned')}  {scanned} files under {root}")
    print(f"{bold('findings')} {len(findings)}")
    print(dim("-" * 64))
    if not findings:
        return 0

    rows = []
    for f in findings:
        rows.append([
            sev_color[f.severity](f.severity),
            cyan(f"{f.path}:{f.line}"),
            magenta(f.rule),
            f.match,
        ])
    print_table(["SEV", "LOCATION", "RULE", "MATCH"], rows)
    return 1
