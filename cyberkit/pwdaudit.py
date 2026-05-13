"""
pwdaudit — local password strength audit + optional HIBP breach lookup.

Local checks (always):
  * length, character-class diversity, Shannon entropy of the string
  * detection of obvious patterns (keyboard runs, repeated chars,
    year prefixes/suffixes, l33t substitutions of a common base word)
  * estimated guess-entropy via a pool-size + pattern penalty model
Online check (HIBP k-anonymity, opt-in via default; disable with --offline):
  * SHA-1(password), send the first 5 hex chars to the HIBP range API,
    look for the remaining 35 chars in the response. Only the prefix
    ever leaves your machine.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import math
import re
import string
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import NamedTuple

from ._common import bold, cyan, dim, emit_json, green, red, yellow


_BUNDLED_LIST_CACHE: set[str] | None = None


def _bundled_passwords() -> set[str]:
    """Load the bundled common-password list lazily."""
    global _BUNDLED_LIST_CACHE
    if _BUNDLED_LIST_CACHE is not None:
        return _BUNDLED_LIST_CACHE
    path = Path(__file__).resolve().parent / "data" / "passwords-small.txt"
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            _BUNDLED_LIST_CACHE = {ln.strip() for ln in fh if ln.strip()}
    except OSError:
        _BUNDLED_LIST_CACHE = set()
    return _BUNDLED_LIST_CACHE

COMMON_BASES = {
    "password", "qwerty", "admin", "letmein", "welcome", "monkey",
    "dragon", "abc123", "iloveyou", "secret", "passwd", "login", "root",
}
KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


class Result(NamedTuple):
    length: int
    charset_size: int
    shannon_bits: float
    estimated_guess_bits: float
    score: int                   # 0..4 (zxcvbn-style)
    findings: list[str]
    hibp_pwned_count: int | None
    in_common_list: bool


def _pool_size(pw: str) -> int:
    pools = 0
    if any(c.islower() for c in pw): pools += 26
    if any(c.isupper() for c in pw): pools += 26
    if any(c.isdigit() for c in pw): pools += 10
    if any(c in string.punctuation for c in pw): pools += len(string.punctuation)
    if any(c == " " for c in pw): pools += 1
    if any(ord(c) > 127 for c in pw): pools += 32
    return pools or 1


def _shannon_bits(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(s)
    h = -sum((c / total) * math.log2(c / total) for c in freq.values())
    return h * total


def _keyboard_run(pw: str, min_len: int = 4) -> bool:
    low = pw.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - min_len + 1):
            seg = row[i:i + min_len]
            if seg in low or seg[::-1] in low:
                return True
    return False


def _repeats(pw: str) -> bool:
    return bool(re.search(r"(.)\1{2,}", pw))


def _year_pattern(pw: str) -> bool:
    return bool(re.search(r"(19|20)\d{2}", pw))


def _common_base(pw: str) -> str | None:
    normalized = pw.lower().translate(LEET)
    for base in COMMON_BASES:
        if base in normalized:
            return base
    return None


def audit_local(pw: str) -> Result:
    findings: list[str] = []
    in_common = pw in _bundled_passwords() or pw.lower() in _bundled_passwords()
    if in_common:
        findings.append("EXACT match in bundled common-password list — instantly cracked")
    if len(pw) < 8:
        findings.append("very short (< 8 chars)")
    elif len(pw) < 12:
        findings.append("short (< 12 chars)")

    classes = sum([
        any(c.islower() for c in pw),
        any(c.isupper() for c in pw),
        any(c.isdigit() for c in pw),
        any(c in string.punctuation for c in pw),
    ])
    if classes <= 1:
        findings.append("single character class — increase diversity")

    base = _common_base(pw)
    if base:
        findings.append(f"contains common base word: {base!r}")
    if _keyboard_run(pw):
        findings.append("keyboard run detected (e.g. qwerty/asdf/1234)")
    if _repeats(pw):
        findings.append("repeated characters (>= 3 in a row)")
    if _year_pattern(pw):
        findings.append("contains a 4-digit year")

    pool = _pool_size(pw)
    naive_bits = len(pw) * math.log2(pool) if pool > 1 else 0.0

    penalty = 0.0
    if base: penalty += 25
    if _keyboard_run(pw): penalty += 15
    if _repeats(pw): penalty += 8
    if _year_pattern(pw): penalty += 6
    if classes <= 1: penalty += 8
    estimated = max(0.0, naive_bits - penalty)

    if   estimated < 28: score = 0
    elif estimated < 36: score = 1
    elif estimated < 60: score = 2
    elif estimated < 80: score = 3
    else:                score = 4
    if in_common:
        score = 0

    return Result(
        length=len(pw),
        charset_size=pool,
        shannon_bits=round(_shannon_bits(pw), 2),
        estimated_guess_bits=round(estimated, 2),
        score=score,
        findings=findings,
        hibp_pwned_count=None,
        in_common_list=in_common,
    )


def hibp_lookup(pw: str, timeout: float = 5.0) -> int:
    """k-anonymous lookup against api.pwnedpasswords.com. Returns count or 0."""
    sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    req = urllib.request.Request(url, headers={
        "User-Agent": "cyberkit/pwdaudit",
        "Add-Padding": "true",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("ascii", errors="replace")
    for line in body.splitlines():
        if ":" not in line:
            continue
        hsuf, count = line.strip().split(":", 1)
        if hsuf.upper() == suffix:
            try:
                return int(count)
            except ValueError:
                return 0
    return 0


SCORE_LABELS = {0: red("very weak"), 1: red("weak"),
                2: yellow("fair"),  3: green("strong"),
                4: green("very strong")}


def _read_password(prompt_text: str) -> str:
    if not sys.stdin.isatty():
        return sys.stdin.readline().rstrip("\n")
    return getpass.getpass(prompt_text)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="cyberkit pwdaudit",
                                 description="Audit password strength locally and (by default) check HIBP.")
    ap.add_argument("password", nargs="?",
                    help="password to audit; omit to prompt without echo")
    ap.add_argument("--offline", action="store_true",
                    help="skip the HIBP k-anonymity breach lookup")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args(argv)

    pw = args.password if args.password is not None else _read_password("password: ")
    if pw is None or pw == "":
        print("pwdaudit: empty password", file=sys.stderr)
        return 2

    result = audit_local(pw)
    if not args.offline:
        try:
            result = result._replace(hibp_pwned_count=hibp_lookup(pw))
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            print(f"pwdaudit: HIBP lookup failed ({e}); use --offline to silence",
                  file=sys.stderr)

    if args.json:
        emit_json(result._asdict())
        return 0

    print(f"{bold('length')}             {result.length}")
    print(f"{bold('charset pool')}       {result.charset_size}")
    print(f"{bold('shannon (str)')}      {result.shannon_bits} bits")
    print(f"{bold('estimated guess')}    {result.estimated_guess_bits} bits")
    print(f"{bold('verdict')}            {SCORE_LABELS[result.score]}")
    if result.hibp_pwned_count is None:
        print(f"{bold('HIBP')}               {dim('skipped')}")
    elif result.hibp_pwned_count == 0:
        print(f"{bold('HIBP')}               {green('not seen in any known breach')}")
    else:
        print(f"{bold('HIBP')}               {red(f'PWNED — seen {result.hibp_pwned_count:,} times')}")
    if result.findings:
        print(dim("-" * 64))
        for f in result.findings:
            print(yellow("  ! ") + cyan(f))
    return 0
