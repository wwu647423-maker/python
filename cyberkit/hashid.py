"""
hashid — identify the most likely algorithm behind an opaque hash string.

Uses length + charset heuristics plus structural prefixes (e.g. `$2b$` for
bcrypt, `$argon2id$` for Argon2). For each match we return a confidence
ranking so callers can iterate from most- to least-likely.
"""

from __future__ import annotations

import argparse
import re
import sys
from typing import NamedTuple

from ._common import bold, cyan, dim, emit_json, green, print_table, yellow

HEX = re.compile(r"^[0-9a-fA-F]+$")
B64 = re.compile(r"^[A-Za-z0-9+/=._-]+$")


class Candidate(NamedTuple):
    name: str
    confidence: int
    note: str


_HEX_BY_LEN: dict[int, list[tuple[str, str]]] = {
    8:   [("CRC-32", "32-bit hex"),
          ("Adler-32", "32-bit hex")],
    16:  [("MySQL323", "16-hex MySQL pre-4.1"),
          ("DES(Unix) checksum", "rare")],
    32:  [("MD5", "RFC 1321"),
          ("NTLM", "Windows password hash"),
          ("MD4", "legacy")],
    40:  [("SHA-1", "FIPS 180-1"),
          ("RIPEMD-160", "alt 160-bit hash"),
          ("MySQL 4.1+ (stripped *)", "see also bare *...40hex")],
    56:  [("SHA-224", ""),
          ("SHA3-224", "")],
    64:  [("SHA-256", "FIPS 180-2"),
          ("SHA3-256", ""),
          ("BLAKE2s-256", "")],
    96:  [("SHA-384", ""),
          ("SHA3-384", "")],
    128: [("SHA-512", ""),
          ("SHA3-512", ""),
          ("BLAKE2b-512", ""),
          ("Whirlpool", "")],
}


_STRUCTURAL: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"^\$1\$[^$]{1,8}\$[./0-9A-Za-z]{22}$"),
        "md5crypt", "Unix /etc/shadow style"),
    (re.compile(r"^\$2[aby]\$\d{2}\$[./0-9A-Za-z]{53}$"),
        "bcrypt", "OpenBSD; cost in 2nd field"),
    (re.compile(r"^\$5\$(rounds=\d+\$)?[^$]{1,16}\$[./0-9A-Za-z]{43}$"),
        "sha256crypt", "GNU libc sha256-crypt"),
    (re.compile(r"^\$6\$(rounds=\d+\$)?[^$]{1,16}\$[./0-9A-Za-z]{86}$"),
        "sha512crypt", "GNU libc sha512-crypt"),
    (re.compile(r"^\$argon2(id|i|d)\$.+\$.+\$.+$"),
        "Argon2", "memory-hard KDF (RFC 9106)"),
    (re.compile(r"^\$scrypt\$.+"),
        "scrypt", "RFC 7914"),
    (re.compile(r"^\$pbkdf2(-sha\d+)?\$.+"),
        "PBKDF2", "RFC 8018"),
    (re.compile(r"^\$P\$[./0-9A-Za-z]{31}$"),
        "phpass", "WordPress/Drupal portable hash"),
    (re.compile(r"^{SSHA}.+$"),
        "LDAP SSHA", "salted SHA-1, base64 wrapped"),
    (re.compile(r"^_[./0-9A-Za-z]{19}$"),
        "BSDi-crypt", "DES variant with iter count"),
    (re.compile(r"^[./0-9A-Za-z]{13}$"),
        "DES-crypt", "classic 2-char salt + 11-char hash"),
    (re.compile(r"^[a-f0-9]{32}:[A-Fa-f0-9]{16}$"),
        "MD5(unix) salted", "hash:salt or DCC2 layout"),
    (re.compile(r"^[A-Fa-f0-9]{16}$"),
        "LM hash half / DES variant", "16-hex single block"),
]


def identify(hash_str: str) -> list[Candidate]:
    h = hash_str.strip()
    out: list[Candidate] = []

    for pat, name, note in _STRUCTURAL:
        if pat.match(h):
            out.append(Candidate(name, 95, note))

    if HEX.match(h):
        for cand in _HEX_BY_LEN.get(len(h), []):
            name, note = cand
            conf = 80 if name in ("MD5", "SHA-1", "SHA-256", "SHA-512", "NTLM") else 55
            out.append(Candidate(name, conf, note))

    if "$" not in h and ":" not in h and not HEX.match(h) and B64.match(h):
        if len(h) in (24, 28, 44, 88):
            out.append(Candidate("base64(SHA-1/256/512)", 40,
                                  "raw digest base64 encoded"))

    if not out:
        out.append(Candidate("unknown", 0, "no heuristic matched"))

    out.sort(key=lambda c: -c.confidence)
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="cyberkit hashid",
                                 description="Identify the algorithm of a hash string.")
    ap.add_argument("hash", nargs="?", help="hash string to inspect (omit to read stdin)")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args(argv)

    if args.hash is None:
        if sys.stdin.isatty():
            ap.error("no hash given and stdin is a TTY")
        args.hash = sys.stdin.read().strip()

    if not args.hash:
        print("hashid: empty input", file=sys.stderr)
        return 2

    cands = identify(args.hash)

    if args.json:
        emit_json({"input": args.hash,
                   "candidates": [c._asdict() for c in cands]})
        return 0

    print(f"{bold('input')}  {args.hash}")
    print(f"{bold('length')} {len(args.hash)}")
    print(dim("-" * 64))
    rows = []
    for c in cands:
        if c.confidence >= 80:
            tag = green(f"{c.confidence}%")
        elif c.confidence >= 40:
            tag = yellow(f"{c.confidence}%")
        else:
            tag = dim(f"{c.confidence}%")
        rows.append([tag, cyan(c.name), c.note])
    print_table(["CONF", "ALGORITHM", "NOTE"], rows)
    return 0
