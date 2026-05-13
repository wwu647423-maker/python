"""
hashcrack — wordlist-based hash recovery for common unsalted algorithms.

Supported: md5, sha1, sha224, sha256, sha384, sha512, ntlm.
For salted constructions use --salt (prepended by default; --salt-append
to append). Reads candidates from a wordlist file or stdin; prints the
first match and exits 0, otherwise prints nothing and exits 1.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from typing import Callable, Iterable

from ._md4 import md4


def _ntlm(b: bytes) -> str:
    return md4(b.decode("utf-8", "replace").encode("utf-16-le")).hex()


ALGOS: dict[str, Callable[[bytes], str]] = {
    "md5":    lambda b: hashlib.md5(b).hexdigest(),
    "sha1":   lambda b: hashlib.sha1(b).hexdigest(),
    "sha224": lambda b: hashlib.sha224(b).hexdigest(),
    "sha256": lambda b: hashlib.sha256(b).hexdigest(),
    "sha384": lambda b: hashlib.sha384(b).hexdigest(),
    "sha512": lambda b: hashlib.sha512(b).hexdigest(),
    "ntlm":   _ntlm,
}


def crack(target: str, words: Iterable[str], algo: str,
          salt: str = "", salt_append: bool = False) -> str | None:
    """Return the first word whose digest matches `target`, else None."""
    if algo not in ALGOS:
        raise ValueError(f"unsupported algorithm: {algo}")
    fn = ALGOS[algo]
    target = target.strip().lower()
    sbytes = salt.encode("utf-8")
    for raw in words:
        word = raw.rstrip("\r\n")
        if not word:
            continue
        wbytes = word.encode("utf-8")
        candidate = wbytes + sbytes if salt_append else sbytes + wbytes
        if fn(candidate) == target:
            return word
    return None


def _open_wordlist(path: str | None):
    if path is None or path == "-":
        return sys.stdin
    return open(path, "r", encoding="utf-8", errors="replace")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="cyberkit hashcrack",
                                 description="Crack an unsalted (or simply-salted) hash with a wordlist.")
    ap.add_argument("hash", help="target hash (hex)")
    ap.add_argument("-a", "--algo", choices=sorted(ALGOS), required=True,
                    help="digest algorithm")
    ap.add_argument("-w", "--wordlist",
                    help="path to wordlist (default: stdin)")
    ap.add_argument("--salt", default="",
                    help="salt string (default: empty)")
    ap.add_argument("--salt-append", action="store_true",
                    help="append salt to password instead of prepending")
    ap.add_argument("--progress-every", type=int, default=0,
                    help="print progress to stderr every N candidates")
    args = ap.parse_args(argv)

    def words(stream):
        n = 0
        for line in stream:
            n += 1
            if args.progress_every and n % args.progress_every == 0:
                print(f"hashcrack: tested {n} candidates...", file=sys.stderr)
            yield line

    try:
        with _open_wordlist(args.wordlist) as fh:
            found = crack(args.hash, words(fh), args.algo,
                          salt=args.salt, salt_append=args.salt_append)
    except FileNotFoundError as e:
        print(f"hashcrack: {e}", file=sys.stderr)
        return 2

    if found is None:
        print("hashcrack: no match in wordlist", file=sys.stderr)
        return 1
    print(found)
    return 0
