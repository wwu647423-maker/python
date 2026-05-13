"""
hashcrack — wordlist-based hash recovery for common unsalted algorithms.

Supported: md5, sha1, sha224, sha256, sha384, sha512, ntlm.
For salted constructions use --salt (prepended by default; --salt-append
to append). With --rules, expand each wordlist entry with common
hashcat-style mutations (toggle case, append digits, leet-substitute,
year suffixes, etc.) before testing.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from typing import Callable, Iterable, Iterator

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


_LEET_MAP = str.maketrans({"a": "@", "A": "@", "e": "3", "E": "3",
                            "i": "1", "I": "1", "o": "0", "O": "0",
                            "s": "$", "S": "$", "t": "7", "T": "7"})

_DIGIT_SUFFIXES = ["1", "2", "3", "12", "123", "1234", "!", "!!", "."]
_YEAR_SUFFIXES = [str(y) for y in range(2018, 2027)]


def mutate(word: str) -> Iterator[str]:
    """Yield common password mutations of `word`. Order matters: cheap variants first."""
    if not word:
        return
    yield word
    if word.lower() != word:
        yield word.lower()
    if word.upper() != word:
        yield word.upper()
    cap = word[:1].upper() + word[1:].lower()
    if cap != word:
        yield cap

    base_variants = [word, word.lower(), cap]
    seen = {word, word.lower(), word.upper(), cap}
    for base in base_variants:
        for suf in _DIGIT_SUFFIXES + _YEAR_SUFFIXES:
            cand = base + suf
            if cand not in seen:
                seen.add(cand)
                yield cand
        rev = base[::-1]
        if rev not in seen:
            seen.add(rev)
            yield rev

    leet = word.translate(_LEET_MAP)
    if leet not in seen:
        seen.add(leet)
        yield leet
    cap_leet = cap.translate(_LEET_MAP)
    if cap_leet not in seen:
        seen.add(cap_leet)
        yield cap_leet


def expand(words: Iterable[str], rules: bool) -> Iterator[str]:
    for raw in words:
        w = raw.rstrip("\r\n")
        if not w:
            continue
        if not rules:
            yield w
            continue
        yield from mutate(w)


def crack(target: str, words: Iterable[str], algo: str,
          salt: str = "", salt_append: bool = False,
          rules: bool = False) -> str | None:
    """Return the first candidate whose digest matches `target`, else None."""
    if algo not in ALGOS:
        raise ValueError(f"unsupported algorithm: {algo}")
    fn = ALGOS[algo]
    target = target.strip().lower()
    sbytes = salt.encode("utf-8")
    for cand in expand(words, rules):
        wbytes = cand.encode("utf-8")
        full = wbytes + sbytes if salt_append else sbytes + wbytes
        if fn(full) == target:
            return cand
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
    ap.add_argument("--rules", action="store_true",
                    help="expand each wordlist entry with common mutations "
                         "(case toggles, digit/year/symbol suffixes, leet substitutions, reversed)")
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
                          salt=args.salt, salt_append=args.salt_append,
                          rules=args.rules)
    except FileNotFoundError as e:
        print(f"hashcrack: {e}", file=sys.stderr)
        return 2

    if found is None:
        print("hashcrack: no match in wordlist", file=sys.stderr)
        return 1
    print(found)
    return 0
