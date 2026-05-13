"""
baseconv — multi-encoding decoder/encoder with auto-detect.

Encodings supported:
    base16 (hex), base32, base58 (Bitcoin alphabet), base64, base64url, base85,
    url, html-entity, rot13, rot_n (any 0..25 shift).

Auto-detect tries every decoder, scores each output by printable-ASCII
ratio + English-letter density + word-boundary heuristics, and ranks the
plausible candidates. Useful for the typical CTF chain of "this is
base64-of-base32-of-rot13-of-..."
"""

from __future__ import annotations

import argparse
import base64
import binascii
import codecs
import html
import re
import string
import sys
import urllib.parse

from ._common import bold, cyan, dim, emit_json, green, print_table, yellow

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def encode_base16(b: bytes) -> str: return base64.b16encode(b).decode("ascii")
def encode_base32(b: bytes) -> str: return base64.b32encode(b).decode("ascii")
def encode_base64(b: bytes) -> str: return base64.b64encode(b).decode("ascii")
def encode_base64url(b: bytes) -> str: return base64.urlsafe_b64encode(b).decode("ascii")
def encode_base85(b: bytes) -> str: return base64.b85encode(b).decode("ascii")


def encode_base58(b: bytes) -> str:
    n = int.from_bytes(b, "big") if b else 0
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = B58_ALPHABET[r] + out
    pad = 0
    for byte in b:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + out if out else ("1" * pad or "1")


def decode_base58(s: str) -> bytes:
    s = s.strip()
    n = 0
    for ch in s:
        idx = B58_ALPHABET.find(ch)
        if idx < 0:
            raise ValueError(f"invalid base58 char: {ch!r}")
        n = n * 58 + idx
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + raw


def encode_url(b: bytes) -> str:
    return urllib.parse.quote(b, safe="")


def decode_url(s: str) -> bytes:
    return urllib.parse.unquote_to_bytes(s)


def encode_html(b: bytes) -> str:
    return html.escape(b.decode("utf-8", errors="replace"))


def decode_html(s: str) -> bytes:
    return html.unescape(s).encode("utf-8")


def rot_n(s: str, n: int) -> str:
    out = []
    for ch in s:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") + n) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") + n) % 26 + ord("A")))
        else:
            out.append(ch)
    return "".join(out)


ENCODERS = {
    "base16":    lambda b: encode_base16(b),
    "base32":    lambda b: encode_base32(b),
    "base58":    lambda b: encode_base58(b),
    "base64":    lambda b: encode_base64(b),
    "base64url": lambda b: encode_base64url(b),
    "base85":    lambda b: encode_base85(b),
    "url":       lambda b: encode_url(b),
    "html":      lambda b: encode_html(b),
}


def _pad_b64(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def decode_base16(s: str) -> bytes: return base64.b16decode(s.strip(), casefold=True)
def decode_base32(s: str) -> bytes: return base64.b32decode(_pad_b64(s.strip().upper()), casefold=True)
def decode_base64(s: str) -> bytes: return base64.b64decode(_pad_b64(s.strip()), validate=False)
def decode_base64url(s: str) -> bytes: return base64.urlsafe_b64decode(_pad_b64(s.strip()))
def decode_base85(s: str) -> bytes: return base64.b85decode(s.strip())


DECODERS = {
    "base16":    decode_base16,
    "base32":    decode_base32,
    "base58":    decode_base58,
    "base64":    decode_base64,
    "base64url": decode_base64url,
    "base85":    decode_base85,
    "url":       decode_url,
    "html":      decode_html,
}


PRINTABLE = set((string.ascii_letters + string.digits + string.punctuation + " \t\n\r").encode())
_COMMON_WORDS = re.compile(r"\b(the|and|of|to|in|is|that|it|for|on|with|as|by|at|this|be)\b", re.I)


def _score_plaintext(b: bytes) -> float:
    """Higher score = more plausible English. Negative = junk."""
    if not b:
        return -1e6
    printable = sum(1 for c in b if c in PRINTABLE) / len(b)
    if printable < 0.7:
        return -1e3 + printable * 1000
    text = b.decode("utf-8", errors="replace")
    letters = sum(1 for c in text if c.isalpha()) / len(text)
    spaces = sum(1 for c in text if c == " ") / len(text)
    words = len(_COMMON_WORDS.findall(text))
    return printable * 100 + letters * 80 + spaces * 60 + words * 25 - (1 - printable) * 200


def autodetect(s: str) -> list[tuple[str, bytes, float]]:
    """Try every decoder, return ranked [(method, bytes, score)] candidates."""
    results: list[tuple[str, bytes, float]] = []
    for name, fn in DECODERS.items():
        try:
            decoded = fn(s)
        except (ValueError, binascii.Error, UnicodeDecodeError):
            continue
        if decoded == s.encode("utf-8", errors="replace"):
            continue
        results.append((name, decoded, _score_plaintext(decoded)))

    for n in range(1, 26):
        rotated = rot_n(s, n)
        scored = _score_plaintext(rotated.encode("utf-8", errors="replace"))
        if scored > 100:
            results.append((f"rot{n}", rotated.encode("utf-8", errors="replace"), scored))

    results.sort(key=lambda x: -x[2])
    return results


def _read_input(args) -> bytes:
    if args.input:
        return args.input.encode("utf-8")
    return sys.stdin.buffer.read()


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="cyberkit baseconv",
                                 description="Encode / decode / auto-detect text encodings.")
    sub = ap.add_subparsers(dest="mode", required=True)

    enc = sub.add_parser("encode")
    enc.add_argument("scheme", choices=sorted(ENCODERS))
    enc.add_argument("-i", "--input", help="literal string (default: stdin bytes)")

    dec = sub.add_parser("decode")
    dec.add_argument("scheme", choices=list(DECODERS) + ["rot"])
    dec.add_argument("-i", "--input", help="literal string (default: stdin text)")
    dec.add_argument("--shift", type=int, default=13,
                     help="rot shift (default: 13, only used for 'rot')")
    dec.add_argument("--raw", action="store_true",
                     help="write decoded bytes to stdout instead of decoding to text")

    auto = sub.add_parser("auto")
    auto.add_argument("-i", "--input", help="literal string (default: stdin text)")
    auto.add_argument("-n", "--top", type=int, default=8)
    auto.add_argument("--json", action="store_true")

    args = ap.parse_args(argv)

    if args.mode == "encode":
        data = _read_input(args)
        sys.stdout.write(ENCODERS[args.scheme](data) + "\n")
        return 0

    if args.mode == "decode":
        if args.scheme == "rot":
            text = args.input if args.input is not None else sys.stdin.read()
            sys.stdout.write(rot_n(text, args.shift) + "\n")
            return 0
        text = args.input if args.input is not None else sys.stdin.read().strip()
        try:
            decoded = DECODERS[args.scheme](text)
        except (ValueError, binascii.Error) as e:
            print(f"baseconv: {e}", file=sys.stderr)
            return 2
        if args.raw:
            sys.stdout.buffer.write(decoded)
        else:
            sys.stdout.write(decoded.decode("utf-8", errors="replace"))
            if not decoded.endswith(b"\n"):
                sys.stdout.write("\n")
        return 0

    if args.mode == "auto":
        text = args.input if args.input is not None else sys.stdin.read().strip()
        cands = autodetect(text)[:args.top]
        if args.json:
            emit_json([{"method": m, "score": round(s, 2),
                        "decoded": d.decode("utf-8", errors="replace")}
                       for m, d, s in cands])
            return 0
        if not cands:
            print(yellow("no plausible decoding found"))
            return 1
        print(f"{bold('input')} {text[:80]}{'…' if len(text) > 80 else ''}")
        print(dim("-" * 64))
        rows = []
        for method, decoded, score in cands:
            preview = decoded.decode("utf-8", errors="replace").replace("\n", "\\n")
            if len(preview) > 60:
                preview = preview[:60] + "…"
            tag = green(f"{score:7.1f}") if score >= 100 else cyan(f"{score:7.1f}")
            rows.append([tag, method, preview])
        print_table(["SCORE", "METHOD", "PREVIEW"], rows)
        return 0

    return 2
