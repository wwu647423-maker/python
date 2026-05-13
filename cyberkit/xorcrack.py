"""
xorcrack — XOR cipher tooling.

Modes:
  encrypt / decrypt          : raw XOR with a given key (XOR is symmetric)
  brute-single               : try all 256 single-byte keys and rank
                                plaintexts by English letter frequency
  brute-repeating            : recover a multi-byte repeating key, no
                                known plaintext required:
                                1. estimate key length via normalized
                                    Hamming distance (Kasiski / FMS)
                                2. for each column, run brute-single
                                3. concatenate column keys

The plaintext scoring is a chi-squared distance to English letter
frequencies, with bonuses for printable ASCII / spaces.
"""

from __future__ import annotations

import argparse
import binascii
import math
import string
import sys
from typing import NamedTuple

from ._common import bold, cyan, dim, emit_json, green, yellow

ENGLISH_FREQ = {
    'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702,
    'f': 2.228, 'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153,
    'k': 0.772, 'l': 4.025, 'm': 2.406, 'n': 6.749, 'o': 7.507,
    'p': 1.929, 'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
    'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150, 'y': 1.974,
    'z': 0.074, ' ': 13.000,
}

PRINTABLE = set((string.ascii_letters + string.digits + string.punctuation + " \t\n\r").encode())


def xor(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("empty key")
    out = bytearray(len(data))
    klen = len(key)
    for i, b in enumerate(data):
        out[i] = b ^ key[i % klen]
    return bytes(out)


def score_english(b: bytes) -> float:
    """Lower is more English-like. ~0 is perfect; >100 is gibberish.

    Combines three signals:
      1. Printable-ASCII ratio (must clear an 85% floor).
      2. English letter+space coverage (a wrong-key XOR result often
         maps real letters onto digits/punctuation; the letter ratio
         collapses and we detect it).
      3. Chi-squared distance to standard English frequencies,
         normalized by sample size so it doesn't grow unbounded.
    """
    if not b:
        return 1e9
    n = len(b)

    printable = sum(1 for c in b if c in PRINTABLE)
    if printable / n < 0.85:
        return 1e6 + (n - printable)

    counts = {ch: 0 for ch in ENGLISH_FREQ}
    letter_count = 0
    for c in b:
        ch = chr(c).lower() if c < 128 else ""
        if ch in counts:
            counts[ch] += 1
            letter_count += 1

    letter_ratio = letter_count / n
    if letter_ratio < 0.55:
        return 10000.0 + (1.0 - letter_ratio) * 1000.0

    chi2 = 0.0
    for ch, freq in ENGLISH_FREQ.items():
        observed = counts[ch]
        expected = (freq / 100.0) * letter_count
        if expected > 0:
            chi2 += (observed - expected) ** 2 / expected
    return chi2 / max(1, letter_count) * 100.0


class SingleByteResult(NamedTuple):
    key: int
    score: float
    plaintext: bytes


def brute_single(data: bytes, top: int = 5) -> list[SingleByteResult]:
    out: list[SingleByteResult] = []
    for k in range(256):
        pt = xor(data, bytes([k]))
        out.append(SingleByteResult(k, score_english(pt), pt))
    out.sort(key=lambda r: r.score)
    return out[:top]


def _hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def estimate_keysize(data: bytes, kmin: int = 2, kmax: int = 40,
                     max_blocks: int = 32) -> list[tuple[int, float]]:
    """Return [(keysize, normalized_hamming)] sorted by best.

    For each candidate keysize K we average the normalized Hamming distance
    over every pair drawn from up to `max_blocks` consecutive K-byte blocks.
    Using more than ~4 blocks dramatically reduces noise vs. the canonical
    Cryptopals approach.
    """
    out: list[tuple[int, float]] = []
    for ks in range(kmin, kmax + 1):
        n = min(len(data) // ks, max_blocks)
        if n < 2:
            continue
        chunks = [data[i * ks:(i + 1) * ks] for i in range(n)]
        pairs: list[float] = []
        for i in range(n):
            for j in range(i + 1, n):
                pairs.append(_hamming(chunks[i], chunks[j]) / ks)
        out.append((ks, sum(pairs) / len(pairs)))
    out.sort(key=lambda x: x[1])
    return out


def _smallest_period(key: bytes) -> bytes:
    """If the key is periodic (e.g. b'ICEICE' has period 3), return the unit."""
    n = len(key)
    for p in range(1, n + 1):
        if n % p == 0 and key[:p] * (n // p) == key:
            return key[:p]
    return key


def brute_repeating(data: bytes, kmin: int = 2, kmax: int = 40,
                    try_top: int = 8) -> tuple[bytes, bytes]:
    """Recover the repeating-XOR key. Returns (key, plaintext).

    The returned key is reduced to its smallest period so we never report
    e.g. b'ICEICE' when the true key is b'ICE'.
    """
    candidates = estimate_keysize(data, kmin, kmax)
    if not candidates:
        raise ValueError("data too short for repeating-key recovery")

    best_key: bytes = b""
    best_score: float = math.inf
    best_pt: bytes = b""
    for ks, _norm in candidates[:try_top]:
        cols = [bytes(data[i::ks]) for i in range(ks)]
        key = bytearray(ks)
        for i, col in enumerate(cols):
            key[i] = brute_single(col, top=1)[0].key
        pt = xor(data, bytes(key))
        s = score_english(pt)
        if s < best_score:
            best_score = s
            best_key = bytes(key)
            best_pt = pt
    return _smallest_period(best_key), best_pt


def _parse_key(arg: str, hex_mode: bool) -> bytes:
    if hex_mode:
        try:
            return binascii.unhexlify(arg)
        except (binascii.Error, ValueError) as e:
            raise SystemExit(f"xorcrack: invalid hex key: {e}")
    return arg.encode("utf-8")


def _read_input(path: str | None, hex_mode: bool) -> bytes:
    if path is None or path == "-":
        raw = sys.stdin.buffer.read()
    else:
        with open(path, "rb") as fh:
            raw = fh.read()
    if hex_mode:
        cleaned = bytes(b for b in raw if b not in b" \r\n\t")
        try:
            return binascii.unhexlify(cleaned)
        except (binascii.Error, ValueError) as e:
            raise SystemExit(f"xorcrack: input is not valid hex: {e}")
    return raw


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="cyberkit xorcrack",
                                 description="XOR cipher: encrypt/decrypt or recover unknown key.")
    sub = ap.add_subparsers(dest="mode", required=True)

    p_enc = sub.add_parser("crypt", help="XOR data with a known key (encrypt == decrypt)")
    p_enc.add_argument("-i", "--input", help="input file (default: stdin)")
    p_enc.add_argument("-k", "--key", required=True, help="key string")
    p_enc.add_argument("--hex-key", action="store_true", help="treat --key as hex")
    p_enc.add_argument("--hex-in", action="store_true", help="input is hex")
    p_enc.add_argument("--hex-out", action="store_true", help="emit hex output")

    p_s = sub.add_parser("brute-single", help="recover a single-byte XOR key")
    p_s.add_argument("-i", "--input", help="input file (default: stdin)")
    p_s.add_argument("--hex-in", action="store_true", help="input is hex")
    p_s.add_argument("-n", "--top", type=int, default=5, help="show top-N candidates")
    p_s.add_argument("--json", action="store_true")

    p_r = sub.add_parser("brute-repeating", help="recover a multi-byte repeating XOR key")
    p_r.add_argument("-i", "--input", help="input file (default: stdin)")
    p_r.add_argument("--hex-in", action="store_true", help="input is hex")
    p_r.add_argument("--kmin", type=int, default=2)
    p_r.add_argument("--kmax", type=int, default=40)
    p_r.add_argument("--json", action="store_true")

    args = ap.parse_args(argv)

    if args.mode == "crypt":
        data = _read_input(args.input, args.hex_in)
        key = _parse_key(args.key, args.hex_key)
        out = xor(data, key)
        if args.hex_out:
            sys.stdout.write(out.hex() + "\n")
        else:
            sys.stdout.buffer.write(out)
        return 0

    if args.mode == "brute-single":
        data = _read_input(args.input, args.hex_in)
        results = brute_single(data, top=args.top)
        if args.json:
            emit_json([{"key": r.key, "score": r.score,
                        "plaintext": r.plaintext.decode("latin-1", "replace")}
                       for r in results])
            return 0
        print(f"{bold('top')} {len(results)} {bold('candidates (lower score = more English):')}\n")
        for r in results:
            preview = r.plaintext[:60].decode("latin-1", "replace")
            preview = preview.replace("\n", "\\n").replace("\r", "")
            print(f"  key=0x{r.key:02x} {dim(f'({r.key!r})'):<10} "
                  f"score={green(f'{r.score:7.2f}')}   "
                  f"plain={cyan(preview)}")
        return 0

    if args.mode == "brute-repeating":
        data = _read_input(args.input, args.hex_in)
        try:
            key, pt = brute_repeating(data, kmin=args.kmin, kmax=args.kmax)
        except ValueError as e:
            print(f"xorcrack: {e}", file=sys.stderr)
            return 2
        if args.json:
            emit_json({"key_hex": key.hex(),
                        "key_ascii": key.decode("latin-1", "replace"),
                        "plaintext": pt.decode("latin-1", "replace")})
            return 0
        print(f"{bold('recovered key')}     {green(key.decode('latin-1', 'replace'))}  "
              f"{dim('(' + key.hex() + ')')}")
        print(f"{bold('keysize')}           {len(key)}")
        print(f"{bold('plaintext score')}   {score_english(pt):.2f} {dim('(chi^2)')}")
        print(dim("-" * 64))
        sys.stdout.flush()
        sys.stdout.buffer.write(pt[:4096])
        sys.stdout.buffer.flush()
        if len(pt) > 4096:
            sys.stdout.write(yellow("\n[truncated to 4096 bytes]\n"))
        else:
            sys.stdout.write("\n")
        return 0

    return 2
