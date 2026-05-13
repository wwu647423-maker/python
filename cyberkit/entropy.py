"""
entropy — Shannon entropy analysis of a file.

Reports the file's global entropy (bits/byte; 8.0 = uniform random) and a
windowed entropy series across the file. High and remarkably *flat*
entropy across many windows is a fingerprint of encrypted or compressed
content (vs. packed executables which often show entropy ramps).

A simple ASCII spark-line lets you see at a glance where the boring
sections end and the high-entropy payload begins.
"""

from __future__ import annotations

import argparse
import math
import sys

from ._common import bold, cyan, dim, emit_json, green, red, yellow

SPARK = "▁▂▃▄▅▆▇█"

MAGIC: list[tuple[bytes, str]] = [
    (b"\x7fELF",             "ELF executable"),
    (b"MZ",                  "DOS/PE executable (Windows .exe/.dll)"),
    (b"\xca\xfe\xba\xbe",    "Mach-O fat binary or Java class file"),
    (b"\xcf\xfa\xed\xfe",    "Mach-O 64-bit (little-endian)"),
    (b"\xfe\xed\xfa\xce",    "Mach-O 32-bit (big-endian)"),
    (b"PK\x03\x04",          "ZIP archive (jar/apk/odf/docx/xlsx/...)"),
    (b"PK\x05\x06",          "ZIP archive (empty)"),
    (b"\x1f\x8b\x08",         "gzip-compressed data"),
    (b"BZh",                 "bzip2 archive"),
    (b"\xfd7zXZ\x00",        "xz archive"),
    (b"7z\xbc\xaf\x27\x1c",  "7z archive"),
    (b"Rar!\x1a\x07",        "RAR archive"),
    (b"\x89PNG\r\n\x1a\n",   "PNG image"),
    (b"\xff\xd8\xff",         "JPEG image"),
    (b"GIF87a",               "GIF87a image"),
    (b"GIF89a",               "GIF89a image"),
    (b"%PDF-",                "PDF document"),
    (b"OggS",                 "Ogg container"),
    (b"ID3",                  "MP3 (ID3)"),
    (b"RIFF",                 "RIFF container (WAV/AVI/WEBP)"),
    (b"\x00\x00\x01\xba",     "MPEG program stream"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"BMP",                  "BMP image (rare)"),
    (b"BM",                   "BMP image"),
    (b"-----BEGIN ",          "PEM-encoded artifact (cert / key / CSR)"),
    (b"{\\rtf",               "RTF document"),
    (b"<?xml",                "XML"),
    (b"<!DOCTYPE",            "HTML / DTD"),
    (b"<html",                "HTML"),
    (b"#!",                   "shebang script"),
]


def detect_magic(data: bytes) -> str:
    head = data[:64]
    for sig, label in MAGIC:
        if head.startswith(sig):
            return label
    if head and all(0x20 <= b < 0x7f or b in (9, 10, 13) for b in head):
        return "ASCII / UTF-8 text (no magic match)"
    return "unknown / no magic match"


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    total = len(data)
    h = 0.0
    for c in freq:
        if c:
            p = c / total
            h -= p * math.log2(p)
    return h


def windowed_entropy(data: bytes, window: int) -> list[float]:
    return [shannon_entropy(data[i:i + window])
            for i in range(0, len(data), window)]


def _sparkline(values: list[float], lo: float = 0.0, hi: float = 8.0) -> str:
    if not values:
        return ""
    step = (hi - lo) / (len(SPARK) - 1)
    chars = []
    for v in values:
        idx = max(0, min(len(SPARK) - 1, int((v - lo) / step)))
        chars.append(SPARK[idx])
    return "".join(chars)


def classify(global_h: float) -> str:
    if global_h >= 7.5: return "encrypted / compressed (very high entropy)"
    if global_h >= 6.5: return "likely compressed or partially encrypted"
    if global_h >= 5.0: return "structured binary (executables, media)"
    if global_h >= 3.0: return "mostly text / structured data"
    return "very low entropy (sparse / padded)"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="cyberkit entropy",
                                 description="Shannon entropy analysis with windowed view.")
    ap.add_argument("path", help="file to analyze (use - for stdin)")
    ap.add_argument("-w", "--window", type=int, default=4096,
                    help="window size in bytes (default: 4096)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.path == "-":
        data = sys.stdin.buffer.read()
    else:
        try:
            with open(args.path, "rb") as fh:
                data = fh.read()
        except OSError as e:
            print(f"entropy: {e}", file=sys.stderr)
            return 2

    if args.window < 16:
        print("entropy: --window must be >= 16", file=sys.stderr)
        return 2

    global_h = shannon_entropy(data)
    win_h = windowed_entropy(data, args.window)
    magic = detect_magic(data)

    if args.json:
        emit_json({
            "path": args.path,
            "size": len(data),
            "global_entropy": round(global_h, 4),
            "window": args.window,
            "windows": [round(v, 4) for v in win_h],
            "classification": classify(global_h),
            "magic": magic,
        })
        return 0

    if global_h >= 7.5: col = red
    elif global_h >= 5.0: col = yellow
    else: col = green

    print(f"{bold('file')}            {args.path}")
    print(f"{bold('size')}            {len(data):,} bytes")
    print(f"{bold('magic')}           {cyan(magic)}")
    print(f"{bold('global entropy')}  {col(f'{global_h:.4f}')} bits/byte  "
          f"({col(classify(global_h))})")
    print(f"{bold('window')}          {args.window} bytes, {len(win_h)} windows")
    print(dim("-" * 64))

    if win_h:
        spark = _sparkline(win_h)
        if len(spark) > 70:
            step = max(1, len(spark) // 70)
            spark = spark[::step]
        print(f"{bold('shape')}  {cyan(spark)}")
        print(dim("       (0.0 .................................................. 8.0)"))
        hi = max(win_h)
        lo = min(win_h)
        print(f"{bold('range')}  min={green(f'{lo:.3f}')}  max={red(f'{hi:.3f}')}  "
              f"mean={cyan(f'{sum(win_h)/len(win_h):.3f}')}")
    return 0
