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

    if args.json:
        emit_json({
            "path": args.path,
            "size": len(data),
            "global_entropy": round(global_h, 4),
            "window": args.window,
            "windows": [round(v, 4) for v in win_h],
            "classification": classify(global_h),
        })
        return 0

    if global_h >= 7.5: col = red
    elif global_h >= 5.0: col = yellow
    else: col = green

    print(f"{bold('file')}            {args.path}")
    print(f"{bold('size')}            {len(data):,} bytes")
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
