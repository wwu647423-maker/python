"""
hexview — clean hex+ASCII dump (xxd / hexdump -C compatible layout).
"""

from __future__ import annotations

import argparse
import sys

from ._common import cyan, dim, green


def hexdump(data: bytes, offset: int = 0, width: int = 16) -> str:
    """Return a multi-line hex+ASCII dump rendering."""
    lines: list[str] = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_parts = []
        for j, b in enumerate(chunk):
            hex_parts.append(f"{b:02x}")
            if j == width // 2 - 1:
                hex_parts.append("")
        hex_field = " ".join(hex_parts).ljust(width * 3 + 1)
        ascii_field = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset + i:08x}  {hex_field} |{ascii_field}|")
    return "\n".join(lines)


def hexdump_color(data: bytes, offset: int = 0, width: int = 16) -> str:
    lines: list[str] = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_parts = []
        for j, b in enumerate(chunk):
            hex_parts.append(f"{b:02x}")
            if j == width // 2 - 1:
                hex_parts.append("")
        hex_field = " ".join(hex_parts).ljust(width * 3 + 1)
        ascii_field = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{dim(f'{offset + i:08x}')}  {cyan(hex_field)} |{green(ascii_field)}|")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="cyberkit hexview",
                                 description="Hex+ASCII dump.")
    ap.add_argument("path", nargs="?",
                    help="file path (use - or omit to read stdin)")
    ap.add_argument("-o", "--offset", type=int, default=0,
                    help="byte offset to start from")
    ap.add_argument("-n", "--length", type=int, default=None,
                    help="number of bytes to dump (default: all)")
    ap.add_argument("-w", "--width", type=int, default=16,
                    help="bytes per row (default: 16)")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args(argv)

    if args.path is None or args.path == "-":
        data = sys.stdin.buffer.read()
    else:
        try:
            with open(args.path, "rb") as fh:
                if args.offset:
                    fh.seek(args.offset)
                data = fh.read(args.length) if args.length is not None else fh.read()
        except OSError as e:
            print(f"hexview: {e}", file=sys.stderr)
            return 2

    if args.width not in (8, 16, 24, 32):
        print("hexview: --width must be 8, 16, 24, or 32", file=sys.stderr)
        return 2

    fn = hexdump if args.no_color else hexdump_color
    sys.stdout.write(fn(data, offset=args.offset, width=args.width) + "\n")
    return 0
