"""Shared utilities: output formatting, terminal detection, JSON helpers."""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Iterable


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    return os.environ.get("TERM", "") != "dumb"


_COLOR = _supports_color()


def c(text: str, code: str) -> str:
    """Wrap text in an ANSI color code if the terminal supports color."""
    if not _COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def red(s: str) -> str: return c(s, "31")
def green(s: str) -> str: return c(s, "32")
def yellow(s: str) -> str: return c(s, "33")
def blue(s: str) -> str: return c(s, "34")
def magenta(s: str) -> str: return c(s, "35")
def cyan(s: str) -> str: return c(s, "36")
def bold(s: str) -> str: return c(s, "1")
def dim(s: str) -> str: return c(s, "2")


def emit_json(obj: Any) -> None:
    """Print a single JSON document to stdout (UTF-8, no ASCII escaping)."""
    json.dump(obj, sys.stdout, ensure_ascii=False, indent=2, default=str, sort_keys=True)
    sys.stdout.write("\n")


def emit_jsonl(rows: Iterable[Any]) -> None:
    """Stream rows as JSON-Lines."""
    for row in rows:
        json.dump(row, sys.stdout, ensure_ascii=False, default=str, sort_keys=True)
        sys.stdout.write("\n")
        sys.stdout.flush()


def print_table(headers: list[str], rows: list[list[str]], stream=sys.stdout) -> None:
    """Render a simple aligned text table."""
    widths = [len(h) for h in headers]
    for r in rows:
        for i, cell in enumerate(r):
            if i < len(widths):
                widths[i] = max(widths[i], len(str(cell)))
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    stream.write(bold(fmt.format(*headers)) + "\n")
    stream.write(dim("  ".join("-" * w for w in widths)) + "\n")
    for r in rows:
        stream.write(fmt.format(*[str(x) for x in r]) + "\n")
