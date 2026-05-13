"""
Top-level dispatcher.

Usage:
    python -m cyberkit <subcommand> [args...]
    python -m cyberkit -h
"""

from __future__ import annotations

import argparse
import importlib
import sys

from . import __version__

DISPATCH: dict[str, tuple[str, str]] = {
    "portscan":    ("cyberkit.portscan",    "Concurrent TCP connect scanner with banner grab"),
    "dnsenum":     ("cyberkit.dnsenum",     "DNS recon: record dump, AXFR, subdomain brute"),
    "dirfuzz":     ("cyberkit.dirfuzz",     "HTTP content discovery with 404 fingerprinting"),
    "httpprobe":   ("cyberkit.httpprobe",   "HTTP fingerprinting & tech detection"),
    "certinspect": ("cyberkit.certinspect", "TLS certificate inspection & expiry / hostname checks"),
    "hashid":      ("cyberkit.hashid",      "Identify hash type from length/charset/structure"),
    "hashcrack":   ("cyberkit.hashcrack",   "Wordlist crack of md5/sha1/sha256/sha512/ntlm (+--rules)"),
    "pwdaudit":    ("cyberkit.pwdaudit",    "Password strength + HIBP k-anonymity breach lookup"),
    "jwtinspect":  ("cyberkit.jwtinspect",  "Decode JWTs; flag alg=none; brute HS256 secrets"),
    "xorcrack":    ("cyberkit.xorcrack",    "XOR encrypt/decrypt; single-byte and repeating-key recovery"),
    "baseconv":    ("cyberkit.baseconv",    "Encode / decode / auto-detect base16/32/58/64/85/url/rot"),
    "secrets":     ("cyberkit.secrets",     "Scan files/dirs for hardcoded credentials and tokens"),
    "entropy":     ("cyberkit.entropy",     "Shannon entropy of a file with windowed analysis"),
    "hexview":     ("cyberkit.hexview",     "Hex+ASCII dump with offset/length controls"),
}


def _print_help() -> None:
    print("cyberkit  —  pure-stdlib offensive-security toolkit  (v" + __version__ + ")")
    print()
    print("usage: python -m cyberkit <subcommand> [args...]")
    print()
    print("subcommands:")
    width = max(len(k) for k in DISPATCH)
    for name, (_mod, desc) in DISPATCH.items():
        print(f"  {name:<{width}}  {desc}")
    print()
    print("run  python -m cyberkit <subcommand> -h  for module-specific options.")


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        _print_help()
        return 0
    if argv[0] in ("-V", "--version"):
        print(__version__)
        return 0

    name = argv[0]
    if name not in DISPATCH:
        print(f"cyberkit: unknown subcommand {name!r}", file=sys.stderr)
        print("run  python -m cyberkit -h  for the list.", file=sys.stderr)
        return 2

    module_name = DISPATCH[name][0]
    module = importlib.import_module(module_name)
    if not hasattr(module, "main"):
        print(f"cyberkit: module {module_name} has no main()", file=sys.stderr)
        return 2
    try:
        return int(module.main(argv[1:]) or 0)
    except KeyboardInterrupt:
        print("\ncyberkit: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
