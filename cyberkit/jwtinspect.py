"""
jwtinspect — decode, audit, and (optionally) brute-force JWTs.

Audits performed:
  * decode header + payload (handles missing base64 padding)
  * highlight `alg=none` (CVE-2015-9235-style auth bypass)
  * check JWS HS256/HS384/HS512 signature against a candidate secret or
    a wordlist (offline; pure HMAC, no network)
  * spot common red flags: missing `exp`, `exp` in the past, no `kid`
    yet algorithm is asymmetric, etc.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import re
import sys
import time
from typing import NamedTuple

from ._common import bold, cyan, dim, emit_json, green, red, yellow

HS_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


class Decoded(NamedTuple):
    header: dict
    payload: dict
    signature_b64: str
    signing_input: bytes


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def decode_jwt(token: str) -> Decoded:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("not a JWT: expected 3 dot-separated segments")
    h_b64, p_b64, s_b64 = parts
    try:
        header = json.loads(_b64url_decode(h_b64))
        payload = json.loads(_b64url_decode(p_b64))
    except (ValueError, UnicodeDecodeError) as e:
        raise ValueError(f"failed to decode header/payload: {e}") from e
    signing_input = (h_b64 + "." + p_b64).encode("ascii")
    return Decoded(header=header, payload=payload, signature_b64=s_b64,
                   signing_input=signing_input)


def verify_hmac(decoded: Decoded, secret: str) -> bool:
    alg = decoded.header.get("alg", "")
    if alg not in HS_ALGS:
        return False
    digestmod = HS_ALGS[alg]
    mac = hmac.new(secret.encode("utf-8"), decoded.signing_input, digestmod).digest()
    expected = _b64url_encode(mac)
    return hmac.compare_digest(expected, decoded.signature_b64)


def brute_hmac(decoded: Decoded, words) -> str | None:
    """Return the first secret whose HMAC matches, else None."""
    for raw in words:
        s = raw.rstrip("\r\n")
        if not s:
            continue
        if verify_hmac(decoded, s):
            return s
    return None


_SQLI_HINTS = re.compile(r"(['\"]|--|/\*|\bUNION\b|\bSELECT\b|\bOR\s+1\b)", re.I)
_PATH_TRAVERSAL = re.compile(r"\.\.[\\/]|/etc/|%2e%2e", re.I)
_NULL_BYTE = re.compile(r"\x00|%00")


def audit(decoded: Decoded) -> list[tuple[str, str]]:
    """Return list of (severity, message) findings."""
    findings: list[tuple[str, str]] = []
    alg = decoded.header.get("alg", "")
    if alg.lower() == "none":
        findings.append(("CRITICAL",
                         "alg=none — server may accept unsigned tokens (CVE-2015-9235)"))
    if not alg:
        findings.append(("HIGH", "header has no 'alg' field"))
    if alg in HS_ALGS and len(decoded.signature_b64) < 40:
        findings.append(("HIGH", "HMAC signature looks truncated"))

    kid = decoded.header.get("kid")
    if isinstance(kid, str):
        if _SQLI_HINTS.search(kid):
            findings.append(("HIGH",
                             f"'kid' contains SQL-injection-like characters: {kid!r}"))
        if _PATH_TRAVERSAL.search(kid):
            findings.append(("HIGH",
                             f"'kid' looks like a path-traversal payload: {kid!r}"))
        if _NULL_BYTE.search(kid):
            findings.append(("HIGH", "'kid' contains a null byte — file/db lookup trick"))
        if kid.startswith(("/", "\\")) or kid.startswith("http"):
            findings.append(("MED", f"'kid' looks like a path or URL: {kid!r}"))
    elif kid is not None:
        findings.append(("LOW", f"'kid' is not a string ({type(kid).__name__})"))

    for hdr in ("jku", "x5u"):
        url = decoded.header.get(hdr)
        if isinstance(url, str):
            findings.append(("HIGH",
                             f"header has '{hdr}={url}' — verify the URL is on an "
                             f"allowlist (otherwise: trusted-key injection)"))

    if "x5c" in decoded.header:
        findings.append(("MED", "header has 'x5c' (embedded certificate chain) — "
                                  "ensure the server pins to a CA / chain it trusts"))

    exp = decoded.payload.get("exp")
    if exp is None:
        findings.append(("MED", "payload has no 'exp' claim — token never expires"))
    elif isinstance(exp, (int, float)) and exp < time.time():
        findings.append(("LOW", f"token expired at unix={int(exp)}"))

    if alg.startswith(("RS", "ES", "PS")) and "kid" not in decoded.header:
        findings.append(("LOW", "asymmetric alg without 'kid' — key-rollover unfriendly"))

    if "iss" not in decoded.payload:
        findings.append(("LOW", "no 'iss' claim — issuer unverifiable"))
    if "sub" not in decoded.payload:
        findings.append(("LOW", "no 'sub' claim — subject unverifiable"))
    return findings


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="cyberkit jwtinspect",
                                 description="Decode and audit a JWT.")
    ap.add_argument("token", nargs="?", help="JWT (omit to read from stdin)")
    ap.add_argument("--secret", help="verify HMAC signature against this secret")
    ap.add_argument("--brute", help="path to a wordlist of HMAC secrets to try")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args(argv)

    if args.token is None:
        if sys.stdin.isatty():
            ap.error("no token given and stdin is a TTY")
        args.token = sys.stdin.read().strip()

    try:
        decoded = decode_jwt(args.token)
    except ValueError as e:
        print(f"jwtinspect: {e}", file=sys.stderr)
        return 2

    findings = audit(decoded)
    cracked: str | None = None
    verified: bool | None = None
    if args.secret is not None:
        verified = verify_hmac(decoded, args.secret)
    if args.brute:
        try:
            with open(args.brute, "r", encoding="utf-8", errors="replace") as fh:
                cracked = brute_hmac(decoded, fh)
        except FileNotFoundError as e:
            print(f"jwtinspect: {e}", file=sys.stderr)
            return 2

    if args.json:
        emit_json({
            "header": decoded.header,
            "payload": decoded.payload,
            "signature_b64": decoded.signature_b64,
            "findings": [{"severity": s, "msg": m} for s, m in findings],
            "verified": verified,
            "cracked_secret": cracked,
        })
        return 0

    print(bold("header"))
    print("  " + json.dumps(decoded.header, indent=2, ensure_ascii=False).replace("\n", "\n  "))
    print(bold("payload"))
    print("  " + json.dumps(decoded.payload, indent=2, ensure_ascii=False).replace("\n", "\n  "))
    print(bold("signature ") + dim("(base64url, " + str(len(decoded.signature_b64)) + " chars)"))
    print("  " + decoded.signature_b64)

    if verified is not None:
        if verified:
            print(green("\n[+] signature VALID for given secret"))
        else:
            print(red("\n[-] signature INVALID for given secret"))
    if cracked is not None:
        print(green(f"\n[+] cracked HMAC secret: {cracked!r}"))
    elif args.brute:
        print(yellow("\n[-] no HMAC secret in wordlist matched"))

    if findings:
        print(dim("\n" + "-" * 64))
        print(bold("findings:"))
        sev_color = {"CRITICAL": red, "HIGH": red, "MED": yellow, "LOW": cyan}
        for sev, msg in findings:
            print(f"  {sev_color.get(sev, dim)(sev):<10} {msg}")
    return 0
