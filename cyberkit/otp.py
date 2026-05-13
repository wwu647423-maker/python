"""
otp — HOTP (RFC 4226) and TOTP (RFC 6238) generation and verification.

Pure stdlib; works with any base32-encoded shared secret as exported by
google-authenticator / authy / 1password style otpauth:// URIs.

Verification supports a configurable time skew window (default ±1 step,
i.e. ±30 seconds) so a code generated a moment ago still validates.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import struct
import sys
import time
import urllib.parse
from typing import NamedTuple

from ._common import bold, cyan, dim, emit_json, green, red, yellow

HASH_BY_NAME = {
    "SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512,
}


def _b32_decode(secret: str) -> bytes:
    s = secret.strip().replace(" ", "").replace("-", "").upper()
    s += "=" * (-len(s) % 8)
    return base64.b32decode(s, casefold=True)


def hotp(secret: bytes, counter: int, digits: int = 6,
         algorithm: str = "SHA1") -> str:
    """Compute the HOTP code for a counter value (RFC 4226 §5.3)."""
    digestmod = HASH_BY_NAME[algorithm.upper()]
    msg = struct.pack(">Q", counter)
    mac = hmac.new(secret, msg, digestmod).digest()
    offset = mac[-1] & 0x0F
    truncated = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10 ** digits)).zfill(digits)


def totp(secret: bytes, now: float | None = None, step: int = 30,
         t0: int = 0, digits: int = 6, algorithm: str = "SHA1") -> str:
    """Compute the TOTP code at `now` (default: real wall-clock UTC)."""
    if now is None:
        now = time.time()
    counter = int((now - t0) // step)
    return hotp(secret, counter, digits=digits, algorithm=algorithm)


class Verification(NamedTuple):
    valid: bool
    matched_skew: int | None


def verify_totp(secret: bytes, code: str, window: int = 1,
                now: float | None = None, step: int = 30,
                digits: int = 6, algorithm: str = "SHA1") -> Verification:
    """Constant-time-ish check across [-window, +window] step offsets."""
    if now is None:
        now = time.time()
    counter = int(now // step)
    code = code.strip()
    matched: int | None = None
    valid = False
    for skew in range(-window, window + 1):
        try:
            cand = hotp(secret, counter + skew, digits=digits, algorithm=algorithm)
        except Exception:
            continue
        if hmac.compare_digest(cand, code):
            valid = True
            matched = skew
            break
    return Verification(valid=valid, matched_skew=matched)


def parse_otpauth(uri: str) -> dict:
    """Decode an otpauth://totp/<label>?secret=...&issuer=... URI."""
    if not uri.startswith("otpauth://"):
        raise ValueError("not an otpauth:// URI")
    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme != "otpauth":
        raise ValueError("scheme must be otpauth")
    kind = parsed.netloc
    if kind not in ("totp", "hotp"):
        raise ValueError(f"unsupported otpauth type: {kind}")
    params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
    label = urllib.parse.unquote(parsed.path.lstrip("/"))
    return {
        "type": kind,
        "label": label,
        "secret": params.get("secret", ""),
        "issuer": params.get("issuer", ""),
        "algorithm": params.get("algorithm", "SHA1").upper(),
        "digits": int(params.get("digits", "6")),
        "period": int(params.get("period", "30")),
        "counter": int(params.get("counter", "0")),
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="cyberkit otp",
                                 description="Generate / verify TOTP / HOTP codes.")
    sub = ap.add_subparsers(dest="mode", required=True)

    g = sub.add_parser("gen", help="generate current TOTP code")
    g.add_argument("secret", help="base32 secret or otpauth:// URI")
    g.add_argument("--digits", type=int, default=6)
    g.add_argument("--step", type=int, default=30)
    g.add_argument("--algo", default="SHA1", choices=list(HASH_BY_NAME))
    g.add_argument("--at", type=float, default=None,
                   help="unix timestamp instead of now (testing)")
    g.add_argument("--json", action="store_true")

    h = sub.add_parser("hotp", help="generate HOTP code for an explicit counter")
    h.add_argument("secret")
    h.add_argument("counter", type=int)
    h.add_argument("--digits", type=int, default=6)
    h.add_argument("--algo", default="SHA1", choices=list(HASH_BY_NAME))

    v = sub.add_parser("verify", help="verify a TOTP code with skew tolerance")
    v.add_argument("secret")
    v.add_argument("code")
    v.add_argument("-w", "--window", type=int, default=1,
                   help="±N steps tolerated (default 1 → ±30s)")
    v.add_argument("--step", type=int, default=30)
    v.add_argument("--digits", type=int, default=6)
    v.add_argument("--algo", default="SHA1", choices=list(HASH_BY_NAME))

    p = sub.add_parser("parse", help="parse an otpauth:// URI into JSON")
    p.add_argument("uri")

    args = ap.parse_args(argv)

    if args.mode == "gen":
        secret_str = args.secret
        digits, step, algo = args.digits, args.step, args.algo
        if secret_str.startswith("otpauth://"):
            try:
                info = parse_otpauth(secret_str)
            except ValueError as e:
                print(f"otp: {e}", file=sys.stderr); return 2
            secret_str = info["secret"]
            digits, step, algo = info["digits"], info["period"], info["algorithm"]
        try:
            secret = _b32_decode(secret_str)
        except Exception as e:
            print(f"otp: invalid base32 secret: {e}", file=sys.stderr); return 2
        now = args.at if args.at is not None else time.time()
        code = totp(secret, now=now, step=step, digits=digits, algorithm=algo)
        remaining = step - int(now) % step
        if args.json:
            emit_json({"code": code, "step": step,
                       "remaining_seconds": remaining, "algorithm": algo})
            return 0
        print(f"{bold('code')}       {green(code)}")
        print(f"{bold('valid for')}  {remaining}s")
        return 0

    if args.mode == "hotp":
        try:
            secret = _b32_decode(args.secret)
        except Exception as e:
            print(f"otp: invalid base32 secret: {e}", file=sys.stderr); return 2
        print(hotp(secret, args.counter, digits=args.digits, algorithm=args.algo))
        return 0

    if args.mode == "verify":
        try:
            secret = _b32_decode(args.secret)
        except Exception as e:
            print(f"otp: invalid base32 secret: {e}", file=sys.stderr); return 2
        v = verify_totp(secret, args.code, window=args.window,
                         step=args.step, digits=args.digits, algorithm=args.algo)
        if v.valid:
            print(green(f"OK (skew={v.matched_skew:+d} steps)"))
            return 0
        print(red("INVALID"))
        return 1

    if args.mode == "parse":
        try:
            info = parse_otpauth(args.uri)
        except ValueError as e:
            print(f"otp: {e}", file=sys.stderr); return 2
        emit_json(info)
        return 0

    return 2
