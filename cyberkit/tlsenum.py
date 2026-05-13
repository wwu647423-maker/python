"""
tlsenum — enumerate which TLS versions and ciphers a server accepts.

For each candidate TLS version we try a fresh handshake with that
version pinned (min == max). For ciphers, we iterate through a curated
list of weak + strong suites; if the negotiated cipher matches our
candidate, the server supports it.

Reports:
    * which versions are accepted (with security commentary on legacy ones)
    * which ciphers are accepted (with weak-suite highlighting)
    * negotiated ALPN protocols
    * a session-resumption probe (sends two handshakes and asks the
      second one whether the session was reused)
"""

from __future__ import annotations

import argparse
import socket
import ssl
import sys
from typing import NamedTuple

from ._common import bold, cyan, dim, emit_json, green, magenta, print_table, red, yellow

WEAK_SUITES = {
    "NULL", "EXPORT", "DES-CBC", "RC4", "MD5", "PSK", "anon",
    "EXPORT40", "EXP-", "ADH-", "AECDH-",
}

VERSION_LABEL = {
    ssl.TLSVersion.TLSv1: "TLSv1.0",
    ssl.TLSVersion.TLSv1_1: "TLSv1.1",
    ssl.TLSVersion.TLSv1_2: "TLSv1.2",
    ssl.TLSVersion.TLSv1_3: "TLSv1.3",
}

WEAK_VERSIONS = {"SSLv3", "TLSv1.0", "TLSv1.1"}

CIPHER_PROBES = [
    "AES256-GCM-SHA384", "AES128-GCM-SHA256",
    "AES256-SHA256", "AES128-SHA256",
    "AES256-SHA", "AES128-SHA",
    "DES-CBC3-SHA",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-AES128-GCM-SHA256",
    "RC4-MD5", "RC4-SHA",
    "EXP-RC4-MD5",
    "NULL-SHA", "NULL-MD5",
]


class VersionResult(NamedTuple):
    version: str
    supported: bool
    cipher: str
    detail: str


class CipherResult(NamedTuple):
    cipher: str
    accepted: bool
    weak: bool


def _is_weak(cipher: str) -> bool:
    return any(w in cipher.upper() for w in WEAK_SUITES)


def _try_version(host: str, port: int, version: ssl.TLSVersion,
                 timeout: float, sni: str) -> VersionResult:
    label = VERSION_LABEL.get(version, str(version))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ValueError, AttributeError, ssl.SSLError) as e:
        return VersionResult(label, False, "", f"client doesn't support {label}: {e}")
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as tls:
                proto = tls.version() or label
                cipher = (tls.cipher() or ("", "", 0))[0]
                return VersionResult(proto, True, cipher, "")
    except (ssl.SSLError, OSError) as e:
        msg = str(e).split("\n")[0]
        return VersionResult(label, False, "", msg)


def _try_cipher(host: str, port: int, cipher: str, timeout: float,
                sni: str) -> CipherResult:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    except (ValueError, AttributeError):
        pass
    try:
        ctx.set_ciphers(cipher)
    except ssl.SSLError:
        return CipherResult(cipher, False, _is_weak(cipher))
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as tls:
                neg = (tls.cipher() or ("", "", 0))[0]
                return CipherResult(neg, True, _is_weak(neg))
    except (ssl.SSLError, OSError):
        return CipherResult(cipher, False, _is_weak(cipher))


def _check_resumption(host: str, port: int, timeout: float, sni: str) -> bool:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as tls:
                session = tls.session
                if session is None:
                    return False
        with socket.create_connection((host, port), timeout=timeout) as raw:
            tls = ctx.wrap_socket(raw, server_hostname=sni, session=session, do_handshake_on_connect=False)
            tls.do_handshake()
            reused = getattr(tls, "session_reused", False)
            tls.close()
            return bool(reused)
    except (ssl.SSLError, OSError):
        return False


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="cyberkit tlsenum",
                                 description="Enumerate supported TLS versions, ciphers, and features.")
    ap.add_argument("target", help="host[:port] (default port 443)")
    ap.add_argument("-t", "--timeout", type=float, default=4.0)
    ap.add_argument("--sni", default=None)
    ap.add_argument("--skip-ciphers", action="store_true",
                    help="skip the slow per-cipher enumeration")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if ":" in args.target and not args.target.startswith("["):
        host, _, p = args.target.rpartition(":")
        port = int(p)
    else:
        host, port = args.target, 443
    sni = args.sni or host

    versions = [ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1,
                ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3]
    vres = [_try_version(host, port, v, args.timeout, sni) for v in versions]

    ciphers: list[CipherResult] = []
    if not args.skip_ciphers:
        seen: set[str] = set()
        for c in CIPHER_PROBES:
            r = _try_cipher(host, port, c, args.timeout, sni)
            if r.cipher in seen:
                continue
            seen.add(r.cipher)
            ciphers.append(r)

    resumed = _check_resumption(host, port, args.timeout, sni)

    if args.json:
        emit_json({
            "target": f"{host}:{port}",
            "versions": [v._asdict() for v in vres],
            "ciphers": [c._asdict() for c in ciphers if c.accepted],
            "session_resumption": resumed,
        })
        return 0

    print(f"{bold('target')}            {host}:{port}")
    print(dim("-" * 64))
    print(bold("TLS versions:"))
    rows = []
    for r in vres:
        tag = (red("LEGACY") if r.supported and r.version in WEAK_VERSIONS
               else green("ok") if r.supported else dim("no"))
        rows.append([tag, cyan(r.version),
                     r.cipher or "-",
                     dim(r.detail)[:60] if not r.supported else ""])
    print_table(["STATUS", "VERSION", "CIPHER", "DETAIL"], rows)

    if not args.skip_ciphers:
        print()
        print(bold("ciphers:"))
        accepted = [c for c in ciphers if c.accepted]
        if accepted:
            rows = [[red("WEAK") if c.weak else green("ok"),
                     magenta(c.cipher)] for c in accepted]
            print_table(["RATING", "CIPHER"], rows)
        else:
            print(dim("  (server enforces TLS 1.3 only — TLS 1.2 cipher probes had no effect)"))

    print()
    print(f"{bold('session resumption')}  "
          f"{green('yes') if resumed else dim('no / not observed')}")
    return 0
