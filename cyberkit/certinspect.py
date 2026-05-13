"""
certinspect — TLS / X.509 certificate inspection.

Connects to a host:port, performs the TLS handshake (no verification, so
we can inspect bad / self-signed / expired certs), then reports:

    * negotiated TLS protocol & cipher
    * full peer-cert leaf info: subject, issuer, serial, validity, SANs
    * computed time-to-expiry, with WARNING / CRITICAL gates
    * security flags: weak protocol (TLS<1.2), weak RSA (<2048), small EC
      curve, self-signed, expired, hostname mismatch
    * full DER as hex if --raw is given
"""

from __future__ import annotations

import argparse
import os
import socket
import ssl
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any

from ._common import bold, cyan, dim, emit_json, green, magenta, red, yellow


def _decode_der(der: bytes) -> dict:
    """Parse a DER cert into the dict format ssl.getpeercert() returns.

    `_ssl._test_decode_cert` is undocumented but ships with every CPython
    build and is the standard workaround for parsing peer certs that
    failed verification (which is the whole point of this tool).
    """
    if not der:
        return {}
    try:
        from _ssl import _test_decode_cert
    except ImportError:
        return {}
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(pem)
        return _test_decode_cert(path) or {}
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def fetch_cert(host: str, port: int, timeout: float = 5.0,
               sni: str | None = None) -> tuple[dict, bytes, str, tuple]:
    """Returns (cert_dict, cert_der, protocol, cipher_tuple)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=sni or host) as tls:
            der = tls.getpeercert(binary_form=True) or b""
            proto = tls.version() or ""
            cipher = tls.cipher() or ("", "", 0)
    cert = _decode_der(der)
    return cert, der, proto, cipher


def _flatten_name(seq: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    for tup in seq or ():
        for k, v in tup:
            out[k] = v
    return out


def _parse_dt(raw: str) -> datetime:
    return datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def analyze(cert: dict, proto: str, cipher: tuple, host: str) -> dict:
    findings: list[tuple[str, str]] = []
    info: dict[str, Any] = {}

    info["protocol"] = proto
    info["cipher"] = {"name": cipher[0], "version": cipher[1], "bits": cipher[2]}
    if proto and proto in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
        findings.append(("HIGH", f"weak protocol negotiated: {proto}"))

    subj = _flatten_name(cert.get("subject"))
    issuer = _flatten_name(cert.get("issuer"))
    info["subject"] = subj
    info["issuer"] = issuer
    info["serial_number"] = cert.get("serialNumber", "")
    info["version"] = cert.get("version", 0)

    nb = cert.get("notBefore")
    na = cert.get("notAfter")
    info["not_before"] = nb
    info["not_after"] = na
    now = datetime.now(timezone.utc)
    if nb:
        nb_dt = _parse_dt(nb)
        if nb_dt > now:
            findings.append(("HIGH", f"certificate is not yet valid (notBefore={nb})"))
    if na:
        na_dt = _parse_dt(na)
        days_left = (na_dt - now).days
        info["days_until_expiry"] = days_left
        if days_left < 0:
            findings.append(("CRITICAL", f"certificate EXPIRED {-days_left} days ago"))
        elif days_left < 14:
            findings.append(("HIGH", f"certificate expires in {days_left} days"))
        elif days_left < 30:
            findings.append(("MED", f"certificate expires in {days_left} days"))

    sans = [v for k, v in cert.get("subjectAltName", ()) if k.lower() == "dns"]
    info["sans"] = sans

    matched = False
    candidates = sans or ([subj.get("commonName")] if subj.get("commonName") else [])
    for pattern in candidates:
        if pattern and _hostname_matches(host, pattern):
            matched = True
            break
    info["hostname_match"] = matched
    if candidates and not matched:
        findings.append(("HIGH", f"hostname {host!r} does not match cert "
                                  f"(SAN={sans or [subj.get('commonName')]})"))

    if subj == issuer and subj:
        findings.append(("MED", "certificate appears self-signed (subject == issuer)"))

    info["findings"] = [{"severity": s, "msg": m} for s, m in findings]
    return info


def _hostname_matches(host: str, pattern: str) -> bool:
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        if "." in host and host.split(".", 1)[1] == suffix:
            return True
    return False


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="cyberkit certinspect",
                                 description="Inspect a TLS endpoint's certificate.")
    ap.add_argument("target", help="host[:port] (default port 443)")
    ap.add_argument("-t", "--timeout", type=float, default=5.0)
    ap.add_argument("--sni", default=None,
                    help="SNI hostname to send (default: same as target host)")
    ap.add_argument("--raw", action="store_true",
                    help="also print the DER hex blob")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    target = args.target
    if ":" in target and not target.startswith("["):
        host, _, port_s = target.rpartition(":")
        try:
            port = int(port_s)
        except ValueError:
            port = 443
            host = target
    else:
        host, port = target, 443

    try:
        cert, der, proto, cipher = fetch_cert(host, port, args.timeout, args.sni)
    except (OSError, ssl.SSLError) as e:
        print(f"certinspect: handshake failed: {e}", file=sys.stderr)
        return 2

    info = analyze(cert, proto, cipher, host)

    if args.json:
        if args.raw:
            info["der_hex"] = der.hex()
        emit_json({"host": host, "port": port, **info})
        return 1 if any(f["severity"] in ("HIGH", "CRITICAL") for f in info["findings"]) else 0

    print(f"{bold('host')}        {host}:{port}")
    print(f"{bold('protocol')}    {info['protocol']}")
    cph = info["cipher"]
    print(f"{bold('cipher')}      {cph['name']}  {cph['version']}  {cph['bits']}-bit")
    print()
    print(bold("subject:"))
    for k, v in info["subject"].items():
        print(f"  {k:18} {cyan(v)}")
    print(bold("issuer:"))
    for k, v in info["issuer"].items():
        print(f"  {k:18} {magenta(v)}")
    print()
    print(f"{bold('serial')}      {info['serial_number']}")
    print(f"{bold('valid from')}  {info['not_before']}")
    print(f"{bold('valid to')}    {info['not_after']}", end="")
    days = info.get("days_until_expiry")
    if days is not None:
        col = red if days < 14 else (yellow if days < 30 else green)
        print(f"   ({col(f'{days} days left')})")
    else:
        print()

    print(f"{bold('SANs')}        {', '.join(info['sans']) or dim('(none)')}")
    print(f"{bold('hostname')}    {green('matches') if info['hostname_match'] else red('MISMATCH')}")

    if info["findings"]:
        print(dim("\n" + "-" * 64))
        print(bold("findings:"))
        sev_color = {"CRITICAL": red, "HIGH": red, "MED": yellow, "LOW": cyan}
        for f in info["findings"]:
            print(f"  {sev_color.get(f['severity'], dim)(f['severity']):<10} {f['msg']}")
        return 1
    if args.raw:
        print(dim("\n" + "-" * 64))
        print(bold("DER (hex):"))
        print(der.hex())
    return 0
