"""
portscan — concurrent TCP-connect scanner.

Performs full TCP handshakes (no raw sockets, no root required), supports
flexible port specs ("22,80,443" / "1-1024" / "top100" / "all"), grabs
service banners with a small protocol-aware probe table, and emits either
a human table or JSON-Lines.
"""

from __future__ import annotations

import argparse
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable

from ._common import bold, cyan, dim, emit_jsonl, green, print_table, red, yellow

TOP_100 = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
    8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 11211, 27017,
    32768, 49152, 49153, 49154, 49155, 49156, 49157,
]

PROBES: dict[int, bytes] = {
    21:  b"",
    22:  b"",
    25:  b"EHLO cyberkit.local\r\n",
    80:  b"HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: cyberkit/portscan\r\n\r\n",
    110: b"",
    143: b"",
    443: b"",
    8080: b"HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: cyberkit/portscan\r\n\r\n",
}


def parse_ports(spec: str) -> list[int]:
    """'22,80,1000-1010' / 'top100' / 'all' → sorted unique [int]."""
    spec = spec.strip().lower()
    if spec == "all":
        return list(range(1, 65536))
    if spec == "top100":
        return sorted(TOP_100)
    out: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo, hi = chunk.split("-", 1)
            lo_i, hi_i = int(lo), int(hi)
            if lo_i > hi_i or lo_i < 1 or hi_i > 65535:
                raise ValueError(f"bad port range: {chunk}")
            out.update(range(lo_i, hi_i + 1))
        else:
            p = int(chunk)
            if not 1 <= p <= 65535:
                raise ValueError(f"bad port: {p}")
            out.add(p)
    return sorted(out)


def _grab_banner(sock: socket.socket, host: str, port: int, timeout: float) -> str:
    """Send a small protocol-appropriate probe and read at most ~512 bytes."""
    sock.settimeout(timeout)
    try:
        probe = PROBES.get(port, b"")
        if b"%s" in probe:
            probe = probe.replace(b"%s", host.encode("idna", errors="replace"))
        if probe:
            try:
                sock.sendall(probe)
            except OSError:
                pass
        data = b""
        try:
            data = sock.recv(512)
        except OSError:
            return ""
        return data.decode("latin-1", errors="replace").strip().replace("\r", "").replace("\n", " | ")[:200]
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _maybe_tls_banner(host: str, port: int, timeout: float) -> str:
    """For 443/8443 wrap in TLS and inspect the certificate CN/SAN."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert(binary_form=False) or {}
                cn = ""
                for tup in cert.get("subject", ()):
                    for k, v in tup:
                        if k == "commonName":
                            cn = v
                sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
                proto = tls.version() or "TLS"
                cipher = tls.cipher() or ("?", "?", 0)
                ident = cn or (sans[0] if sans else "")
                return f"{proto} {cipher[0]} cn={ident}"
    except (OSError, ssl.SSLError):
        return ""


def scan_port(host: str, port: int, timeout: float, banner: bool) -> dict | None:
    """Return a result dict if open, None if filtered/closed."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except (OSError, socket.timeout):
        return None

    info: dict = {"host": host, "port": port, "state": "open"}
    try:
        info["service"] = socket.getservbyport(port, "tcp")
    except OSError:
        info["service"] = ""

    if banner:
        if port in (443, 8443, 9443):
            sock.close()
            info["banner"] = _maybe_tls_banner(host, port, timeout)
        else:
            info["banner"] = _grab_banner(sock, host, port, timeout)
    else:
        sock.close()
        info["banner"] = ""
    return info


def _resolve(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return ""


def run_scan(host: str, ports: Iterable[int], workers: int, timeout: float, banner: bool) -> list[dict]:
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(scan_port, host, p, timeout, banner): p for p in ports}
        for f in as_completed(futs):
            r = f.result()
            if r:
                results.append(r)
    results.sort(key=lambda r: r["port"])
    return results


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="cyberkit portscan",
                                 description="Concurrent TCP-connect scanner.")
    ap.add_argument("target", help="hostname or IPv4 address")
    ap.add_argument("-p", "--ports", default="top100",
                    help="port spec: '22,80,443', '1-1024', 'top100', 'all' (default: top100)")
    ap.add_argument("-t", "--timeout", type=float, default=1.5,
                    help="per-connection timeout in seconds (default: 1.5)")
    ap.add_argument("-w", "--workers", type=int, default=128,
                    help="concurrent worker threads (default: 128)")
    ap.add_argument("-B", "--no-banner", action="store_true",
                    help="skip banner grabbing")
    ap.add_argument("--json", action="store_true",
                    help="emit JSON-Lines instead of a table")
    args = ap.parse_args(argv)

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"portscan: {e}", file=sys.stderr)
        return 2

    ip = _resolve(args.target)
    if not ip:
        print(f"portscan: cannot resolve {args.target!r}", file=sys.stderr)
        return 2

    if not args.json:
        print(f"{bold('target')}    {args.target} ({ip})")
        print(f"{bold('ports')}     {len(ports)}  ({args.ports})")
        print(f"{bold('workers')}   {args.workers}   "
              f"{bold('timeout')} {args.timeout}s   "
              f"{bold('banner')}  {'no' if args.no_banner else 'yes'}")
        print(dim("-" * 64))

    results = run_scan(args.target, ports, args.workers, args.timeout, not args.no_banner)

    if args.json:
        emit_jsonl(results)
    else:
        if not results:
            print(yellow("no open ports."))
        else:
            rows = [[
                green(str(r["port"])),
                r["service"] or dim("-"),
                cyan(r["banner"][:80]) if r["banner"] else dim("-"),
            ] for r in results]
            print_table(["PORT", "SERVICE", "BANNER"], rows)
        print(dim("-" * 64))
        print(f"{len(results)} open / {len(ports)} probed")
    return 0
