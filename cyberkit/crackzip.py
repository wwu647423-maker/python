"""
crackzip — wordlist password cracker for ZipCrypto-encrypted .zip files.

Uses stdlib `zipfile`, so it only handles the classic ZipCrypto cipher
(WinZip / 7-Zip "AES-256" zips are *not* covered — those need a CRC
header layout that zipfile.py refuses to decrypt). For real-world
engagements that's usually fine: legacy ZipCrypto remains common in
e.g. document drops, CTF challenges, archived backups.

Speedup: we read the smallest encrypted entry's first 12 bytes (the
ZipCrypto check bytes), and verify the trial password against those
in-process. Only when the check bytes match do we actually decompress
to confirm. With Python 3.9+ this is essentially as fast as you can
get without going to C.

Multi-threaded with a configurable worker count, supports the same
mutation rules as `hashcrack --rules`.
"""

from __future__ import annotations

import argparse
import struct
import sys
import zipfile
import zlib
from concurrent.futures import ThreadPoolExecutor
from typing import Iterable

from ._common import bold, cyan, dim, green, red, yellow
from .hashcrack import expand as _expand_rules


_CRCTABLE: list[int] | None = None


def _crc_table() -> list[int]:
    global _CRCTABLE
    if _CRCTABLE is not None:
        return _CRCTABLE
    table: list[int] = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (0xEDB88320 if c & 1 else 0)
        table.append(c)
    _CRCTABLE = table
    return table


def _crc32_update(crc: int, byte: int) -> int:
    return (crc >> 8) ^ _crc_table()[(crc ^ byte) & 0xFF]


class _ZCKeys:
    """The three 32-bit ZipCrypto keys, as in APPNOTE.TXT §6.1."""
    __slots__ = ("k0", "k1", "k2")

    def __init__(self) -> None:
        self.k0 = 0x12345678
        self.k1 = 0x23456789
        self.k2 = 0x34567890

    def update(self, byte: int) -> None:
        self.k0 = _crc32_update(self.k0, byte)
        self.k1 = (self.k1 + (self.k0 & 0xFF)) & 0xFFFFFFFF
        self.k1 = (self.k1 * 134775813 + 1) & 0xFFFFFFFF
        self.k2 = _crc32_update(self.k2, (self.k1 >> 24) & 0xFF)

    def stream_byte(self) -> int:
        t = (self.k2 | 2) & 0xFFFF
        return ((t * (t ^ 1)) >> 8) & 0xFF


def _zipcrypto_check(password: bytes, header12: bytes, check_byte: int) -> bool:
    """Run ZipCrypto's 12-byte header through the cipher with `password`.
    Returns True if the last decrypted byte matches `check_byte`."""
    keys = _ZCKeys()
    for b in password:
        keys.update(b)
    last = 0
    for c in header12:
        sb = keys.stream_byte()
        plain = c ^ sb
        keys.update(plain)
        last = plain
    return last == check_byte


def _dos_time(date_time: tuple[int, int, int, int, int, int]) -> int:
    _y, _mo, _d, h, mi, s = date_time
    return ((h & 0x1F) << 11) | ((mi & 0x3F) << 5) | ((s // 2) & 0x1F)


def _entry_check_byte(zi: zipfile.ZipInfo) -> int:
    """ZipCrypto check byte: high byte of mod-time when general-purpose
    bit 3 (streaming / data-descriptor) is set, else high byte of CRC."""
    if zi.flag_bits & 0x8:
        return (_dos_time(zi.date_time) >> 8) & 0xFF
    return (zi.CRC >> 24) & 0xFF


def _encrypted_entries(zf: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    return [zi for zi in zf.infolist() if zi.flag_bits & 0x1 and not zi.is_dir()]


def _read_encryption_header(zip_path: str, zi: zipfile.ZipInfo) -> bytes:
    """Parse the ZIP local file header at zi.header_offset directly off
    disk and return the 12-byte ZipCrypto encryption header that follows.

    We bypass zipfile.open() because that always tries to decrypt; we
    only want the raw bytes. The local-file-header layout is fixed by
    APPNOTE.TXT §4.3.7 and stable, so parsing it ourselves is more
    portable than poking at zipfile.py's private symbols.
    """
    with open(zip_path, "rb") as fh:
        fh.seek(zi.header_offset)
        lfh = fh.read(30)
        if len(lfh) < 30 or lfh[:4] != b"PK\x03\x04":
            raise ValueError(f"bad local file header at offset {zi.header_offset}")
        fname_len = struct.unpack("<H", lfh[26:28])[0]
        extra_len = struct.unpack("<H", lfh[28:30])[0]
        fh.seek(fname_len + extra_len, 1)
        header12 = fh.read(12)
    if len(header12) != 12:
        raise ValueError("zip entry truncated before encryption header")
    return header12


def crack(zip_path: str, words: Iterable[str], rules: bool = False,
          workers: int = 4, verify_full: bool = True) -> str | None:
    """Try each candidate against the smallest encrypted entry; return the password or None."""
    with zipfile.ZipFile(zip_path) as zf:
        entries = _encrypted_entries(zf)
        if not entries:
            raise ValueError("no encrypted entries in archive")
        entries.sort(key=lambda zi: zi.compress_size)
        target = entries[0]
        check_byte = _entry_check_byte(target)
        target_name = target.filename

    header12 = _read_encryption_header(zip_path, target)
    expanded = list(_expand_rules(iter(list(words)), rules))

    if workers <= 1:
        for cand in expanded:
            pw = cand.encode("utf-8")
            if _zipcrypto_check(pw, header12, check_byte):
                if not verify_full or _full_verify(zip_path, target_name, pw):
                    return cand
        return None

    chunk_size = max(1, len(expanded) // workers)
    chunks = [expanded[i:i + chunk_size] for i in range(0, len(expanded), chunk_size)]

    def _worker(batch: list[str]) -> str | None:
        for cand in batch:
            pw = cand.encode("utf-8")
            if _zipcrypto_check(pw, header12, check_byte):
                if not verify_full or _full_verify(zip_path, target_name, pw):
                    return cand
        return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for fut in pool.map(_worker, chunks):
            if fut is not None:
                return fut
    return None


def _full_verify(zip_path: str, name: str, pwd: bytes) -> bool:
    try:
        with zipfile.ZipFile(zip_path) as zf:
            with zf.open(name, "r", pwd=pwd) as fh:
                fh.read(1)
        return True
    except (RuntimeError, zipfile.BadZipFile, zlib.error):
        return False


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="cyberkit crackzip",
                                 description="Crack ZipCrypto-encrypted .zip files against a wordlist.")
    ap.add_argument("zip", help="path to encrypted zip file")
    ap.add_argument("-w", "--wordlist", default=None,
                    help="path to wordlist (default: bundled passwords-small.txt)")
    ap.add_argument("--rules", action="store_true",
                    help="expand each entry with hashcat-style mutations (case/digits/leet/reverse)")
    ap.add_argument("-T", "--threads", type=int, default=4)
    ap.add_argument("--no-verify", action="store_true",
                    help="skip the slow 'actually decompress' verification step (faster, ~1/256 false-positive risk)")
    args = ap.parse_args(argv)

    if args.wordlist is None:
        from pathlib import Path
        args.wordlist = str(Path(__file__).resolve().parent / "data" / "passwords-small.txt")

    try:
        with open(args.wordlist, "r", encoding="utf-8", errors="replace") as fh:
            words = fh.read().splitlines()
    except OSError as e:
        print(f"crackzip: {e}", file=sys.stderr); return 2

    try:
        found = crack(args.zip, words, rules=args.rules, workers=args.threads,
                      verify_full=not args.no_verify)
    except (zipfile.BadZipFile, ValueError, OSError) as e:
        print(f"crackzip: {e}", file=sys.stderr); return 2

    if found is None:
        print(red("no match"), file=sys.stderr); return 1
    print(green(found))
    return 0
