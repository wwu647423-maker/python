"""
Pure-Python MD4 (RFC 1320).

Needed because OpenSSL 3 ships without the legacy provider on most modern
distros, so `hashlib.new("md4")` raises. MD4 itself is cryptographically
dead — we expose it only because NTLM = MD4(UTF-16LE(password)) is still
ubiquitous in real engagements.
"""

from __future__ import annotations

import struct

_MASK = 0xFFFFFFFF


def _rotl(x: int, n: int) -> int:
    x &= _MASK
    return ((x << n) | (x >> (32 - n))) & _MASK


def md4(message: bytes) -> bytes:
    """Return the 16-byte MD4 digest of `message`."""
    msg = bytearray(message)
    orig_len_bits = (len(msg) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", orig_len_bits)

    A = 0x67452301
    B = 0xEFCDAB89
    C = 0x98BADCFE
    D = 0x10325476

    R1_X = list(range(16))
    R1_S = [3, 7, 11, 19] * 4
    R2_X = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
    R2_S = [3, 5, 9, 13] * 4
    R3_X = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
    R3_S = [3, 9, 11, 15] * 4

    for off in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", msg[off:off + 64]))
        AA, BB, CC, DD = A, B, C, D
        a, b, cc, d = A, B, C, D

        for i in range(16):
            f = (b & cc) | ((~b) & d)
            t = (a + f + X[R1_X[i]]) & _MASK
            a = _rotl(t, R1_S[i])
            a, b, cc, d = d, a, b, cc

        for i in range(16):
            g = (b & cc) | (b & d) | (cc & d)
            t = (a + g + X[R2_X[i]] + 0x5A827999) & _MASK
            a = _rotl(t, R2_S[i])
            a, b, cc, d = d, a, b, cc

        for i in range(16):
            h = b ^ cc ^ d
            t = (a + h + X[R3_X[i]] + 0x6ED9EBA1) & _MASK
            a = _rotl(t, R3_S[i])
            a, b, cc, d = d, a, b, cc

        A = (a + AA) & _MASK
        B = (b + BB) & _MASK
        C = (cc + CC) & _MASK
        D = (d + DD) & _MASK

    return struct.pack("<4I", A, B, C, D)


def ntlm(password: str) -> str:
    """NTLM hash (hex) of `password`: MD4(UTF-16LE(password))."""
    return md4(password.encode("utf-16-le")).hex()
