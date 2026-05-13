import base64
import hashlib
import hmac
import json
import time
import unittest

from cyberkit.jwtinspect import audit, brute_hmac, decode_jwt, verify_hmac


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def make_jwt(header: dict, payload: dict, secret: str | None) -> str:
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing = f"{h}.{p}".encode()
    if secret is None or header.get("alg", "").lower() == "none":
        s = ""
    else:
        algs = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        digestmod = algs[header["alg"]]
        s = _b64url(hmac.new(secret.encode(), signing, digestmod).digest())
    return f"{h}.{p}.{s}"


class TestJwtInspect(unittest.TestCase):
    def test_decode_roundtrip(self):
        tok = make_jwt({"alg": "HS256", "typ": "JWT"},
                       {"sub": "alice", "exp": int(time.time()) + 60},
                       "topsecret")
        d = decode_jwt(tok)
        self.assertEqual(d.header["alg"], "HS256")
        self.assertEqual(d.payload["sub"], "alice")

    def test_verify_hs256(self):
        tok = make_jwt({"alg": "HS256", "typ": "JWT"},
                       {"sub": "bob"}, "s3cret")
        d = decode_jwt(tok)
        self.assertTrue(verify_hmac(d, "s3cret"))
        self.assertFalse(verify_hmac(d, "wrong"))

    def test_brute_hits(self):
        tok = make_jwt({"alg": "HS256"}, {"x": 1}, "letmein")
        d = decode_jwt(tok)
        self.assertEqual(brute_hmac(d, iter(["foo", "bar", "letmein", "baz"])),
                         "letmein")

    def test_brute_misses(self):
        tok = make_jwt({"alg": "HS256"}, {"x": 1}, "letmein")
        d = decode_jwt(tok)
        self.assertIsNone(brute_hmac(d, iter(["foo", "bar"])))

    def test_alg_none_flagged_critical(self):
        tok = make_jwt({"alg": "none"}, {"sub": "admin"}, None)
        d = decode_jwt(tok)
        sev = [f[0] for f in audit(d)]
        self.assertIn("CRITICAL", sev)

    def test_no_exp_flagged_med(self):
        tok = make_jwt({"alg": "HS256"}, {"sub": "x"}, "k")
        d = decode_jwt(tok)
        msgs = [m for _s, m in audit(d)]
        self.assertTrue(any("no 'exp'" in m for m in msgs))

    def test_invalid_format_raises(self):
        with self.assertRaises(ValueError):
            decode_jwt("notajwt")


if __name__ == "__main__":
    unittest.main()
