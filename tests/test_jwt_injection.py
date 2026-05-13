import base64
import json
import unittest

from cyberkit.jwtinspect import audit, decode_jwt


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _make(header: dict, payload: dict) -> str:
    h = _b64u(json.dumps(header, separators=(",", ":")).encode())
    p = _b64u(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.dummysigaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


class TestKidInjection(unittest.TestCase):
    def _findings(self, header):
        return audit(decode_jwt(_make(header, {"sub": "u", "exp": 99999999999})))

    def test_kid_sql_injection_flagged(self):
        msgs = [m for _s, m in self._findings({"alg": "HS256", "kid": "x' OR '1'='1"})]
        self.assertTrue(any("SQL-injection" in m for m in msgs))

    def test_kid_path_traversal_flagged(self):
        msgs = [m for _s, m in self._findings({"alg": "HS256", "kid": "../../etc/passwd"})]
        self.assertTrue(any("path-traversal" in m for m in msgs))

    def test_kid_null_byte_flagged(self):
        msgs = [m for _s, m in self._findings({"alg": "HS256", "kid": "abc\x00.pem"})]
        self.assertTrue(any("null byte" in m for m in msgs))

    def test_kid_clean_no_inject_finding(self):
        f = self._findings({"alg": "HS256", "kid": "key-2024-01"})
        msgs = [m for _s, m in f]
        self.assertFalse(any("SQL" in m or "path-traversal" in m or "null byte" in m for m in msgs))


class TestJkuX5u(unittest.TestCase):
    def test_jku_flagged(self):
        msgs = [m for _s, m in audit(decode_jwt(_make(
            {"alg": "RS256", "jku": "https://attacker.example/keys.json"},
            {"sub": "x", "exp": 99999999999})))]
        self.assertTrue(any("jku" in m for m in msgs))

    def test_x5u_flagged(self):
        msgs = [m for _s, m in audit(decode_jwt(_make(
            {"alg": "RS256", "x5u": "https://attacker.example/cert.pem"},
            {"sub": "x", "exp": 99999999999})))]
        self.assertTrue(any("x5u" in m for m in msgs))


class TestSubtake(unittest.TestCase):
    """Light smoke check that the service signature table compiles."""

    def test_signatures_compile(self):
        from cyberkit.subtake import SERVICES
        self.assertGreaterEqual(len(SERVICES), 10)
        for s in SERVICES:
            self.assertIsNotNone(s.cname_pattern.pattern)


if __name__ == "__main__":
    unittest.main()
