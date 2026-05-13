import unittest

from cyberkit.otp import _b32_decode, hotp, parse_otpauth, totp, verify_totp


RFC4226_KEY = b"12345678901234567890"


class TestHOTP(unittest.TestCase):
    """RFC 4226 Appendix D test vectors."""

    EXPECTED = [
        "755224", "287082", "359152", "969429", "338314",
        "254676", "287922", "162583", "399871", "520489",
    ]

    def test_all_vectors(self):
        for c, want in enumerate(self.EXPECTED):
            got = hotp(RFC4226_KEY, c, digits=6, algorithm="SHA1")
            self.assertEqual(got, want, f"HOTP({c}) = {got}, want {want}")


class TestTOTP(unittest.TestCase):
    """RFC 6238 Appendix B test vectors."""

    SHA1_KEY = b"12345678901234567890"

    def _otp_at(self, t):
        return totp(self.SHA1_KEY, now=t, step=30, digits=8, algorithm="SHA1")

    def test_sha1_t59(self):
        self.assertEqual(self._otp_at(59), "94287082")

    def test_sha1_t_1111111109(self):
        self.assertEqual(self._otp_at(1111111109), "07081804")

    def test_sha1_t_1234567890(self):
        self.assertEqual(self._otp_at(1234567890), "89005924")


class TestVerify(unittest.TestCase):
    def test_verify_exact(self):
        code = totp(RFC4226_KEY, now=1000, step=30, digits=6)
        v = verify_totp(RFC4226_KEY, code, window=1, now=1000, step=30, digits=6)
        self.assertTrue(v.valid)
        self.assertEqual(v.matched_skew, 0)

    def test_verify_skew_within_window(self):
        code = totp(RFC4226_KEY, now=1000, step=30, digits=6)
        v = verify_totp(RFC4226_KEY, code, window=1, now=1030, step=30, digits=6)
        self.assertTrue(v.valid)
        self.assertEqual(v.matched_skew, -1)

    def test_verify_skew_outside_window(self):
        code = totp(RFC4226_KEY, now=1000, step=30, digits=6)
        v = verify_totp(RFC4226_KEY, code, window=1, now=1200, step=30, digits=6)
        self.assertFalse(v.valid)

    def test_verify_wrong_code(self):
        v = verify_totp(RFC4226_KEY, "000000", window=1, now=1000, step=30, digits=6)
        self.assertFalse(v.valid)


class TestBase32(unittest.TestCase):
    def test_decode_hello_world(self):
        self.assertEqual(_b32_decode("JBSWY3DPEB3W64TMMQ"), b"Hello world")

    def test_decode_strips_spaces_and_dashes(self):
        self.assertEqual(_b32_decode("JBSWY 3DPEB-3W64TM-MQ"), b"Hello world")

    def test_decode_missing_padding(self):
        self.assertEqual(_b32_decode("MFRGGZA"), b"abcd")


class TestOtpAuth(unittest.TestCase):
    def test_parse_basic(self):
        uri = ("otpauth://totp/Example:alice%40example.com"
               "?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=6&period=30")
        info = parse_otpauth(uri)
        self.assertEqual(info["type"], "totp")
        self.assertEqual(info["secret"], "JBSWY3DPEHPK3PXP")
        self.assertEqual(info["issuer"], "Example")
        self.assertEqual(info["digits"], 6)
        self.assertEqual(info["period"], 30)

    def test_parse_rejects_other_scheme(self):
        with self.assertRaises(ValueError):
            parse_otpauth("https://example.com/")


if __name__ == "__main__":
    unittest.main()
