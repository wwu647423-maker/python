import unittest

from cyberkit.pwdaudit import audit_local


class TestPwdAudit(unittest.TestCase):
    def test_short_password_very_weak(self):
        r = audit_local("abc")
        self.assertEqual(r.score, 0)
        self.assertTrue(any("short" in f for f in r.findings))

    def test_common_base_flagged(self):
        r = audit_local("Password1!")
        self.assertTrue(any("common base" in f for f in r.findings))

    def test_leet_common_base_flagged(self):
        r = audit_local("P@ssw0rd123")
        self.assertTrue(any("common base" in f for f in r.findings))

    def test_keyboard_run_flagged(self):
        r = audit_local("qwerty1234")
        self.assertTrue(any("keyboard run" in f for f in r.findings))

    def test_year_flagged(self):
        r = audit_local("Birthday2023!")
        self.assertTrue(any("4-digit year" in f for f in r.findings))

    def test_strong_password(self):
        r = audit_local("Tr0ub4dor&3-correct-horse-battery-staple")
        self.assertGreaterEqual(r.score, 3)
        self.assertEqual(r.findings, [])

    def test_charset_size_reflects_diversity(self):
        r1 = audit_local("aaaaaaaa")
        r2 = audit_local("Aa1!Aa1!")
        self.assertGreater(r2.charset_size, r1.charset_size)


if __name__ == "__main__":
    unittest.main()
