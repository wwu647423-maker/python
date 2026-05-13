import unittest

from cyberkit.secrets import RULES, scan_text, shannon


class TestSecrets(unittest.TestCase):
    def _has(self, findings, rule_name):
        return any(f.rule == rule_name for f in findings)

    def test_shannon_known(self):
        self.assertAlmostEqual(shannon("aaaa"), 0.0)
        self.assertAlmostEqual(shannon("ab"), 1.0)

    def test_aws_access_key(self):
        token = "AKIA" + "IOSFODNN7EXAMPLE"
        f = list(scan_text("t.py", f"AWS_KEY = {token}"))
        self.assertTrue(self._has(f, "AWS Access Key ID"))

    def test_github_pat(self):
        token = "gh" + "p_" + "A" * 36
        f = list(scan_text("t.py", f"export GH_TOKEN={token}"))
        self.assertTrue(self._has(f, "GitHub Personal Access Token"))

    def test_slack_token(self):
        token = "xo" + "xb-" + "12345678901-1234567890-abcdefABCDEF1234567890ab"
        f = list(scan_text("t.py", f"SLACK_TOKEN = {token}"))
        self.assertTrue(self._has(f, "Slack Token"))

    def test_pem_block(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
        f = list(scan_text("t.py", text))
        self.assertTrue(self._has(f, "PEM Private Key Block"))

    def test_jwt(self):
        jwt = ("eyJhbGciOiJIUzI1NiJ9."
               "eyJzdWIiOiJhbGljZSJ9."
               "BAfMI2VVB7BCnHGuDfgsCMA")
        f = list(scan_text("t.py", f"token={jwt}"))
        self.assertTrue(self._has(f, "JWT"))

    def test_password_assignment(self):
        text = 'password = "hunter2hunter2"'
        f = list(scan_text("t.py", text))
        self.assertTrue(self._has(f, "Password assignment"))

    def test_url_with_credentials(self):
        text = "DATABASE_URL=postgres://alice:s3cret@db.example.com/prod"
        f = list(scan_text("t.py", text))
        self.assertTrue(self._has(f, "URL with credentials"))

    def test_low_entropy_generic_filtered(self):
        text = 'api_key = "1111111111111111111111"'
        f = list(scan_text("t.py", text))
        self.assertFalse(self._has(f, "Generic API Key (context match)"))

    def test_redaction(self):
        text = "AKIA" + "IOSFODNN7EXAMPLE"
        f = list(scan_text("t.py", text, redact=True))
        self.assertTrue(f)
        self.assertIn("…", f[0].match)
        self.assertNotEqual(f[0].match, text)

    def test_no_redaction(self):
        text = "gh" + "p_" + "B" * 36
        f = list(scan_text("t.py", text, redact=False))
        self.assertEqual(f[0].match, text)

    def test_clean_file_no_findings(self):
        f = list(scan_text("ok.py", "def hello(): return 'world'"))
        self.assertEqual(f, [])

    def test_rules_compile(self):
        for r in RULES:
            self.assertIsNotNone(r.pattern.pattern)


if __name__ == "__main__":
    unittest.main()
