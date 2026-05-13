import unittest

from cyberkit.cspaudit import audit, parse


class TestParse(unittest.TestCase):
    def test_basic(self):
        d = parse("default-src 'self'; script-src 'self' https://cdn.example.com")
        self.assertEqual(d["default-src"], ["'self'"])
        self.assertEqual(d["script-src"], ["'self'", "https://cdn.example.com"])

    def test_directive_case_insensitive(self):
        d = parse("Script-Src 'self'")
        self.assertIn("script-src", d)


class TestAudit(unittest.TestCase):
    def _has(self, findings, directive, substr):
        return any(directive == f.directive and substr in f.message for f in findings)

    def _sev(self, findings, directive, substr):
        for f in findings:
            if f.directive == directive and substr in f.message:
                return f.severity
        return None

    def test_unsafe_inline_script_high(self):
        _p, f = audit("default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.assertEqual(self._sev(f, "script-src", "unsafe-inline"), "HIGH")

    def test_unsafe_eval(self):
        _p, f = audit("default-src 'self'; script-src 'unsafe-eval'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.assertTrue(self._has(f, "script-src", "unsafe-eval"))

    def test_wildcard_high(self):
        _p, f = audit("default-src *; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src 'none'")
        self.assertEqual(self._sev(f, "default-src", "wildcard"), "HIGH")

    def test_missing_critical_with_no_default(self):
        _p, f = audit("script-src 'self'")
        msgs = [(x.directive, x.severity) for x in f]
        self.assertIn(("object-src", "HIGH"), msgs)
        self.assertIn(("frame-ancestors", "HIGH"), msgs)

    def test_missing_critical_with_default_src_low(self):
        _p, f = audit("default-src 'self'")
        sevs = {x.directive: x.severity for x in f}
        self.assertEqual(sevs.get("object-src"), "LOW")
        self.assertEqual(sevs.get("base-uri"), "LOW")

    def test_clean_policy_no_high_findings(self):
        policy = ("default-src 'none'; script-src 'self'; "
                  "object-src 'none'; base-uri 'none'; "
                  "frame-ancestors 'none'")
        _p, f = audit(policy)
        for x in f:
            self.assertNotIn(x.severity, ("HIGH", "CRITICAL"),
                             f"unexpected {x.severity}: {x}")

    def test_data_in_script_src_high(self):
        _p, f = audit("default-src 'self'; script-src data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.assertEqual(self._sev(f, "script-src", "data:"), "HIGH")


if __name__ == "__main__":
    unittest.main()
