import unittest

from cyberkit.mailcheck import audit_dmarc, audit_spf


class TestSPF(unittest.TestCase):
    def test_missing(self):
        rec, f = audit_spf([])
        self.assertIsNone(rec)
        self.assertTrue(any("no SPF" in x.message for x in f))

    def test_plus_all_critical(self):
        _r, f = audit_spf(["v=spf1 +all"])
        self.assertTrue(any(x.severity == "CRITICAL" and "+all" in x.message for x in f))

    def test_softfail_low(self):
        _r, f = audit_spf(["v=spf1 include:_spf.example.com ~all"])
        sevs = [x.severity for x in f]
        self.assertIn("LOW", sevs)
        self.assertNotIn("CRITICAL", sevs)
        self.assertNotIn("HIGH", sevs)

    def test_strict_fail_clean(self):
        _r, f = audit_spf(["v=spf1 include:_spf.example.com -all"])
        sevs = [x.severity for x in f]
        self.assertNotIn("CRITICAL", sevs)
        self.assertNotIn("HIGH", sevs)
        self.assertNotIn("MED", sevs)

    def test_no_terminal_med(self):
        _r, f = audit_spf(["v=spf1 include:_spf.example.com"])
        self.assertTrue(any(x.severity == "MED" and "terminal" in x.message for x in f))

    def test_lookup_overflow(self):
        rec = "v=spf1 " + " ".join(f"include:s{i}.example.com" for i in range(12)) + " -all"
        _r, f = audit_spf([rec])
        self.assertTrue(any("10 lookups" in x.message or "RFC 7208" in x.message for x in f))

    def test_multiple_records_high(self):
        _r, f = audit_spf(["v=spf1 -all", "v=spf1 +all"])
        self.assertTrue(any("multiple SPF" in x.message for x in f))


class TestDMARC(unittest.TestCase):
    def test_missing(self):
        rec, f = audit_dmarc([])
        self.assertIsNone(rec)
        self.assertTrue(any("no DMARC" in x.message for x in f))

    def test_p_none_high(self):
        _r, f = audit_dmarc(["v=DMARC1; p=none; rua=mailto:r@example.com"])
        self.assertTrue(any(x.severity == "HIGH" and "p=none" in x.message for x in f))

    def test_p_reject_clean(self):
        _r, f = audit_dmarc(["v=DMARC1; p=reject; rua=mailto:r@example.com; pct=100"])
        sevs = [x.severity for x in f]
        self.assertNotIn("HIGH", sevs)
        self.assertNotIn("CRITICAL", sevs)

    def test_pct_partial(self):
        _r, f = audit_dmarc(["v=DMARC1; p=reject; pct=10; rua=mailto:r@example.com"])
        self.assertTrue(any("pct=10" in x.message for x in f))

    def test_missing_rua(self):
        _r, f = audit_dmarc(["v=DMARC1; p=reject"])
        self.assertTrue(any("rua" in x.message for x in f))


if __name__ == "__main__":
    unittest.main()
