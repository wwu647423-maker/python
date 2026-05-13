import ipaddress
import unittest

from cyberkit.cidr import _net, contains, info, split, summarize


class TestInfo(unittest.TestCase):
    def test_ipv4_slash24(self):
        d = info(_net("10.0.0.0/24"))
        self.assertEqual(d["network"], "10.0.0.0")
        self.assertEqual(d["broadcast"], "10.0.0.255")
        self.assertEqual(d["prefix_length"], 24)
        self.assertEqual(d["num_addresses"], 256)
        self.assertEqual(d["first_host"], "10.0.0.1")
        self.assertEqual(d["last_host"], "10.0.0.254")
        self.assertTrue(d["is_private"])
        self.assertFalse(d["is_global"])

    def test_ipv4_slash32(self):
        d = info(_net("1.2.3.4/32"))
        self.assertEqual(d["num_addresses"], 1)

    def test_ipv6(self):
        d = info(_net("2001:db8::/64"))
        self.assertEqual(d["version"], 6)
        self.assertIsNone(d["broadcast"])
        self.assertEqual(d["num_addresses"], 2 ** 64)

    def test_non_strict_input(self):
        d = info(_net("10.0.0.5/24"))
        self.assertEqual(d["network"], "10.0.0.0")


class TestContains(unittest.TestCase):
    def test_in(self):
        self.assertTrue(contains(_net("10.0.0.0/8"), ipaddress.ip_address("10.20.30.40")))

    def test_out(self):
        self.assertFalse(contains(_net("10.0.0.0/8"), ipaddress.ip_address("11.0.0.1")))

    def test_version_mismatch(self):
        self.assertFalse(contains(_net("10.0.0.0/8"),
                                  ipaddress.ip_address("::1")))


class TestSummarize(unittest.TestCase):
    def test_collapse_contiguous(self):
        self.assertEqual(summarize(["10.0.0.0/25", "10.0.0.128/25"]),
                         ["10.0.0.0/24"])

    def test_collapse_individual_ips(self):
        self.assertEqual(summarize(["10.0.0.1", "10.0.0.2", "10.0.0.3"]),
                         ["10.0.0.1/32", "10.0.0.2/31"])

    def test_mixed_v4_v6(self):
        out = summarize(["10.0.0.0/24", "2001:db8::/64"])
        self.assertIn("10.0.0.0/24", out)
        self.assertIn("2001:db8::/64", out)

    def test_invalid_raises(self):
        with self.assertRaises(ValueError):
            summarize(["not-a-cidr"])


class TestSplit(unittest.TestCase):
    def test_split_24_into_26(self):
        parts = split(_net("10.0.0.0/24"), 26)
        self.assertEqual(parts, ["10.0.0.0/26", "10.0.0.64/26",
                                  "10.0.0.128/26", "10.0.0.192/26"])

    def test_split_invalid_smaller_prefix_raises(self):
        with self.assertRaises(ValueError):
            split(_net("10.0.0.0/24"), 16)


if __name__ == "__main__":
    unittest.main()
