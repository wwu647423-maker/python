import hashlib
import unittest

from cyberkit.hashcrack import crack, mutate


class TestMutate(unittest.TestCase):
    def test_yields_word_first(self):
        muts = list(mutate("hello"))
        self.assertEqual(muts[0], "hello")

    def test_includes_case_variants(self):
        muts = set(mutate("hello"))
        self.assertIn("HELLO", muts)
        self.assertIn("Hello", muts)

    def test_includes_digit_suffix(self):
        muts = set(mutate("hello"))
        self.assertIn("hello123", muts)
        self.assertIn("Hello123", muts)

    def test_includes_year_suffix(self):
        muts = set(mutate("admin"))
        self.assertTrue(any(m.startswith("admin") and m[5:].isdigit() and len(m) == 9 for m in muts))

    def test_includes_leet(self):
        muts = set(mutate("password"))
        self.assertIn("p@$$w0rd", muts)

    def test_includes_reverse(self):
        muts = set(mutate("hello"))
        self.assertIn("olleh", muts)

    def test_empty_input(self):
        self.assertEqual(list(mutate("")), [])


class TestCrackWithRules(unittest.TestCase):
    def test_finds_capitalized_with_suffix(self):
        target = hashlib.md5(b"Hello123").hexdigest()
        wordlist = ["world", "hello", "foo"]
        self.assertEqual(crack(target, iter(wordlist), "md5", rules=True), "Hello123")

    def test_misses_without_rules(self):
        target = hashlib.md5(b"Hello123").hexdigest()
        wordlist = ["world", "hello", "foo"]
        self.assertIsNone(crack(target, iter(wordlist), "md5", rules=False))

    def test_finds_leet(self):
        target = hashlib.md5(b"p@$$w0rd").hexdigest()
        wordlist = ["password"]
        self.assertEqual(crack(target, iter(wordlist), "md5", rules=True), "p@$$w0rd")

    def test_finds_reversed(self):
        target = hashlib.sha256(b"olleh").hexdigest()
        self.assertEqual(crack(target, iter(["hello"]), "sha256", rules=True), "olleh")


if __name__ == "__main__":
    unittest.main()
