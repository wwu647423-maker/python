import string
import unittest

from cyberkit.passwordgen import (AMBIGUOUS, DEFAULT_WORDS,
                                   estimate_entropy_bits, gen_passphrase,
                                   gen_pin, gen_random)


class TestRandomPassword(unittest.TestCase):
    def test_length(self):
        for n in (8, 12, 20, 40, 100):
            self.assertEqual(len(gen_random(n)), n)

    def test_contains_each_class_by_default(self):
        pw = gen_random(40)
        self.assertTrue(any(c.islower() for c in pw))
        self.assertTrue(any(c.isupper() for c in pw))
        self.assertTrue(any(c.isdigit() for c in pw))
        self.assertTrue(any(not c.isalnum() for c in pw))

    def test_disable_symbols(self):
        for _ in range(5):
            pw = gen_random(40, symbol=False)
            self.assertFalse(any(not c.isalnum() for c in pw))

    def test_no_ambiguous(self):
        for _ in range(8):
            pw = gen_random(80, no_ambiguous=True)
            self.assertFalse(any(c in AMBIGUOUS for c in pw))

    def test_rejects_too_short(self):
        with self.assertRaises(ValueError):
            gen_random(2)

    def test_rejects_no_classes(self):
        with self.assertRaises(ValueError):
            gen_random(10, lower=False, upper=False, digit=False, symbol=False)

    def test_uniqueness_across_calls(self):
        samples = {gen_random(20) for _ in range(50)}
        self.assertGreaterEqual(len(samples), 49)


class TestPassphrase(unittest.TestCase):
    def test_word_count(self):
        p = gen_passphrase(6, sep="-")
        self.assertEqual(len(p.split("-")), 6)

    def test_separator(self):
        p = gen_passphrase(4, sep="_")
        self.assertEqual(len(p.split("_")), 4)

    def test_capitalize(self):
        p = gen_passphrase(4, capitalize=True)
        for word in p.split("-"):
            self.assertTrue(word[0].isupper())

    def test_add_digit(self):
        p = gen_passphrase(3, add_digit=True)
        self.assertTrue(p[-1].isdigit())

    def test_wordlist_size_reasonable(self):
        self.assertGreater(len(DEFAULT_WORDS), 200)


class TestPin(unittest.TestCase):
    def test_length(self):
        self.assertEqual(len(gen_pin(4)), 4)
        self.assertEqual(len(gen_pin(6)), 6)
        self.assertEqual(len(gen_pin(12)), 12)

    def test_all_digits(self):
        for _ in range(20):
            self.assertTrue(gen_pin(8).isdigit())


class TestEntropy(unittest.TestCase):
    def test_entropy_grows_with_length(self):
        self.assertLess(estimate_entropy_bits("abc"),
                        estimate_entropy_bits("abcdefghijklmno"))

    def test_entropy_grows_with_classes(self):
        only_lower = estimate_entropy_bits("aaaaaaaaaa")
        mixed = estimate_entropy_bits("aA1!aA1!aA")
        self.assertLess(only_lower, mixed)


if __name__ == "__main__":
    unittest.main()
