import os
import unittest

from cyberkit.entropy import shannon_entropy, windowed_entropy


class TestEntropy(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(shannon_entropy(b""), 0.0)

    def test_constant_is_zero(self):
        self.assertEqual(shannon_entropy(b"A" * 1000), 0.0)

    def test_two_values_is_one_bit(self):
        data = (b"\x00" * 500) + (b"\xff" * 500)
        self.assertAlmostEqual(shannon_entropy(data), 1.0, places=6)

    def test_uniform_random_is_high(self):
        h = shannon_entropy(os.urandom(8192))
        self.assertGreater(h, 7.5)

    def test_text_is_mid_range(self):
        data = (b"The quick brown fox jumps over the lazy dog. " * 200)
        h = shannon_entropy(data)
        self.assertGreater(h, 3.5)
        self.assertLess(h, 5.5)

    def test_windows_split_data(self):
        data = b"A" * 100 + b"B" * 100
        wins = windowed_entropy(data, 100)
        self.assertEqual(len(wins), 2)
        self.assertEqual(wins[0], 0.0)
        self.assertEqual(wins[1], 0.0)


if __name__ == "__main__":
    unittest.main()
