import unittest

from cyberkit.xorcrack import (brute_repeating, brute_single,
                                estimate_keysize, score_english, xor)


PLAINTEXT = (
    b"The quick brown fox jumps over the lazy dog. "
    b"This is a sample English sentence used to seed cryptanalysis tests. "
    b"It contains plenty of common letters like e, t, a, o, i, n, s, h, r."
)


class TestXorCrack(unittest.TestCase):
    def test_xor_self_inverse(self):
        ct = xor(PLAINTEXT, b"abcdef")
        self.assertEqual(xor(ct, b"abcdef"), PLAINTEXT)

    def test_score_english_prefers_plaintext(self):
        ct = xor(PLAINTEXT, b"\x42")
        self.assertLess(score_english(PLAINTEXT), score_english(ct))

    def test_brute_single_recovers_key(self):
        ct = xor(PLAINTEXT, b"\x42")
        best = brute_single(ct, top=1)[0]
        self.assertEqual(best.key, 0x42)
        self.assertEqual(best.plaintext, PLAINTEXT)

    def test_brute_single_random_key(self):
        for k in (0x01, 0x33, 0x7F, 0xAB, 0xFE):
            ct = xor(PLAINTEXT, bytes([k]))
            best = brute_single(ct, top=1)[0]
            self.assertEqual(best.key, k, f"failed for key 0x{k:02x}")

    def test_estimate_keysize_prefers_correct(self):
        key = b"sekret"
        ct = xor(PLAINTEXT * 5, key)
        cands = [k for k, _ in estimate_keysize(ct, kmin=2, kmax=12)[:3]]
        self.assertTrue(any(k % len(key) == 0 for k in cands),
                        f"expected a multiple of {len(key)} in {cands}")

    def test_brute_repeating_recovers(self):
        key = b"ICE"
        ct = xor(PLAINTEXT * 4, key)
        recovered, pt = brute_repeating(ct, kmin=2, kmax=10)
        self.assertEqual(pt, PLAINTEXT * 4)
        self.assertEqual(recovered, key)


if __name__ == "__main__":
    unittest.main()
