import unittest

from cyberkit.baseconv import (DECODERS, ENCODERS, autodetect, decode_base58,
                                encode_base58, rot_n)


SAMPLE = b"hello, world!"


class TestBaseConv(unittest.TestCase):
    def test_roundtrip_all_schemes(self):
        for name, enc in ENCODERS.items():
            dec = DECODERS[name]
            self.assertEqual(dec(enc(SAMPLE)), SAMPLE,
                             f"{name} roundtrip failed")

    def test_base58_known_vector(self):
        self.assertEqual(encode_base58(b"\x00\x00abc"), "11ZiCa")
        self.assertEqual(decode_base58("11ZiCa"), b"\x00\x00abc")

    def test_base58_leading_zeros(self):
        for n in range(0, 5):
            data = b"\x00" * n + b"\x01\x02"
            self.assertEqual(decode_base58(encode_base58(data)), data)

    def test_rot13_involution(self):
        self.assertEqual(rot_n(rot_n("Hello, World!", 13), 13), "Hello, World!")

    def test_rot_n_alphabet_only(self):
        self.assertEqual(rot_n("abc XYZ 123", 3), "def ABC 123")

    def test_autodetect_base64(self):
        import base64
        text = base64.b64encode(b"the quick brown fox jumps over the lazy dog").decode()
        cands = autodetect(text)
        self.assertTrue(cands)
        self.assertEqual(cands[0][0], "base64")
        self.assertIn(b"the quick", cands[0][1])

    def test_autodetect_rot13(self):
        text = rot_n("the quick brown fox jumps over the lazy dog", 13)
        cands = autodetect(text)
        rot_methods = [c for c in cands if c[0].startswith("rot")]
        self.assertTrue(rot_methods)
        best = rot_methods[0]
        self.assertEqual(best[0], "rot13")
        self.assertIn(b"the quick", best[1])

    def test_autodetect_returns_empty_or_low_score_for_clearly_binary_input(self):
        cands = autodetect("\x00\x01\x02non-printable garbage \x7f\x7f\x7f")
        for _m, _d, s in cands:
            self.assertLess(s, 100)


if __name__ == "__main__":
    unittest.main()
