import unittest

from cyberkit.hexview import hexdump


class TestHexView(unittest.TestCase):
    def test_one_line(self):
        out = hexdump(b"Hello, world!\x00")
        line = out.splitlines()[0]
        self.assertTrue(line.startswith("00000000"))
        self.assertIn("48 65 6c 6c 6f", line)
        self.assertIn("|Hello, world!.|", line)

    def test_multi_line_offset(self):
        data = bytes(range(64))
        out = hexdump(data, offset=0x1000)
        self.assertEqual(len(out.splitlines()), 4)
        self.assertTrue(out.splitlines()[0].startswith("00001000"))
        self.assertTrue(out.splitlines()[3].startswith("00001030"))

    def test_unprintable_replaced(self):
        out = hexdump(bytes([0, 1, 2, 30, 31, 32, 127, 128]))
        line = out.splitlines()[0]
        self.assertIn("|..... ..|", line)

    def test_no_trailing_newline(self):
        out = hexdump(b"x")
        self.assertFalse(out.endswith("\n"))


if __name__ == "__main__":
    unittest.main()
