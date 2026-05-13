import unittest

from cyberkit.entropy import detect_magic


class TestMagic(unittest.TestCase):
    def test_elf(self):
        self.assertIn("ELF", detect_magic(b"\x7fELF\x02\x01\x01\x00rest"))

    def test_pe(self):
        self.assertIn("PE", detect_magic(b"MZ\x90\x00\x03\x00..."))

    def test_png(self):
        self.assertIn("PNG", detect_magic(b"\x89PNG\r\n\x1a\nIHDR"))

    def test_jpeg(self):
        self.assertIn("JPEG", detect_magic(b"\xff\xd8\xff\xe0\x00\x10JFIF"))

    def test_pdf(self):
        self.assertIn("PDF", detect_magic(b"%PDF-1.7\n"))

    def test_zip(self):
        self.assertIn("ZIP", detect_magic(b"PK\x03\x04..."))

    def test_gzip(self):
        self.assertIn("gzip", detect_magic(b"\x1f\x8b\x08\x00data"))

    def test_sqlite(self):
        self.assertIn("SQLite", detect_magic(b"SQLite format 3\x00" + b"\x00" * 90))

    def test_ascii_text(self):
        self.assertIn("ASCII", detect_magic(b"Hello world\nplain text"))

    def test_unknown(self):
        m = detect_magic(b"\xde\xad\xbe\xef\x00\xff\xa5\x5a")
        self.assertEqual(m, "unknown / no magic match")


if __name__ == "__main__":
    unittest.main()
