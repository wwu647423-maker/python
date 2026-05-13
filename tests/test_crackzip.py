import os
import subprocess
import tempfile
import unittest
import zipfile

from cyberkit.crackzip import (_ZCKeys, _zipcrypto_check, _entry_check_byte,
                                 _read_encryption_header, crack)


def _make_encrypted_zip(path: str, password: str, name: str = "secret.txt",
                          content: bytes = b"hello\n") -> None:
    """Build an encrypted ZIP using the 'zip' CLI which writes real
    ZipCrypto. stdlib zipfile cannot *create* encrypted zips, only
    decrypt them, so we shell out — skip the test if zip(1) is missing."""
    if subprocess.call(["which", "zip"], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL) != 0:
        raise unittest.SkipTest("`zip` binary not available")
    src = os.path.join(os.path.dirname(path), name)
    with open(src, "wb") as fh:
        fh.write(content)
    if os.path.exists(path):
        os.remove(path)
    subprocess.check_call(
        ["zip", "-P", password, "-j", path, src],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


class TestZipCryptoLowLevel(unittest.TestCase):
    def test_keys_deterministic(self):
        a = _ZCKeys()
        b = _ZCKeys()
        for byte in b"hello":
            a.update(byte)
            b.update(byte)
        self.assertEqual((a.k0, a.k1, a.k2), (b.k0, b.k1, b.k2))

    def test_stream_byte_differs_after_update(self):
        k = _ZCKeys()
        s0 = k.stream_byte()
        k.update(0x41)
        s1 = k.stream_byte()
        self.assertNotEqual(s0, s1)


class TestCrackEnd2End(unittest.TestCase):
    def test_crack_known_password(self):
        with tempfile.TemporaryDirectory() as tmp:
            zpath = os.path.join(tmp, "t.zip")
            _make_encrypted_zip(zpath, password="monkey")
            words = ["foo", "bar", "letmein", "monkey", "baz"]
            self.assertEqual(crack(zpath, iter(words), workers=1), "monkey")

    def test_crack_with_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            zpath = os.path.join(tmp, "t.zip")
            _make_encrypted_zip(zpath, password="Welcome2024")
            words = ["welcome"]
            self.assertEqual(crack(zpath, iter(words), rules=True, workers=1),
                             "Welcome2024")

    def test_miss(self):
        with tempfile.TemporaryDirectory() as tmp:
            zpath = os.path.join(tmp, "t.zip")
            _make_encrypted_zip(zpath, password="completely-not-in-list")
            words = ["aaa", "bbb", "ccc"]
            self.assertIsNone(crack(zpath, iter(words), workers=1))

    def test_unencrypted_zip_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            zpath = os.path.join(tmp, "open.zip")
            with zipfile.ZipFile(zpath, "w") as zf:
                zf.writestr("hello.txt", b"plain")
            with self.assertRaises(ValueError):
                crack(zpath, iter(["x"]))


if __name__ == "__main__":
    unittest.main()
