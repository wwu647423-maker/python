import hashlib
import unittest

from cyberkit.hashcrack import crack


WORDLIST = ["apple", "banana", "hunter2", "letmein", "p@ssw0rd"]


class TestHashCrack(unittest.TestCase):
    def test_md5_hit(self):
        target = hashlib.md5(b"hunter2").hexdigest()
        self.assertEqual(crack(target, iter(WORDLIST), "md5"), "hunter2")

    def test_sha1_hit(self):
        target = hashlib.sha1(b"banana").hexdigest()
        self.assertEqual(crack(target, iter(WORDLIST), "sha1"), "banana")

    def test_sha256_miss(self):
        target = hashlib.sha256(b"not-in-list").hexdigest()
        self.assertIsNone(crack(target, iter(WORDLIST), "sha256"))

    def test_sha512_hit(self):
        target = hashlib.sha512(b"apple").hexdigest()
        self.assertEqual(crack(target, iter(WORDLIST), "sha512"), "apple")

    def test_salt_prepend(self):
        target = hashlib.md5(b"NaCl" + b"banana").hexdigest()
        self.assertEqual(crack(target, iter(WORDLIST), "md5", salt="NaCl"),
                         "banana")

    def test_salt_append(self):
        target = hashlib.md5(b"banana" + b"NaCl").hexdigest()
        self.assertEqual(
            crack(target, iter(WORDLIST), "md5", salt="NaCl", salt_append=True),
            "banana",
        )

    def test_ntlm(self):
        from cyberkit.hashcrack import ALGOS
        target = ALGOS["ntlm"](b"Password1")
        self.assertEqual(crack(target, iter(["Password1"]), "ntlm"), "Password1")


if __name__ == "__main__":
    unittest.main()
