import unittest

from cyberkit.hashid import identify


class TestHashId(unittest.TestCase):
    def _top(self, h: str) -> str:
        return identify(h)[0].name

    def test_md5(self):
        self.assertEqual(self._top("5d41402abc4b2a76b9719d911017c592"), "MD5")

    def test_sha1(self):
        self.assertEqual(self._top("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"), "SHA-1")

    def test_sha256(self):
        digest = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        self.assertEqual(self._top(digest), "SHA-256")

    def test_sha512(self):
        digest = ("309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f"
                  "989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f")
        self.assertEqual(self._top(digest), "SHA-512")

    def test_bcrypt(self):
        h = "$2b$12$Eix5pY8b8.q1IUxQbm3oU.UJ3CmCm5lyDjGgEgETgPDb4uXVZWXxK"
        self.assertEqual(self._top(h), "bcrypt")

    def test_argon2(self):
        h = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
        self.assertEqual(self._top(h), "Argon2")

    def test_sha512crypt(self):
        h = "$6$rounds=5000$salt$JpL3FfvNmS6vY3qiSY/CcVoTb9F1iyl4q9rxsTcDPK9eOd0lTzlBSWnEPGGNkSqVRJSyXcSY8gTcRSwYV.6jh."
        self.assertEqual(self._top(h), "sha512crypt")

    def test_unknown(self):
        self.assertEqual(self._top("hello world"), "unknown")


if __name__ == "__main__":
    unittest.main()
