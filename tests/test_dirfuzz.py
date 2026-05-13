import http.server
import socketserver
import threading
import time
import unittest

from cyberkit.dirfuzz import Fingerprint, Probe, calibrate_404, fuzz, is_noise


class _Handler(http.server.BaseHTTPRequestHandler):
    real_paths = {"/admin": (200, b"<title>Admin</title>admin page body" * 5),
                  "/api/v1": (200, b"<title>API</title>api index"),
                  "/secret": (403, b"forbidden")}

    def do_GET(self):
        for p, (code, body) in self.real_paths.items():
            if self.path == p:
                self.send_response(code)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
        body = b"<title>Not Found</title>this page does not exist."
        self.send_response(404)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args, **_kwargs):
        pass


class _ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


class TestDirfuzz(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = _ReusableTCPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _base(self):
        return f"http://127.0.0.1:{self.port}"

    def test_calibrate_picks_up_404(self):
        fp = calibrate_404(self._base(), timeout=2.0, ua="test")
        self.assertTrue(fp.valid)
        self.assertEqual(fp.status, 404)

    def test_is_noise_filters_404_status(self):
        fp = Fingerprint(404, -1, "", True)
        noise = Probe("/foo", "u", 404, 30, "", "", "", "")
        real = Probe("/admin", "u", 200, 80, "", "", "", "")
        self.assertTrue(is_noise(noise, fp))
        self.assertFalse(is_noise(real, fp))

    def test_fuzz_finds_real_paths(self):
        words = ["admin", "api/v1", "secret", "missing", "another-missing"]
        fp = calibrate_404(self._base(), timeout=2.0, ua="test")
        hits = fuzz(self._base(), words, workers=4, timeout=2.0, ua="test", fingerprint=fp)
        paths = {h.path for h in hits}
        self.assertIn("/admin", paths)
        self.assertIn("/api/v1", paths)
        self.assertIn("/secret", paths)
        self.assertNotIn("/missing", paths)
        self.assertNotIn("/another-missing", paths)


if __name__ == "__main__":
    unittest.main()
