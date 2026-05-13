import socket
import threading
import unittest

from cyberkit.whois import _follow_referrals, _query


class _WhoisServer:
    """Minimal in-process WHOIS server for tests."""

    def __init__(self, response: str):
        self.response = response.encode()
        self.received: list[str] = []
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        self.sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                data = b""
                while b"\n" not in data and len(data) < 1024:
                    chunk = conn.recv(256)
                    if not chunk:
                        break
                    data += chunk
                self.received.append(data.decode("utf-8", errors="replace").strip())
                conn.sendall(self.response)
            finally:
                conn.close()
        self.sock.close()

    def __enter__(self):
        self._t.start()
        return self

    def __exit__(self, *_a):
        self._stop.set()
        self._t.join(timeout=2)


class TestFollowReferrals(unittest.TestCase):
    def test_refer_line(self):
        self.assertEqual(_follow_referrals("refer: whois.verisign-grs.com\n"),
                         "whois.verisign-grs.com")

    def test_whois_line(self):
        self.assertEqual(_follow_referrals("whois: whois.nic.io\n"),
                         "whois.nic.io")

    def test_referral_server_line(self):
        self.assertEqual(_follow_referrals("ReferralServer: whois://rwhois.arin.net\n"),
                         "rwhois.arin.net")

    def test_registrar_takes_precedence(self):
        text = ("refer: whois.iana.org\n"
                "Registrar WHOIS Server: whois.markmonitor.com\n")
        self.assertEqual(_follow_referrals(text), "whois.markmonitor.com")

    def test_no_match(self):
        self.assertIsNone(_follow_referrals("nothing relevant here"))

    def test_ignores_garbage_host(self):
        self.assertIsNone(_follow_referrals("refer: not-a-host\n"))


class TestQuery(unittest.TestCase):
    def test_round_trip_against_fake_server(self):
        with _WhoisServer("Domain Name: EXAMPLE.COM\nNo referral here.\n") as srv:
            resp = _query("127.0.0.1", "example.com", timeout=2, port=srv.port)
        self.assertIn("EXAMPLE.COM", resp)
        self.assertEqual(srv.received, ["example.com"])


if __name__ == "__main__":
    unittest.main()
