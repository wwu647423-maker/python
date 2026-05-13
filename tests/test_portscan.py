import socket
import threading
import time
import unittest

from cyberkit.portscan import parse_ports, scan_port


def _ephemeral_listener(host: str = "127.0.0.1"):
    """Open a TCP server on a free port. Returns (port, stop_callable)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, 0))
    srv.listen(8)
    port = srv.getsockname()[1]

    stop = threading.Event()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.sendall(b"SSH-2.0-Test\r\n")
            except OSError:
                pass
            finally:
                conn.close()
        srv.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()

    def stopper():
        stop.set()
        t.join(timeout=2)

    return port, stopper


class TestParsePorts(unittest.TestCase):
    def test_csv(self):
        self.assertEqual(parse_ports("22,80,443"), [22, 80, 443])

    def test_range(self):
        self.assertEqual(parse_ports("80-85"), [80, 81, 82, 83, 84, 85])

    def test_mix(self):
        self.assertEqual(parse_ports("22,80-82,443"), [22, 80, 81, 82, 443])

    def test_top100(self):
        ports = parse_ports("top100")
        self.assertIn(22, ports)
        self.assertIn(80, ports)
        self.assertIn(443, ports)

    def test_invalid(self):
        with self.assertRaises(ValueError):
            parse_ports("0-100")
        with self.assertRaises(ValueError):
            parse_ports("70000")


class TestScanPort(unittest.TestCase):
    def test_open_port_detected(self):
        port, stop = _ephemeral_listener()
        try:
            time.sleep(0.05)
            result = scan_port("127.0.0.1", port, timeout=1.0, banner=True)
            self.assertIsNotNone(result)
            self.assertEqual(result["port"], port)
            self.assertEqual(result["state"], "open")
            self.assertIn("SSH-2.0-Test", result["banner"])
        finally:
            stop()

    def test_closed_port_returns_none(self):
        result = scan_port("127.0.0.1", 1, timeout=0.3, banner=False)
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
