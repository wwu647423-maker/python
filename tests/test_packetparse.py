import struct
import unittest

from cyberkit.packetparse import (_normalize_hex, auto_decode, parse_arp,
                                   parse_ethernet, parse_ipv4, parse_ipv6,
                                   parse_tcp, parse_udp)


def _build_eth_ip4_tcp(src_port=12345, dst_port=80, payload=b"GET /\r\n"):
    eth = bytes.fromhex("aabbccddeeff112233445566") + struct.pack(">H", 0x0800)
    ip_total = 20 + 20 + len(payload)
    ip_hdr = bytes([0x45, 0]) + struct.pack(">H", ip_total) + struct.pack(
        ">HHBBH", 0xCAFE, 0, 64, 6, 0) + bytes([10, 0, 0, 1, 8, 8, 8, 8])
    tcp_hdr = struct.pack(">HHIIHHHH", src_port, dst_port, 1, 0,
                          0x5018, 64240, 0, 0)
    return eth + ip_hdr + tcp_hdr + payload


def _build_eth_ip4_udp_dns():
    eth = bytes.fromhex("aabbccddeeff112233445566") + struct.pack(">H", 0x0800)
    qname = b"\x07example\x03com\x00"
    dns_header = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    dns_q = qname + struct.pack(">HH", 1, 1)
    dns_ans = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + bytes([1, 2, 3, 4])
    dns_payload = dns_header + dns_q + dns_ans
    udp_total = 8 + len(dns_payload)
    udp_hdr = struct.pack(">HHHH", 53, 33333, udp_total, 0)
    ip_total = 20 + udp_total
    ip_hdr = bytes([0x45, 0]) + struct.pack(">H", ip_total) + struct.pack(
        ">HHBBH", 0xDEAD, 0, 64, 17, 0) + bytes([8, 8, 8, 8, 10, 0, 0, 5])
    return eth + ip_hdr + udp_hdr + dns_payload


class TestNormalize(unittest.TestCase):
    def test_strip_punctuation(self):
        self.assertEqual(_normalize_hex("0x0000:  4500 003c"), b"\x45\x00\x00\x3c")

    def test_odd_nibbles_raise(self):
        with self.assertRaises(ValueError):
            _normalize_hex("4500003")


class TestParse(unittest.TestCase):
    def test_ethernet_ipv4_tcp(self):
        pkt = _build_eth_ip4_tcp()
        out = parse_ethernet(pkt)
        self.assertEqual(out["ethertype_name"], "IPv4")
        ip = out["ipv4"]
        self.assertEqual(ip["src"], "10.0.0.1")
        self.assertEqual(ip["dst"], "8.8.8.8")
        self.assertEqual(ip["protocol_name"], "TCP")
        tcp = ip["tcp"]
        self.assertEqual(tcp["src_port"], 12345)
        self.assertEqual(tcp["dst_port"], 80)
        self.assertIn("PSH", tcp["flags"])
        self.assertIn("ACK", tcp["flags"])
        self.assertIn("GET /", tcp["payload_preview"])

    def test_dns_over_udp(self):
        pkt = _build_eth_ip4_udp_dns()
        out = parse_ethernet(pkt)
        dns = out["ipv4"]["udp"]["dns"]
        self.assertEqual(dns["rcode"], 0)
        a = [r for r in dns["records"] if r["rtype"] == "A"]
        self.assertEqual(a[0]["data"], "1.2.3.4")

    def test_ipv6_min_header(self):
        hdr = (struct.pack(">IHBB", (6 << 28), 0, 59, 64)
               + b"\x20\x01\x0d\xb8" + b"\x00" * 12
               + b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x01")
        out = parse_ipv6(hdr)
        self.assertEqual(out["version"], 6)
        self.assertEqual(out["src"], "2001:db8::")
        self.assertEqual(out["dst"], "2001:db8::1")

    def test_arp_request(self):
        arp = struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1) \
              + bytes.fromhex("aabbccddeeff") + bytes([10, 0, 0, 1]) \
              + bytes(6) + bytes([10, 0, 0, 100])
        out = parse_arp(arp)
        self.assertEqual(out["sender_ip"], "10.0.0.1")
        self.assertEqual(out["target_ip"], "10.0.0.100")
        self.assertEqual(out["op"], 1)


class TestAutoDecode(unittest.TestCase):
    def test_auto_picks_ethernet(self):
        out = auto_decode(_build_eth_ip4_tcp())
        self.assertEqual(out["layer"], "ethernet")

    def test_auto_picks_ipv4_without_ethernet(self):
        pkt = _build_eth_ip4_tcp()[14:]
        out = auto_decode(pkt)
        self.assertEqual(out["layer"], "ipv4")

    def test_short_or_garbage(self):
        out = auto_decode(b"\xff\xff")
        self.assertEqual(out["layer"], "unknown")


if __name__ == "__main__":
    unittest.main()
