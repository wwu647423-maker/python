import struct
import unittest

from cyberkit._dns import (DnsError, TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_MX,
                            TYPE_NS, TYPE_SOA, TYPE_TXT, _decode_name,
                            _encode_name, build_query, parse_response)


def _build_response(qname: bytes, answers: list[bytes], rcode: int = 0) -> bytes:
    flags = 0x8180 | (rcode & 0xF)
    header = struct.pack(">HHHHHH", 0x1234, flags, 1, len(answers), 0, 0)
    question = qname + struct.pack(">HH", 1, 1)
    return header + question + b"".join(answers)


def _a_rr(name_offset: int, ip: bytes, ttl: int = 300) -> bytes:
    return struct.pack(">HHHIH", 0xC000 | name_offset, 1, 1, ttl, 4) + ip


class TestEncoding(unittest.TestCase):
    def test_encode_simple(self):
        self.assertEqual(_encode_name("example.com"),
                         b"\x07example\x03com\x00")

    def test_encode_root(self):
        self.assertEqual(_encode_name(""), b"\x00")
        self.assertEqual(_encode_name("."), b"\x00")

    def test_decode_no_compression(self):
        wire = b"\x07example\x03com\x00"
        name, off = _decode_name(wire, 0)
        self.assertEqual(name, "example.com")
        self.assertEqual(off, len(wire))

    def test_decode_with_compression(self):
        wire = b"\x05hello\x00" + b"\x05world" + b"\xc0\x00"
        name, _off = _decode_name(wire, 7)
        self.assertEqual(name, "world.hello")

    def test_loop_protection(self):
        wire = b"\x00\xc0\x00"
        with self.assertRaises(DnsError):
            _decode_name(wire, 1, depth=33)


class TestQueryBuild(unittest.TestCase):
    def test_query_header_flags(self):
        pkt = build_query("example.com", TYPE_A, qid=0xABCD)
        qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", pkt[:12])
        self.assertEqual(qid, 0xABCD)
        self.assertEqual(flags, 0x0100)
        self.assertEqual(qd, 1)
        self.assertEqual((an, ns, ar), (0, 0, 0))


class TestResponseParsing(unittest.TestCase):
    def _qname(self):
        return b"\x07example\x03com\x00"

    def test_a_record(self):
        pkt = _build_response(self._qname(),
                              [_a_rr(12, bytes([1, 2, 3, 4]), ttl=300)])
        _r, recs = parse_response(pkt)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].rtype, "A")
        self.assertEqual(recs[0].data, "1.2.3.4")
        self.assertEqual(recs[0].ttl, 300)

    def test_aaaa_record(self):
        qname = self._qname()
        rdata = bytes.fromhex("20010db8000000000000000000000001")
        rr = struct.pack(">HHHIH", 0xC00C, TYPE_AAAA, 1, 60, 16) + rdata
        pkt = _build_response(qname, [rr])
        _r, recs = parse_response(pkt)
        self.assertEqual(recs[0].rtype, "AAAA")
        self.assertEqual(recs[0].data, "2001:db8::1")

    def test_mx_record(self):
        qname = self._qname()
        rdata = struct.pack(">H", 10) + b"\x04mail\xc0\x0c"
        rr = struct.pack(">HHHIH", 0xC00C, TYPE_MX, 1, 60, len(rdata)) + rdata
        pkt = _build_response(qname, [rr])
        _r, recs = parse_response(pkt)
        self.assertEqual(recs[0].rtype, "MX")
        self.assertEqual(recs[0].data, "10 mail.example.com")

    def test_txt_record_multistring(self):
        qname = self._qname()
        s1 = b"v=spf1 include:_spf.example -all"
        s2 = b"more"
        rdata = bytes([len(s1)]) + s1 + bytes([len(s2)]) + s2
        rr = struct.pack(">HHHIH", 0xC00C, TYPE_TXT, 1, 60, len(rdata)) + rdata
        pkt = _build_response(qname, [rr])
        _r, recs = parse_response(pkt)
        self.assertEqual(recs[0].rtype, "TXT")
        self.assertIn("v=spf1", recs[0].data)
        self.assertIn("more", recs[0].data)

    def test_nxdomain(self):
        pkt = _build_response(self._qname(), [], rcode=3)
        rcode, recs = parse_response(pkt)
        self.assertEqual(rcode, 3)
        self.assertEqual(recs, [])

    def test_truncated_packet_raises(self):
        with self.assertRaises(DnsError):
            parse_response(b"\x00" * 5)


if __name__ == "__main__":
    unittest.main()
