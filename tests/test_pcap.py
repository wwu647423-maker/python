import struct
import unittest

from cyberkit.pcap import iter_packets


def _build_pcap_global(byteorder="<", nano=False, linktype=1) -> bytes:
    # PCAP convention: ONE logical magic constant, written in the file's
    # native byte order. So both LE and BE writers store 0xA1B2C3D4 (us) /
    # 0xA1B23C4D (ns); on disk the bytes differ only by byte order, which
    # is exactly how readers detect endianness.
    magic_const = 0xA1B23C4D if nano else 0xA1B2C3D4
    return struct.pack(byteorder + "IHHiIII",
                       magic_const, 2, 4, 0, 0, 65535, linktype)


def _build_pcap_packet(byteorder="<", payload: bytes = b"", ts_sec=1700000000, ts_sub=123456) -> bytes:
    hdr = struct.pack(byteorder + "IIII",
                       ts_sec, ts_sub, len(payload), len(payload))
    return hdr + payload


def _build_eth_ip_udp_dns() -> bytes:
    qname = b"\x07example\x03com\x00"
    dns_payload = (struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
                   + qname + struct.pack(">HH", 1, 1)
                   + b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4)
                   + bytes([1, 2, 3, 4]))
    udp_total = 8 + len(dns_payload)
    udp = struct.pack(">HHHH", 53, 33333, udp_total, 0) + dns_payload
    ip_total = 20 + udp_total
    ip = (bytes([0x45, 0]) + struct.pack(">H", ip_total)
          + struct.pack(">HHBBH", 0xDEAD, 0, 64, 17, 0)
          + bytes([8, 8, 8, 8, 10, 0, 0, 5]))
    eth = bytes.fromhex("aabbccddeeff112233445566") + struct.pack(">H", 0x0800)
    return eth + ip + udp


class TestPcap(unittest.TestCase):
    def test_little_endian_microsecond(self):
        pkt = _build_eth_ip_udp_dns()
        blob = _build_pcap_global("<", False, 1) + _build_pcap_packet("<", pkt)
        packets = list(iter_packets(blob))
        self.assertEqual(len(packets), 1)
        p = packets[0]
        self.assertEqual(p.captured_len, len(pkt))
        eth = p.decoded["ethernet"]
        self.assertEqual(eth["ipv4"]["protocol_name"], "UDP")
        self.assertEqual(eth["ipv4"]["udp"]["dns"]["records"][0]["data"], "1.2.3.4")

    def test_big_endian_nanosecond(self):
        pkt = _build_eth_ip_udp_dns()
        blob = _build_pcap_global(">", True, 1) + _build_pcap_packet(">", pkt)
        packets = list(iter_packets(blob))
        self.assertEqual(len(packets), 1)

    def test_bad_magic_raises(self):
        with self.assertRaises(ValueError):
            list(iter_packets(b"BAD!" + b"\x00" * 30))

    def test_multiple_packets(self):
        pkt = _build_eth_ip_udp_dns()
        blob = _build_pcap_global("<", False, 1) \
               + _build_pcap_packet("<", pkt, ts_sec=1, ts_sub=0) \
               + _build_pcap_packet("<", pkt, ts_sec=2, ts_sub=0) \
               + _build_pcap_packet("<", pkt, ts_sec=3, ts_sub=0)
        packets = list(iter_packets(blob))
        self.assertEqual(len(packets), 3)
        self.assertEqual([p.ts for p in packets], [1.0, 2.0, 3.0])

    def test_truncated_packet_record(self):
        pkt = _build_eth_ip_udp_dns()
        partial = _build_pcap_packet("<", pkt)[:-5]
        blob = _build_pcap_global("<", False, 1) + partial
        packets = list(iter_packets(blob))
        self.assertEqual(packets, [])


if __name__ == "__main__":
    unittest.main()
