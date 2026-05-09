from __future__ import annotations

import unittest

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP
from scapy.packet import Raw

from app.capture.models import summary_from_packet_info
from app.parser.protocol_parser import parse_packet


class ProtocolParserTests(unittest.TestCase):
    def test_parse_tcp_packet(self) -> None:
        packet = IP(src="192.168.1.10", dst="192.168.1.1") / TCP(
            sport=12345,
            dport=80,
            flags="S",
        ) / Raw(load=b"GET / HTTP/1.1\r\n")

        info = parse_packet(packet)

        self.assertEqual(info.protocol, "TCP")
        self.assertEqual(info.src_ip, "192.168.1.10")
        self.assertEqual(info.dst_ip, "192.168.1.1")
        self.assertEqual(info.src_port, 12345)
        self.assertEqual(info.dst_port, 80)
        self.assertEqual(info.tcp_flags, "S")
        self.assertEqual(info.payload, b"GET / HTTP/1.1\r\n")

    def test_parse_udp_packet(self) -> None:
        packet = IP(src="10.0.0.2", dst="10.0.0.53") / UDP(sport=5353, dport=53)

        info = parse_packet(packet)

        self.assertEqual(info.protocol, "UDP")
        self.assertEqual(info.src_port, 5353)
        self.assertEqual(info.dst_port, 53)

    def test_parse_icmp_packet(self) -> None:
        packet = IP(src="172.16.0.2", dst="8.8.8.8") / ICMP(type=8, code=0)

        info = parse_packet(packet)
        summary = summary_from_packet_info(info)

        self.assertEqual(info.protocol, "ICMP")
        self.assertEqual(info.icmp_type, 8)
        self.assertEqual(info.icmp_code, 0)
        self.assertEqual(summary.destination_port, "type=8, code=0")

    def test_parse_arp_packet(self) -> None:
        packet = ARP(op=1, psrc="192.168.1.20", pdst="192.168.1.1")

        info = parse_packet(packet)

        self.assertEqual(info.protocol, "ARP")
        self.assertEqual(info.src_ip, "192.168.1.20")
        self.assertEqual(info.dst_ip, "192.168.1.1")
        self.assertEqual(info.arp_operation, "who-has")


if __name__ == "__main__":
    unittest.main()
