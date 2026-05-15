"""Generate controlled PCAP files for LightIDS validation."""

from __future__ import annotations

from pathlib import Path

from scapy.all import ICMP, IP, Raw, TCP, UDP, wrpcap


OUTPUT_DIR = Path("data") / "stage6_pcaps"
BASE_TIME = 1_710_000_000.0
PORT_SCAN_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 139, 443]
HORIZONTAL_SCAN_HOSTS = [f"192.168.0.{host}" for host in range(101, 111)]
ICMP_REQUEST_COUNT = 20
SENSITIVE_SERVICE_PORTS = [21, 22, 23, 445, 3389, 3306]


def _join(*parts: bytes) -> bytes:
    return b"".join(parts)


def web_attack_payloads() -> list[bytes]:
    return [
        _join(b"GET /search?q=UNION ", b"SELECT password FROM users HTTP/1.1\r\nHost: lab\r\n\r\n"),
        _join(b"GET /comment?text=<scr", b"ipt>alert(1)</scr", b"ipt> HTTP/1.1\r\nHost: lab\r\n\r\n"),
        _join(b"GET /download?file=../", b"../etc/shadow HTTP/1.1\r\nHost: lab\r\n\r\n"),
        _join(b"GET /view?path=/etc/", b"passwd HTTP/1.1\r\nHost: lab\r\n\r\n"),
        _join(b"GET /admin?c", b"md=id HTTP/1.1\r\nHost: lab\r\n\r\n"),
        _join(b"POST /upload.php HTTP/1.1\r\nHost: lab\r\n\r\n<?php ev", b"al($_POST['x']); ?>"),
    ]


def benign_http_payloads() -> list[bytes]:
    return [
        b"GET /index.html HTTP/1.1\r\nHost: lab\r\n\r\n",
        b"GET /about HTTP/1.1\r\nHost: lab\r\n\r\n",
        b"POST /login HTTP/1.1\r\nHost: lab\r\n\r\nusername=alice&remember=yes",
        b"GET /static/app.css HTTP/1.1\r\nHost: lab\r\n\r\n",
        b"GET /api/status HTTP/1.1\r\nHost: lab\r\n\r\n",
        b"POST /comment HTTP/1.1\r\nHost: lab\r\n\r\nmessage=hello",
    ]


def set_time(packet, timestamp: float):
    packet.time = timestamp
    return packet


def write_pcap(name: str, packets: list) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    wrpcap(str(OUTPUT_DIR / name), packets)


def tcp_syn_scan_positive() -> list:
    packets = []
    for index, port in enumerate(PORT_SCAN_PORTS):
        packet = IP(src="192.168.0.51", dst="192.168.0.100") / TCP(
            sport=40000 + index,
            dport=port,
            flags="S",
        )
        packets.append(set_time(packet, BASE_TIME + index))
    return packets


def tcp_horizontal_scan_positive() -> list:
    packets = []
    for index, host in enumerate(HORIZONTAL_SCAN_HOSTS):
        packet = IP(src="192.168.0.51", dst=host) / TCP(
            sport=44000 + index,
            dport=445,
            flags="S",
        )
        packets.append(set_time(packet, BASE_TIME + index))
    return packets


def rule_sensitive_services_positive() -> list:
    packets = []
    for index, port in enumerate(SENSITIVE_SERVICE_PORTS):
        packet = IP(src="192.168.0.60", dst="192.168.0.100") / TCP(
            sport=45000 + index,
            dport=port,
            flags="S",
        )
        packets.append(set_time(packet, BASE_TIME + index))
    return packets


def rule_sensitive_services_ack_negative() -> list:
    packets = []
    for index, port in enumerate(SENSITIVE_SERVICE_PORTS):
        packet = IP(src="192.168.0.60", dst="192.168.0.100") / TCP(
            sport=45100 + index,
            dport=port,
            flags="A",
        )
        packets.append(set_time(packet, BASE_TIME + index))
    return packets


def rule_web_attacks_positive() -> list:
    packets = []
    for index, payload in enumerate(web_attack_payloads()):
        packet = (
            IP(src="192.168.0.61", dst="192.168.0.200")
            / TCP(sport=46000 + index, dport=80, flags="PA")
            / Raw(load=payload)
        )
        packets.append(set_time(packet, BASE_TIME + index))
    return packets


def rule_benign_http_negative() -> list:
    packets = []
    for index, payload in enumerate(benign_http_payloads()):
        packet = (
            IP(src="192.168.0.61", dst="192.168.0.200")
            / TCP(sport=46100 + index, dport=80, flags="PA")
            / Raw(load=payload)
        )
        packets.append(set_time(packet, BASE_TIME + index))
    return packets


def tcp_synack_negative() -> list:
    packets = []
    for index, port in enumerate(PORT_SCAN_PORTS):
        packet = IP(src="192.168.0.100", dst="192.168.0.51") / TCP(
            sport=port,
            dport=50000 + index,
            flags="SA",
        )
        packets.append(set_time(packet, BASE_TIME + index))
    return packets


def dns_response_negative() -> list:
    packets = []
    for index in range(len(PORT_SCAN_PORTS)):
        packet = IP(src="192.168.0.1", dst="192.168.0.51") / UDP(
            sport=53,
            dport=50001 + index,
        )
        packets.append(set_time(packet, BASE_TIME + index))
    return packets


def icmp_request_positive() -> list:
    packets = []
    for index in range(ICMP_REQUEST_COUNT):
        packet = IP(src="192.168.0.51", dst="8.8.8.8") / ICMP(type=8, code=0)
        packets.append(set_time(packet, BASE_TIME + index * 0.25))
    return packets


def icmp_reply_negative() -> list:
    packets = []
    for index in range(ICMP_REQUEST_COUNT):
        packet = IP(src="8.8.8.8", dst="192.168.0.51") / ICMP(type=0, code=0)
        packets.append(set_time(packet, BASE_TIME + index * 0.25))
    return packets


def tcp_scan_outside_window_negative() -> list:
    packets = []
    for index, port in enumerate(PORT_SCAN_PORTS):
        packet = IP(src="192.168.0.51", dst="192.168.0.100") / TCP(
            sport=41000 + index,
            dport=port,
            flags="S",
        )
        packets.append(set_time(packet, BASE_TIME + index * 11))
    return packets


def tcp_scan_boundary_positive() -> list:
    packets = []
    offsets = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10]
    for index, (offset, port) in enumerate(zip(offsets, PORT_SCAN_PORTS)):
        packet = IP(src="192.168.0.51", dst="192.168.0.100") / TCP(
            sport=42000 + index,
            dport=port,
            flags="S",
        )
        packets.append(set_time(packet, BASE_TIME + offset))
    return packets


def multicast_negative() -> list:
    packets = []
    for index, port in enumerate(range(1900, 1900 + len(PORT_SCAN_PORTS))):
        packet = IP(src="192.168.0.51", dst="239.255.255.250") / UDP(
            sport=43000 + index,
            dport=port,
        )
        packets.append(set_time(packet, BASE_TIME + index))
    return packets


def main() -> None:
    pcaps = {
        "rule_sensitive_services_positive.pcap": rule_sensitive_services_positive(),
        "rule_sensitive_services_ack_negative.pcap": rule_sensitive_services_ack_negative(),
        "rule_web_attacks_positive.pcap": rule_web_attacks_positive(),
        "rule_benign_http_negative.pcap": rule_benign_http_negative(),
        "tcp_syn_scan_positive.pcap": tcp_syn_scan_positive(),
        "tcp_horizontal_scan_positive.pcap": tcp_horizontal_scan_positive(),
        "tcp_synack_negative.pcap": tcp_synack_negative(),
        "dns_response_negative.pcap": dns_response_negative(),
        "icmp_request_positive.pcap": icmp_request_positive(),
        "icmp_reply_negative.pcap": icmp_reply_negative(),
        "tcp_scan_outside_window_negative.pcap": tcp_scan_outside_window_negative(),
        "tcp_scan_boundary_positive.pcap": tcp_scan_boundary_positive(),
        "multicast_negative.pcap": multicast_negative(),
    }
    for name, packets in pcaps.items():
        write_pcap(name, packets)
        print(f"generated {OUTPUT_DIR / name}")


if __name__ == "__main__":
    main()
