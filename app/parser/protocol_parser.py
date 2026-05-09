"""Convert Scapy packets into LightIDS PacketInfo objects."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP
from scapy.packet import Raw

from app.parser.models import PacketInfo


ARP_OPERATIONS = {
    1: "who-has",
    2: "is-at",
}


def _packet_time(packet: Any) -> datetime:
    try:
        return datetime.fromtimestamp(float(packet.time))
    except (AttributeError, TypeError, ValueError, OSError):
        return datetime.now()


def _packet_length(packet: Any) -> int:
    try:
        return int(len(packet))
    except TypeError:
        return 0


def _payload_bytes(packet: Any) -> bytes:
    if packet is not None and packet.haslayer(Raw):
        raw_load = packet[Raw].load
        if isinstance(raw_load, bytes):
            return raw_load
        return bytes(raw_load)
    return b""


def _parse_ip_packet(packet: Any, timestamp: datetime, packet_length: int, payload: bytes) -> PacketInfo:
    ip = packet[IP]
    base_fields = {
        "timestamp": timestamp,
        "packet_length": packet_length,
        "src_ip": str(ip.src),
        "dst_ip": str(ip.dst),
        "payload": payload,
    }

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        return PacketInfo(
            **base_fields,
            protocol="TCP",
            src_port=int(tcp.sport),
            dst_port=int(tcp.dport),
            tcp_flags=str(tcp.flags),
        )

    if packet.haslayer(UDP):
        udp = packet[UDP]
        return PacketInfo(
            **base_fields,
            protocol="UDP",
            src_port=int(udp.sport),
            dst_port=int(udp.dport),
        )

    if packet.haslayer(ICMP):
        icmp = packet[ICMP]
        return PacketInfo(
            **base_fields,
            protocol="ICMP",
            icmp_type=int(icmp.type),
            icmp_code=int(icmp.code),
        )

    return PacketInfo(**base_fields, protocol="IP")


def _parse_arp_packet(packet: Any, timestamp: datetime, packet_length: int, payload: bytes) -> PacketInfo:
    arp = packet[ARP]
    operation = ARP_OPERATIONS.get(int(arp.op), str(arp.op))
    return PacketInfo(
        timestamp=timestamp,
        protocol="ARP",
        packet_length=packet_length,
        src_ip=str(arp.psrc),
        dst_ip=str(arp.pdst),
        payload=payload,
        arp_operation=operation,
    )


def parse_packet(packet: Any) -> PacketInfo:
    timestamp = _packet_time(packet)
    packet_length = _packet_length(packet)
    payload = _payload_bytes(packet)

    if packet is not None and packet.haslayer(IP):
        return _parse_ip_packet(packet, timestamp, packet_length, payload)

    if packet is not None and packet.haslayer(ARP):
        return _parse_arp_packet(packet, timestamp, packet_length, payload)

    protocol = packet.__class__.__name__.upper() if packet is not None else "UNKNOWN"
    return PacketInfo(
        timestamp=timestamp,
        protocol=protocol,
        packet_length=packet_length,
        payload=payload,
    )
