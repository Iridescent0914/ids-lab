"""PCAP file reading for LightIDS."""

from __future__ import annotations

from pathlib import Path

from scapy.utils import PcapReader

from app.parser.models import PacketInfo
from app.parser.protocol_parser import parse_packet


class PcapReadError(RuntimeError):
    """Raised when a PCAP file cannot be loaded."""


def read_pcap(path: Path, limit: int | None = None) -> list[PacketInfo]:
    if not path.exists():
        raise PcapReadError(f"PCAP file not found: {path}")
    if not path.is_file():
        raise PcapReadError(f"PCAP path is not a file: {path}")

    packets: list[PacketInfo] = []
    try:
        with PcapReader(str(path)) as reader:
            for packet in reader:
                packets.append(parse_packet(packet))
                if limit is not None and len(packets) >= limit:
                    break
    except Exception as exc:  # pragma: no cover - depends on external PCAP data
        raise PcapReadError(f"Failed to read PCAP file: {path}") from exc

    return packets
