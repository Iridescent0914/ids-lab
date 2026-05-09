"""PCAP file reading for LightIDS."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from scapy.utils import PcapReader

from app.parser.models import PacketInfo
from app.parser.protocol_parser import parse_packet


class PcapReadError(RuntimeError):
    """Raised when a PCAP file cannot be loaded."""


def iter_pcap_packets(path: Path, limit: int | None = None) -> Iterator[PacketInfo]:
    if not path.exists():
        raise PcapReadError(f"PCAP file not found: {path}")
    if not path.is_file():
        raise PcapReadError(f"PCAP path is not a file: {path}")

    try:
        count = 0
        with PcapReader(str(path)) as reader:
            for packet in reader:
                yield parse_packet(packet)
                count += 1
                if limit is not None and count >= limit:
                    break
    except Exception as exc:  # pragma: no cover - depends on external PCAP data
        raise PcapReadError(f"Failed to read PCAP file: {path}") from exc


def read_pcap(path: Path, limit: int | None = None) -> list[PacketInfo]:
    return list(iter_pcap_packets(path, limit))
