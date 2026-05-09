"""Packet summary model used by the data source layer."""

from __future__ import annotations

from dataclasses import dataclass

from app.parser.models import PacketInfo


@dataclass(frozen=True)
class PacketSummary:
    timestamp: str
    protocol: str
    source: str
    source_port: str
    destination: str
    destination_port: str
    length: int


def summary_from_packet_info(packet: PacketInfo) -> PacketSummary:
    return PacketSummary(
        timestamp=packet.timestamp_text,
        protocol=packet.protocol,
        source=packet.source_text,
        source_port=packet.source_port_text,
        destination=packet.destination_text,
        destination_port=packet.destination_port_text,
        length=packet.packet_length,
    )
