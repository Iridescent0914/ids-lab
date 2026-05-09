"""Standard packet data models for LightIDS."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class PacketInfo:
    timestamp: datetime
    protocol: str
    packet_length: int
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    payload: bytes = b""
    tcp_flags: str | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None
    arp_operation: str | None = None

    @property
    def timestamp_epoch(self) -> float:
        return self.timestamp.timestamp()

    @property
    def timestamp_text(self) -> str:
        return self.timestamp.strftime("%Y-%m-%d %H:%M:%S")

    @property
    def source_text(self) -> str:
        return self.src_ip or "-"

    @property
    def destination_text(self) -> str:
        return self.dst_ip or "-"

    @property
    def source_port_text(self) -> str:
        return str(self.src_port) if self.src_port is not None else "-"

    @property
    def destination_port_text(self) -> str:
        if self.dst_port is not None:
            return str(self.dst_port)
        if self.protocol == "ICMP" and self.icmp_type is not None and self.icmp_code is not None:
            return f"type={self.icmp_type}, code={self.icmp_code}"
        return "-"

    @property
    def payload_text(self) -> str:
        if not self.payload:
            return ""
        return self.payload.decode("utf-8", errors="replace")


@dataclass(frozen=True)
class AlertEvent:
    timestamp: datetime
    message: str
    severity: int
    protocol: str
    alert_type: str
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    rule_sid: int | None = None
    packet_length: int = 0

    @property
    def timestamp_text(self) -> str:
        return self.timestamp.strftime("%Y-%m-%d %H:%M:%S")

    @property
    def source_text(self) -> str:
        if self.src_ip is None:
            return "-"
        if self.src_port is None:
            return self.src_ip
        return f"{self.src_ip}:{self.src_port}"

    @property
    def destination_text(self) -> str:
        if self.dst_ip is None:
            return "-"
        if self.dst_port is None:
            return self.dst_ip
        return f"{self.dst_ip}:{self.dst_port}"

    @property
    def display_sid(self) -> str:
        return str(self.rule_sid) if self.rule_sid is not None else "-"
