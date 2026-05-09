"""Threshold-based behavior detection for LightIDS."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta

from app.parser.models import AlertEvent, PacketInfo


@dataclass(frozen=True)
class ThresholdSettings:
    window_seconds: int
    port_scan_unique_ports: int
    icmp_high_frequency_count: int


class ThresholdDetector:
    def __init__(self, settings: ThresholdSettings) -> None:
        self.settings = settings
        self.port_access: dict[tuple[str, str], deque[tuple[datetime, int]]] = defaultdict(deque)
        self.icmp_access: dict[str, deque[datetime]] = defaultdict(deque)
        self.last_port_scan_alert: dict[tuple[str, str], datetime] = {}
        self.last_icmp_alert: dict[str, datetime] = {}

    def reset(self) -> None:
        self.port_access.clear()
        self.icmp_access.clear()
        self.last_port_scan_alert.clear()
        self.last_icmp_alert.clear()

    def detect(self, packet: PacketInfo) -> list[AlertEvent]:
        alerts: list[AlertEvent] = []
        port_scan_alert = self._detect_port_scan(packet)
        if port_scan_alert is not None:
            alerts.append(port_scan_alert)

        icmp_alert = self._detect_icmp_high_frequency(packet)
        if icmp_alert is not None:
            alerts.append(icmp_alert)
        return alerts

    def _detect_port_scan(self, packet: PacketInfo) -> AlertEvent | None:
        if not self._is_port_scan_candidate(packet):
            return None
        if packet.src_ip is None or packet.dst_ip is None or packet.dst_port is None:
            return None

        key = (packet.src_ip, packet.dst_ip)
        window = self._window(packet.timestamp)
        entries = self.port_access[key]
        entries.append((packet.timestamp, packet.dst_port))
        while entries and entries[0][0] < window:
            entries.popleft()

        unique_ports = {port for _, port in entries}
        if len(unique_ports) < self.settings.port_scan_unique_ports:
            return None
        if not self._can_emit(self.last_port_scan_alert, key, packet.timestamp):
            return None

        self.last_port_scan_alert[key] = packet.timestamp
        return AlertEvent(
            timestamp=packet.timestamp,
            message=(
                "Possible port scan detected: "
                f"{packet.src_ip} accessed {len(unique_ports)} ports on {packet.dst_ip} "
                f"within {self.settings.window_seconds}s"
            ),
            severity=1,
            protocol=packet.protocol,
            alert_type="threshold_alert",
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            packet_length=packet.packet_length,
        )

    def _is_port_scan_candidate(self, packet: PacketInfo) -> bool:
        if packet.protocol == "TCP":
            flags = packet.tcp_flags or ""
            return "S" in flags and "A" not in flags

        if packet.protocol == "UDP":
            if packet.src_port in {53, 67, 68, 123, 137, 138, 161, 1900, 5353}:
                return False
            return True

        return False

    def _detect_icmp_high_frequency(self, packet: PacketInfo) -> AlertEvent | None:
        if packet.protocol != "ICMP" or packet.src_ip is None:
            return None
        if packet.icmp_type != 8:
            return None

        window = self._window(packet.timestamp)
        entries = self.icmp_access[packet.src_ip]
        entries.append(packet.timestamp)
        while entries and entries[0] < window:
            entries.popleft()

        if len(entries) < self.settings.icmp_high_frequency_count:
            return None
        if not self._can_emit(self.last_icmp_alert, packet.src_ip, packet.timestamp):
            return None

        self.last_icmp_alert[packet.src_ip] = packet.timestamp
        return AlertEvent(
            timestamp=packet.timestamp,
            message=(
                "ICMP high frequency detected: "
                f"{packet.src_ip} sent {len(entries)} ICMP packets "
                f"within {self.settings.window_seconds}s"
            ),
            severity=2,
            protocol=packet.protocol,
            alert_type="threshold_alert",
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            packet_length=packet.packet_length,
        )

    def _window(self, timestamp: datetime) -> datetime:
        return timestamp - timedelta(seconds=self.settings.window_seconds)

    def _can_emit(
        self,
        last_alerts: dict[object, datetime],
        key: object,
        timestamp: datetime,
    ) -> bool:
        previous = last_alerts.get(key)
        if previous is None:
            return True
        return timestamp - previous >= timedelta(seconds=self.settings.window_seconds)
