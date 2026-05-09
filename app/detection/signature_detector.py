"""Signature detection over standardized PacketInfo objects."""

from __future__ import annotations

from app.detection.rule_engine import rule_matches_packet
from app.parser.models import AlertEvent, PacketInfo
from app.rules.models import DetectionRule


class SignatureDetector:
    def __init__(self, rules: list[DetectionRule]) -> None:
        self.rules = rules

    def detect(self, packet: PacketInfo) -> list[AlertEvent]:
        alerts: list[AlertEvent] = []
        for rule in self.rules:
            if not rule_matches_packet(rule, packet):
                continue

            rule.record_hit(packet.timestamp)
            alerts.append(
                AlertEvent(
                    timestamp=packet.timestamp,
                    message=rule.message,
                    severity=rule.priority or 4,
                    protocol=packet.protocol,
                    alert_type="rule_event",
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    src_port=packet.src_port,
                    dst_port=packet.dst_port,
                    rule_sid=rule.sid,
                    packet_length=packet.packet_length,
                )
            )
        return alerts
