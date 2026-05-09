"""Rule matching engine for LightIDS signature rules."""

from __future__ import annotations

import ipaddress

from app.parser.models import PacketInfo
from app.rules.models import DetectionRule


def rule_matches_packet(rule: DetectionRule, packet: PacketInfo) -> bool:
    if not rule.enabled or not rule.is_valid:
        return False
    if not _match_protocol(rule, packet):
        return False
    if not _match_ip(rule.src_ip, packet.src_ip):
        return False
    if not _match_ip(rule.dst_ip, packet.dst_ip):
        return False
    if not _match_port(rule.src_port, packet.src_port):
        return False
    if not _match_port(rule.dst_port, packet.dst_port):
        return False
    if rule.content is not None and not _match_content(rule, packet):
        return False
    if rule.flags is not None and not _match_flags(rule.flags, packet.tcp_flags):
        return False
    return True


def _match_protocol(rule: DetectionRule, packet: PacketInfo) -> bool:
    if rule.protocol == "ip":
        return packet.protocol in {"IP", "TCP", "UDP", "ICMP"}
    return packet.protocol.lower() == rule.protocol


def _match_ip(rule_value: str, packet_value: str | None) -> bool:
    if rule_value == "any":
        return True
    if packet_value is None:
        return False
    try:
        return ipaddress.ip_address(rule_value) == ipaddress.ip_address(packet_value)
    except ValueError:
        return rule_value == packet_value


def _match_port(rule_value: str, packet_value: int | None) -> bool:
    if rule_value == "any":
        return True
    if packet_value is None:
        return False
    return rule_value.isdigit() and int(rule_value) == packet_value


def _match_content(rule: DetectionRule, packet: PacketInfo) -> bool:
    if rule.content is None:
        return True

    payload = packet.payload
    content = rule.content.encode("utf-8", errors="ignore")
    if rule.nocase:
        return content.lower() in payload.lower()
    return content in payload


def _match_flags(required_flags: str, packet_flags: str | None) -> bool:
    if packet_flags is None:
        return False
    return set(required_flags) == set(packet_flags)
