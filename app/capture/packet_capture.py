"""Realtime packet capture worker."""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from threading import Event

from PyQt6.QtCore import QObject, pyqtSignal
from scapy.all import get_if_list, sniff

from app.parser.models import PacketInfo
from app.parser.protocol_parser import parse_packet


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CaptureInterface:
    device_name: str
    display_name: str
    is_common: bool
    is_loopback: bool
    sort_order: int
    hint: str


def _windows_interface_descriptions() -> dict[str, dict[str, object]]:
    try:
        from scapy.arch.windows import get_windows_if_list
    except ImportError:
        return {}

    descriptions: dict[str, dict[str, object]] = {}
    for item in get_windows_if_list():
        guid = str(item.get("guid", "")).upper()
        if guid:
            descriptions[guid] = item
    return descriptions


def _is_common_interface(device_name: str, description: str) -> bool:
    text = f"{device_name} {description}".lower()
    if "loopback" in text:
        return True

    common_keywords = [
        "wi-fi",
        "wifi",
        "wireless",
        "wlan",
        "ethernet",
        "realtek",
        "intel",
        "mediatek",
        "qualcomm",
        "broadcom",
    ]
    advanced_keywords = [
        "virtual",
        "vmware",
        "virtualbox",
        "hyper-v",
        "wsl",
        "wi-fi direct",
        "wifi direct",
        "bluetooth",
        "tap-windows",
        "tunnel",
        "vpn",
        "pseudo",
        "miniport",
    ]

    if any(keyword in text for keyword in advanced_keywords):
        return False
    return any(keyword in text for keyword in common_keywords)


def _first_display_ip(raw_ips: object) -> str:
    if not isinstance(raw_ips, list):
        return ""

    parsed_ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for raw_ip in raw_ips:
        try:
            parsed_ips.append(ipaddress.ip_address(str(raw_ip)))
        except ValueError:
            continue

    for ip in parsed_ips:
        if ip.version == 4 and not ip.is_loopback and not ip.is_link_local:
            return str(ip)
    for ip in parsed_ips:
        if ip.version == 4 and not ip.is_loopback:
            return str(ip)
    for ip in parsed_ips:
        if ip.version == 6 and not ip.is_loopback and not ip.is_link_local:
            return str(ip)
    return str(parsed_ips[0]) if parsed_ips else ""


def _interface_type(description: str) -> tuple[str, int]:
    text = description.lower()
    if any(keyword in text for keyword in ["wi-fi", "wifi", "wireless", "wlan"]):
        return "Wi-Fi", 10
    if any(keyword in text for keyword in ["ethernet", "realtek", "intel ethernet"]):
        return "Ethernet", 20
    if any(keyword in text for keyword in ["vpn", "tap-windows", "tunnel"]):
        return "Advanced", 60
    if any(keyword in text for keyword in ["vmware", "virtualbox", "hyper-v", "wsl", "virtual"]):
        return "Advanced", 70
    if "bluetooth" in text:
        return "Advanced", 80
    return "Interface", 50


def _format_interface(device_name: str, info: dict[str, object] | None) -> CaptureInterface:
    if device_name == r"\Device\NPF_Loopback":
        return CaptureInterface(
            device_name=device_name,
            display_name="Loopback - Localhost test traffic",
            is_common=True,
            is_loopback=True,
            sort_order=90,
            hint="Loopback captures local 127.0.0.1 traffic only.",
        )

    if not info:
        is_common = _is_common_interface(device_name, "")
        return CaptureInterface(
            device_name=device_name,
            display_name="Interface - Unknown adapter",
            is_common=is_common,
            is_loopback=False,
            sort_order=50 if is_common else 100,
            hint="Capture traffic on this interface.",
        )

    description = str(info.get("description") or info.get("name") or "Network Interface")
    interface_type, sort_order = _interface_type(description)
    display_ip = _first_display_ip(info.get("ips") or [])
    ip_text = f" - {display_ip}" if display_ip else ""
    is_common = _is_common_interface(device_name, description)
    hint = (
        "Suitable for capturing real network traffic."
        if is_common
        else "Advanced interface. Use this for VPN, virtual machine, WSL, or special adapter traffic."
    )

    return CaptureInterface(
        device_name=device_name,
        display_name=f"{interface_type} - {description}{ip_text}",
        is_common=is_common,
        is_loopback=False,
        sort_order=sort_order if is_common else sort_order + 100,
        hint=hint,
    )


def list_interfaces() -> list[CaptureInterface]:
    descriptions = _windows_interface_descriptions()
    interfaces: list[CaptureInterface] = []

    for raw_name in sorted(str(name) for name in get_if_list()):
        guid = ""
        if raw_name.startswith(r"\Device\NPF_"):
            guid = raw_name.removeprefix(r"\Device\NPF_").upper()
        interfaces.append(_format_interface(raw_name, descriptions.get(guid)))

    return sorted(interfaces, key=lambda item: (item.sort_order, item.display_name.lower()))


class PacketCaptureWorker(QObject):
    packet_captured = pyqtSignal(object)
    status_changed = pyqtSignal(str)
    failed = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, interface: str, timeout_seconds: int = 1) -> None:
        super().__init__()
        self.interface = interface
        self.timeout_seconds = max(1, timeout_seconds)
        self._stop_event = Event()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        self.status_changed.emit(f"Capturing on {self.interface}")
        try:
            while not self._stop_event.is_set():
                sniff(
                    iface=self.interface,
                    count=1,
                    timeout=self.timeout_seconds,
                    store=False,
                    prn=self._handle_packet,
                )
        except Exception as exc:  # pragma: no cover - depends on local Npcap/permissions
            logger.exception("Realtime capture failed")
            self.failed.emit(str(exc))
        finally:
            self.status_changed.emit("Capture stopped")
            self.finished.emit()

    def _handle_packet(self, packet: object) -> None:
        packet_info: PacketInfo = parse_packet(packet)
        self.packet_captured.emit(packet_info)
