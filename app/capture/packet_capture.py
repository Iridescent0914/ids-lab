"""实时抓包和网卡枚举模块。

该模块负责两件事：
1. 枚举本机可抓包接口，并把 Scapy/Npcap 的底层设备名整理成适合界面展示的名称；
2. 在后台线程中调用 Scapy ``sniff`` 实时抓包，并把原始数据包转换为 ``PacketInfo``。
"""

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
    """界面中展示的一张网卡信息。

    ``device_name`` 是 Scapy 实际抓包使用的底层接口名；``display_name`` 和
    ``hint`` 面向用户展示；``sort_order`` 用于把常用真实网卡排在前面。
    """

    device_name: str
    display_name: str
    is_common: bool
    is_loopback: bool
    sort_order: int
    hint: str


def _windows_interface_descriptions() -> dict[str, dict[str, object]]:
    """读取 Windows 下 Npcap 网卡的详细描述信息。

    ``get_if_list`` 只能稳定提供 Scapy 可用的设备名；Windows 专用的
    ``get_windows_if_list`` 能提供 GUID、描述、IP 地址等更友好的信息。
    如果当前环境不支持该接口，则返回空字典，后续仍可用基础设备名抓包。
    """
    try:
        from scapy.arch.windows import get_windows_if_list
    except ImportError:
        return {}

    descriptions: dict[str, dict[str, object]] = {}
    for item in get_windows_if_list():
        # Npcap 设备名形如 \Device\NPF_{GUID}，这里用 GUID 作为关联键。
        guid = str(item.get("guid", "")).upper()
        if guid:
            descriptions[guid] = item
    return descriptions


def _is_common_interface(device_name: str, description: str) -> bool:
    """判断接口是否属于普通用户常用的真实网卡。

    Wi-Fi、Ethernet 等真实网卡默认展示；VPN、虚拟机、WSL、蓝牙等特殊接口
    归为高级接口，避免用户第一次使用时在一长串设备里选错。
    """
    text = f"{device_name} {description}".lower()
    if "loopback" in text:
        return True

    # 常见真实网卡关键词。
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
    # 容易让新手困惑或只在特殊场景使用的接口关键词。
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
    """从 Windows 网卡信息中挑选一个最适合展示的 IP 地址。

    优先显示非回环、非链路本地的 IPv4 地址；其次退回到普通 IPv4，再考虑
    IPv6。这样下拉框里显示的 IP 更接近用户实际上网使用的地址。
    """
    if not isinstance(raw_ips, list):
        return ""

    parsed_ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for raw_ip in raw_ips:
        try:
            parsed_ips.append(ipaddress.ip_address(str(raw_ip)))
        except ValueError:
            # 忽略 Scapy 返回的异常或非标准地址文本。
            continue

    # 最优先：真实局域网/公网 IPv4。
    for ip in parsed_ips:
        if ip.version == 4 and not ip.is_loopback and not ip.is_link_local:
            return str(ip)
    # 次优先：IPv4，但允许链路本地地址。
    for ip in parsed_ips:
        if ip.version == 4 and not ip.is_loopback:
            return str(ip)
    # 再考虑 IPv6，仍然优先排除回环和链路本地地址。
    for ip in parsed_ips:
        if ip.version == 6 and not ip.is_loopback and not ip.is_link_local:
            return str(ip)
    return str(parsed_ips[0]) if parsed_ips else ""


def _interface_type(description: str) -> tuple[str, int]:
    """根据网卡描述生成界面分类名称和基础排序权重。

    排序权重越小越靠前，因此 Wi-Fi、Ethernet 会排在高级接口前面。
    """
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
    """把 Scapy/Npcap 原始接口信息整理成 ``CaptureInterface``。

    这里集中处理 loopback、缺少详细信息、真实网卡和高级接口等情况，保证
    ``list_interfaces`` 返回的数据已经可以直接交给 UI 下拉框使用。
    """
    if device_name == r"\Device\NPF_Loopback":
        # Npcap loopback 用于本机 127.0.0.1 测试流量，单独命名更容易理解。
        return CaptureInterface(
            device_name=device_name,
            display_name="Loopback - Localhost test traffic",
            is_common=True,
            is_loopback=True,
            sort_order=90,
            hint="Loopback captures local 127.0.0.1 traffic only.",
        )

    if not info:
        # 某些环境只能拿到底层设备名，仍保留该接口，避免漏掉可抓包设备。
        is_common = _is_common_interface(device_name, "")
        return CaptureInterface(
            device_name=device_name,
            display_name="Interface - Unknown adapter",
            is_common=is_common,
            is_loopback=False,
            sort_order=50 if is_common else 100,
            hint="Capture traffic on this interface.",
        )

    # 优先使用 Windows 网卡描述，其次退回到名称，最后使用通用名称。
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
    """枚举并排序当前机器可用于抓包的接口。

    返回值既包含 Scapy 抓包需要的底层设备名，也包含 UI 展示所需的友好名称。
    主窗口可据此默认选择真实网卡，并通过高级选项显示虚拟/VPN 等接口。
    """
    descriptions = _windows_interface_descriptions()
    interfaces: list[CaptureInterface] = []

    for raw_name in sorted(str(name) for name in get_if_list()):
        guid = ""
        if raw_name.startswith(r"\Device\NPF_"):
            # 将 \Device\NPF_{GUID} 还原为 GUID，以匹配 Windows 详细信息。
            guid = raw_name.removeprefix(r"\Device\NPF_").upper()
        interfaces.append(_format_interface(raw_name, descriptions.get(guid)))

    return sorted(interfaces, key=lambda item: (item.sort_order, item.display_name.lower()))


class PacketCaptureWorker(QObject):
    """后台实时抓包 Worker。

    该对象应移动到 ``QThread`` 中运行。它持续调用 Scapy ``sniff`` 捕获数据包，
    每捕获到一个包就转换为 ``PacketInfo``，再通过信号交给主窗口处理。
    """

    # 每捕获并解析到一个数据包，就发送一个 PacketInfo。
    packet_captured = pyqtSignal(object)
    # 状态栏文本，例如开始抓包、停止抓包。
    status_changed = pyqtSignal(str)
    # 抓包失败时发送错误信息，常见原因包括未安装 Npcap 或权限不足。
    failed = pyqtSignal(str)
    # Worker 退出时通知主窗口清理线程和恢复按钮状态。
    finished = pyqtSignal()

    def __init__(self, interface: str, timeout_seconds: int = 1) -> None:
        """保存抓包接口和超时时间。

        ``timeout_seconds`` 至少为 1，避免 ``sniff`` 长时间阻塞导致 Stop 操作响应
        不及时。循环中每次只抓 1 个包，方便在两次 sniff 之间检查停止标志。
        """
        super().__init__()
        self.interface = interface
        self.timeout_seconds = max(1, timeout_seconds)
        self._stop_event = Event()

    def stop(self) -> None:
        """请求停止实时抓包。

        Scapy ``sniff`` 正在等待数据包时不能被这里强行打断；因此设置停止标志，
        等当前 ``sniff`` 调用因抓到包或超时返回后，``run`` 会退出循环。
        """
        self._stop_event.set()

    def run(self) -> None:
        """执行实时抓包循环。

        为了让停止操作有机会生效，循环中每次 ``sniff`` 只捕获一个包，并设置
        短超时。捕获到的数据包会通过 ``prn`` 回调交给 ``_handle_packet``。
        """
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
        """处理 Scapy 捕获到的单个原始数据包。

        采集模块不直接做检测，而是先调用协议解析层生成 ``PacketInfo``，再通过
        信号交给主窗口统一执行规则检测、阈值检测和界面刷新。
        """
        packet_info: PacketInfo = parse_packet(packet)
        self.packet_captured.emit(packet_info)
