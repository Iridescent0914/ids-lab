"""基于时间窗口的行为阈值检测。

规则检测关注“单个数据包是否命中特征”，而本模块关注“一段时间内多个数据包
是否形成异常行为”。目前实现三类行为：

* 垂直端口扫描：同一源 IP 在窗口内访问同一目的 IP 的多个不同端口；
* 横向扫描：同一源 IP 在窗口内访问多个目的主机的同一端口；
* ICMP 高频：同一源 IP 在窗口内发送大量 ICMP Echo Request。

所有检测输入都是标准化后的 ``PacketInfo``，输出统一为 ``AlertEvent``，因此
可以和规则检测复用同一套 UI 展示、SQLite 存储和 CSV 导出链路。
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict, deque
from dataclasses import dataclass

from app.parser.models import AlertEvent, PacketInfo


# 常见 UDP 服务端响应源端口。若一个 UDP 包的源端口来自这些服务，通常表示
# “服务端回包”而不是“客户端主动扫描”，因此端口扫描候选过滤时会排除它们。
UDP_RESPONSE_PORTS = {53, 67, 68, 123, 137, 138, 161, 1900, 5353}


@dataclass(frozen=True)
class ThresholdSettings:
    """阈值检测配置。

    这些参数来自 ``config/config.json``。使用单独的数据类可以让检测器只依赖
    纯 Python 配置对象，而不需要直接读取 JSON 或应用配置类。
    """

    # 滑动时间窗口长度，单位为秒。
    window_seconds: int
    # 垂直端口扫描阈值：窗口内访问同一目标的不同目的端口数。
    port_scan_unique_ports: int
    # 横向扫描阈值：窗口内访问同一目的端口的不同目标主机数。
    horizontal_scan_unique_hosts: int
    # ICMP 高频阈值：窗口内 Echo Request 数量。
    icmp_high_frequency_count: int


class ThresholdDetector:
    """多包行为检测器。

    检测器内部维护三个滑动窗口缓存，分别服务端口扫描、横向扫描和 ICMP 高频。
    每处理一个新包，就把该包的关键字段加入对应窗口，并清理窗口之外的旧记录。
    当窗口内唯一端口数、唯一主机数或 ICMP 数量达到阈值时生成告警。
    """

    def __init__(self, settings: ThresholdSettings) -> None:
        """初始化阈值配置和运行时状态。

        ``deque`` 适合滑动窗口：新记录从右侧 append，过期记录从左侧 popleft。
        三组 ``last_*_alert`` 字典用于重复告警抑制，避免同一源/目标在同一个窗口
        内每来一个新包都反复报警。
        """
        self.settings = settings

        # 垂直端口扫描状态：
        # key=(src_ip, dst_ip)，value 保存窗口内访问过的 (时间戳, 目的端口)。
        self.port_access: dict[tuple[str, str], deque[tuple[float, int]]] = defaultdict(deque)
        # 横向扫描状态：
        # key=(src_ip, dst_port)，value 保存窗口内访问过的 (时间戳, 目的主机)。
        self.horizontal_access: dict[tuple[str, int], deque[tuple[float, str]]] = defaultdict(deque)
        # ICMP 高频状态：
        # key=src_ip，value 保存窗口内 Echo Request 的时间戳。
        self.icmp_access: dict[str, deque[float]] = defaultdict(deque)

        # 最近一次告警时间，用于按 key 做窗口级抑制。
        self.last_port_scan_alert: dict[tuple[str, str], float] = {}
        self.last_horizontal_scan_alert: dict[tuple[str, int], float] = {}
        self.last_icmp_alert: dict[str, float] = {}

    def reset(self) -> None:
        """清空所有窗口状态和重复告警记录。

        重新导入 PCAP、清空当前流量或开始新的抓包会话时应调用该方法，避免上一轮
        会话的数据影响下一轮检测结果。
        """
        self.port_access.clear()
        self.horizontal_access.clear()
        self.icmp_access.clear()
        self.last_port_scan_alert.clear()
        self.last_horizontal_scan_alert.clear()
        self.last_icmp_alert.clear()

    def detect(self, packet: PacketInfo) -> list[AlertEvent]:
        """对单个数据包执行所有阈值检测。

        一个包理论上可能同时推动多种行为达到阈值，例如 TCP SYN 包既可能补齐
        垂直扫描的端口集合，也可能补齐横向扫描的目标主机集合。因此返回列表。
        """
        alerts: list[AlertEvent] = []

        # 检测同一源主机对同一目标主机的多端口访问。
        port_scan_alert = self._detect_port_scan(packet)
        if port_scan_alert is not None:
            alerts.append(port_scan_alert)

        # 检测同一源主机对多个目标主机的同一端口访问。
        horizontal_scan_alert = self._detect_horizontal_scan(packet)
        if horizontal_scan_alert is not None:
            alerts.append(horizontal_scan_alert)

        # 检测同一源主机短时间内发送大量 ICMP Echo Request。
        icmp_alert = self._detect_icmp_high_frequency(packet)
        if icmp_alert is not None:
            alerts.append(icmp_alert)
        return alerts

    def _detect_port_scan(self, packet: PacketInfo) -> AlertEvent | None:
        """检测垂直端口扫描。

        垂直扫描的判定对象是 ``(源 IP, 目的 IP)``。只要该源在时间窗口内访问同一
        目的主机的不同目的端口数达到配置阈值，就生成 ``threshold_alert``。
        """
        if not self._is_port_scan_candidate(packet):
            return None
        if packet.src_ip is None or packet.dst_ip is None or packet.dst_port is None:
            return None

        current_time = packet.timestamp_epoch
        key = (packet.src_ip, packet.dst_ip)
        window = self._window(current_time)
        entries = self.port_access[key]
        entries.append((current_time, packet.dst_port))

        # 只保留 [当前时间 - window_seconds, 当前时间] 范围内的访问记录。
        while entries and entries[0][0] < window:
            entries.popleft()

        unique_ports = {port for _, port in entries}
        if len(unique_ports) < self.settings.port_scan_unique_ports:
            return None

        # 同一个 key 在一个窗口内已经报警过，则暂时抑制，降低重复告警噪声。
        if not self._can_emit(self.last_port_scan_alert, key, current_time):
            return None

        self.last_port_scan_alert[key] = current_time
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

    def _detect_horizontal_scan(self, packet: PacketInfo) -> AlertEvent | None:
        """检测横向扫描。

        横向扫描的判定对象是 ``(源 IP, 目的端口)``。如果同一源在时间窗口内访问
        多个目的主机的同一端口，例如多个主机的 445/3389，就认为可能存在横向探测。
        """
        if not self._is_port_scan_candidate(packet):
            return None
        if packet.src_ip is None or packet.dst_ip is None or packet.dst_port is None:
            return None

        current_time = packet.timestamp_epoch
        key = (packet.src_ip, packet.dst_port)
        window = self._window(current_time)
        entries = self.horizontal_access[key]
        entries.append((current_time, packet.dst_ip))

        # 清理窗口外的旧目标主机访问记录。
        while entries and entries[0][0] < window:
            entries.popleft()

        unique_hosts = {host for _, host in entries}
        if len(unique_hosts) < self.settings.horizontal_scan_unique_hosts:
            return None

        # 同一源 IP + 目的端口在抑制窗口内只报一次。
        if not self._can_emit(self.last_horizontal_scan_alert, key, current_time):
            return None

        self.last_horizontal_scan_alert[key] = current_time
        return AlertEvent(
            timestamp=packet.timestamp,
            message=(
                "Possible horizontal scan detected: "
                f"{packet.src_ip} accessed port {packet.dst_port} on {len(unique_hosts)} hosts "
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
        """判断数据包是否适合作为扫描行为统计样本。

        端口扫描和横向扫描都应统计“主动探测”流量，而不是服务端响应、广播、
        多播或协议噪声。因此这里先做候选过滤：

        * 目的地址为空、广播或多播时跳过；
        * TCP 只统计 SYN 且不带 ACK 的建连尝试；
        * UDP 排除常见服务端响应源端口；
        * 其他协议不参与端口扫描类统计。
        """
        if packet.dst_ip is None or _is_broadcast_or_multicast(packet.dst_ip):
            return False

        if packet.protocol == "TCP":
            flags = packet.tcp_flags or ""
            # SYN 且非 ACK 更接近客户端主动发起连接；SYN-ACK 是服务端响应。
            return "S" in flags and "A" not in flags

        if packet.protocol == "UDP":
            if packet.src_port in UDP_RESPONSE_PORTS:
                return False
            return True

        return False

    def _detect_icmp_high_frequency(self, packet: PacketInfo) -> AlertEvent | None:
        """检测 ICMP Echo Request 高频行为。

        只统计 ICMP type=8 的请求包，不统计 type=0 的 Echo Reply。按源 IP 维护
        滑动窗口，达到阈值时生成中高严重级别的阈值告警。
        """
        if packet.protocol != "ICMP" or packet.src_ip is None:
            return None
        if packet.icmp_type != 8:
            return None

        current_time = packet.timestamp_epoch
        window = self._window(current_time)
        entries = self.icmp_access[packet.src_ip]
        entries.append(current_time)

        # 移除窗口外的旧 Echo Request 时间戳。
        while entries and entries[0] < window:
            entries.popleft()

        if len(entries) < self.settings.icmp_high_frequency_count:
            return None

        # 同一源 IP 在一个窗口内只触发一次 ICMP 高频告警。
        if not self._can_emit(self.last_icmp_alert, packet.src_ip, current_time):
            return None

        self.last_icmp_alert[packet.src_ip] = current_time
        return AlertEvent(
            timestamp=packet.timestamp,
            message=(
                "ICMP high frequency detected: "
                f"{packet.src_ip} sent {len(entries)} ICMP echo requests "
                f"within {self.settings.window_seconds}s"
            ),
            severity=2,
            protocol=packet.protocol,
            alert_type="threshold_alert",
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            packet_length=packet.packet_length,
        )

    def _window(self, timestamp_epoch: float) -> float:
        """返回当前滑动窗口的起始时间戳。

        例如当前包时间为 100 秒、窗口长度为 10 秒，则保留时间戳 >= 90 的记录。
        """
        return timestamp_epoch - self.settings.window_seconds

    def _can_emit(
        self,
        last_alerts: dict[object, float],
        key: object,
        timestamp_epoch: float,
    ) -> bool:
        """判断某个检测 key 当前是否允许再次报警。

        ``last_alerts`` 保存每个 key 上一次报警的 Unix 时间戳。若从上次报警到现在
        尚未经过一个完整窗口，则返回 ``False``；否则允许再次报警。
        """
        previous = last_alerts.get(key)
        if previous is None:
            return True
        return timestamp_epoch - previous >= self.settings.window_seconds


def _is_broadcast_or_multicast(address: str) -> bool:
    """判断目的地址是否为广播或多播地址。

    扫描检测通常不应把广播、多播流量纳入统计，否则 SSDP、mDNS、NetBIOS 等局域网
    服务发现流量容易造成误报。标准 IP 走 ``ipaddress``；解析失败时保留简单文本
    兜底，处理 ``255.255.255.255`` 或常见 IPv4 多播前缀。
    """
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return address == "255.255.255.255" or address.startswith(("224.", "239."))
    return ip.is_multicast or address == "255.255.255.255"
