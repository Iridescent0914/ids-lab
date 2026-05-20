"""LightIDS 的标准数据模型。

解析层输出 ``PacketInfo``，检测层输出 ``AlertEvent``。这两个对象把 Scapy、
规则引擎、阈值检测、数据库和 UI 解耦：后续模块只需要读取统一字段，不需要
直接理解 Scapy 的协议层对象。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class PacketInfo:
    """标准化后的单个网络数据包。

    实时抓包和 PCAP 离线导入最终都会转换为该对象。字段采用可选类型，是因为
    不同协议能提供的信息不同：TCP/UDP 有端口，ICMP 有 type/code，ARP 有操作
    类型，而未知协议可能只有时间、协议名、长度和 payload。
    """

    # 数据包时间，用于界面显示、告警时间和阈值检测时间窗口。
    timestamp: datetime
    # 标准协议名，例如 TCP、UDP、ICMP、ARP、IP 或 UNKNOWN。
    protocol: str
    # 原始数据包长度，来自 len(packet)。
    packet_length: int
    # 网络层地址；ARP 中对应 psrc/pdst，未知协议可能为空。
    src_ip: str | None = None
    dst_ip: str | None = None
    # 传输层端口；TCP/UDP 有值，ICMP/ARP 没有端口。
    src_port: int | None = None
    dst_port: int | None = None
    # 原始负载字节，用于 content/nocase 规则匹配。
    payload: bytes = b""
    # TCP flags 字符串，例如 S、SA、A，用于 SYN 或 SYN-ACK 判断。
    tcp_flags: str | None = None
    # ICMP type/code，例如 Echo Request 为 type=8, code=0。
    icmp_type: int | None = None
    icmp_code: int | None = None
    # ARP 操作类型，例如 who-has 或 is-at。
    arp_operation: str | None = None

    @property
    def timestamp_epoch(self) -> float:
        """返回 Unix 时间戳，供阈值检测的滑动时间窗口使用。"""
        return self.timestamp.timestamp()

    @property
    def timestamp_text(self) -> str:
        """返回适合表格展示的本地时间字符串。"""
        return self.timestamp.strftime("%Y-%m-%d %H:%M:%S")

    @property
    def source_text(self) -> str:
        """返回源地址显示文本；缺失时用 ``-`` 占位。"""
        return self.src_ip or "-"

    @property
    def destination_text(self) -> str:
        """返回目的地址显示文本；缺失时用 ``-`` 占位。"""
        return self.dst_ip or "-"

    @property
    def source_port_text(self) -> str:
        """返回源端口显示文本；非 TCP/UDP 协议通常显示 ``-``。"""
        return str(self.src_port) if self.src_port is not None else "-"

    @property
    def destination_port_text(self) -> str:
        """返回目的端口或 ICMP type/code 的显示文本。

        ICMP 没有端口，但 type/code 对分析很关键，因此在目的端口列展示
        ``type=..., code=...``，让 Traffic 表格仍能表达 ICMP 语义。
        """
        if self.dst_port is not None:
            return str(self.dst_port)
        if self.protocol == "ICMP" and self.icmp_type is not None and self.icmp_code is not None:
            return f"type={self.icmp_type}, code={self.icmp_code}"
        return "-"

    @property
    def payload_text(self) -> str:
        """把 payload 尝试解码为 UTF-8 文本，便于调试和展示。

        负载可能是任意二进制数据，因此使用 ``errors="replace"``，避免因为
        非 UTF-8 字节导致界面或调试输出抛异常。
        """
        if not self.payload:
            return ""
        return self.payload.decode("utf-8", errors="replace")


@dataclass(frozen=True)
class AlertEvent:
    """统一告警事件模型。

    规则检测和阈值检测都会生成该对象，再交给 UI 和 SQLite 存储层处理。
    ``alert_type`` 用来区分 ``rule_event`` 和 ``threshold_alert``。
    """

    # 告警发生时间，通常沿用触发该告警的数据包时间。
    timestamp: datetime
    # 用户可读的告警描述，例如 SSH service access observed。
    message: str
    # 严重等级，数字越小表示越严重。
    severity: int
    # 触发告警的数据包协议。
    protocol: str
    # 告警来源类型：rule_event 或 threshold_alert。
    alert_type: str
    # 源/目的地址与端口，用于告警表格、CSV 导出和数据库查询。
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    # 规则告警对应规则 sid；阈值告警通常没有 sid。
    rule_sid: int | None = None
    # 触发告警的数据包长度。
    packet_length: int = 0

    @property
    def timestamp_text(self) -> str:
        """返回适合 Alerts 表格展示的时间字符串。"""
        return self.timestamp.strftime("%Y-%m-%d %H:%M:%S")

    @property
    def source_text(self) -> str:
        """返回告警源端显示文本，优先展示 ``IP:port``。"""
        if self.src_ip is None:
            return "-"
        if self.src_port is None:
            return self.src_ip
        return f"{self.src_ip}:{self.src_port}"

    @property
    def destination_text(self) -> str:
        """返回告警目的端显示文本，优先展示 ``IP:port``。"""
        if self.dst_ip is None:
            return "-"
        if self.dst_port is None:
            return self.dst_ip
        return f"{self.dst_ip}:{self.dst_port}"

    @property
    def display_sid(self) -> str:
        """返回规则 sid 的显示文本；阈值告警没有 sid 时显示 ``-``。"""
        return str(self.rule_sid) if self.rule_sid is not None else "-"
